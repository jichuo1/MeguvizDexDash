use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult, opaque_id};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Condvar, Mutex},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexPhase {
    Unbuilt,
    Building,
    Ready,
    Failed,
}
#[derive(Clone, Debug, Serialize)]
pub struct BuildAttempt {
    pub attempt: DecimalU64,
    pub terminal: Option<IndexPhase>,
    pub error: Option<MddError>,
    pub joined_waiters: DecimalU64,
}
#[derive(Clone, Debug, Serialize)]
pub struct IndexAudit {
    pub scope_id: String,
    pub index_instance_id: String,
    pub index_name: String,
    pub phase: IndexPhase,
    pub current_attempt: DecimalU64,
    pub attempts: Vec<BuildAttempt>,
}
enum State<T> {
    Unbuilt,
    Building(u64),
    Ready(u64, Arc<T>),
    Failed(u64, MddError),
}
struct Inner<T> {
    state: State<T>,
    next: u64,
    attempts: BTreeMap<u64, BuildAttempt>,
}
pub struct LazyIndex<T> {
    scope_id: String,
    instance: String,
    name: String,
    max_attempts: u64,
    inner: Mutex<Inner<T>>,
    changed: Condvar,
}
impl<T> LazyIndex<T> {
    pub fn new(
        scope_id: impl Into<String>,
        name: impl Into<String>,
        max_attempts: u64,
    ) -> MddResult<Self> {
        Ok(Self {
            scope_id: scope_id.into(),
            instance: opaque_id("fact-index")?,
            name: name.into(),
            max_attempts,
            inner: Mutex::new(Inner {
                state: State::Unbuilt,
                next: 0,
                attempts: BTreeMap::new(),
            }),
            changed: Condvar::new(),
        })
    }
    fn lock_error(&self) -> MddError {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.lazy_index",
            "index state lock poisoned",
        )
        .detail("scope_id", self.scope_id.clone())
        .detail("index", self.name.clone())
    }
    pub fn audit(&self) -> MddResult<IndexAudit> {
        let inner = self.inner.lock().map_err(|_| self.lock_error())?;
        let (phase, attempt) = match &inner.state {
            State::Unbuilt => (IndexPhase::Unbuilt, 0),
            State::Building(a) => (IndexPhase::Building, *a),
            State::Ready(a, _) => (IndexPhase::Ready, *a),
            State::Failed(a, _) => (IndexPhase::Failed, *a),
        };
        Ok(IndexAudit {
            scope_id: self.scope_id.clone(),
            index_instance_id: self.instance.clone(),
            index_name: self.name.clone(),
            phase,
            current_attempt: DecimalU64(attempt),
            attempts: inner.attempts.values().cloned().collect(),
        })
    }
    pub fn get_or_build(&self, build: impl FnOnce() -> MddResult<T>) -> MddResult<Arc<T>> {
        self.run(false, build)
    }
    pub fn retry_failed(&self, build: impl FnOnce() -> MddResult<T>) -> MddResult<Arc<T>> {
        self.run(true, build)
    }
    fn joined_failure(inner: &Inner<T>, attempt: Option<u64>) -> MddResult<Option<MddError>> {
        let Some(record) = attempt.and_then(|attempt| inner.attempts.get(&attempt)) else {
            return Ok(None);
        };
        if record.terminal == Some(IndexPhase::Failed) {
            return record.error.clone().map(Some).ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.lazy_index",
                    "failed attempt has no terminal error",
                )
            });
        }
        Ok(None)
    }
    fn run(&self, retry: bool, build: impl FnOnce() -> MddResult<T>) -> MddResult<Arc<T>> {
        let mut inner = self.inner.lock().map_err(|_| self.lock_error())?;
        let mut waiting_for = None;
        let attempt = loop {
            // A joined attempt's error remains authoritative even if another caller
            // has already retried and published a later Ready state.
            if let Some(error) = Self::joined_failure(&inner, waiting_for)? {
                return Err(error);
            }
            match &inner.state {
                State::Ready(_, value) => return Ok(Arc::clone(value)),
                State::Building(attempt) => {
                    if waiting_for.is_none() {
                        let current = *attempt;
                        waiting_for = Some(current);
                        let record = inner
                            .attempts
                            .get_mut(&current)
                            .ok_or_else(|| self.lock_error())?;
                        record.joined_waiters.0 = record
                            .joined_waiters
                            .0
                            .checked_add(1)
                            .ok_or_else(|| self.lock_error())?;
                    }
                    inner = self.changed.wait(inner).map_err(|_| self.lock_error())?;
                }
                State::Failed(_, error) if !retry || waiting_for.is_some() => {
                    return Err(error.clone());
                }
                State::Unbuilt | State::Failed(_, _) => {
                    if inner.next >= self.max_attempts {
                        return Err(MddError::new(
                            ErrorCode::QuotaExceeded,
                            "facts.lazy_index",
                            "index attempt budget exhausted",
                        )
                        .detail("index", self.name.clone())
                        .detail("scope_id", self.scope_id.clone()));
                    }
                    inner.next = inner.next.checked_add(1).ok_or_else(|| self.lock_error())?;
                    let attempt = inner.next;
                    inner.state = State::Building(attempt);
                    inner.attempts.insert(
                        attempt,
                        BuildAttempt {
                            attempt: DecimalU64(attempt),
                            terminal: None,
                            error: None,
                            joined_waiters: DecimalU64(0),
                        },
                    );
                    break attempt;
                }
            }
        };
        drop(inner);
        let result = match catch_unwind(AssertUnwindSafe(build)) {
            Ok(value) => value,
            Err(_) => Err(MddError::new(
                ErrorCode::InternalFault,
                "facts.lazy_index",
                "index builder panicked; no ready index published",
            )),
        }
        .map(Arc::new)
        .map_err(|error| {
            error
                .detail("scope_id", self.scope_id.clone())
                .detail("index_instance_id", self.instance.clone())
                .detail("index", self.name.clone())
                .detail("index_attempt", attempt.to_string())
        });
        let mut inner = self.inner.lock().map_err(|_| self.lock_error())?;
        match &result {
            Ok(value) => {
                inner.state = State::Ready(attempt, Arc::clone(value));
                let record = inner
                    .attempts
                    .get_mut(&attempt)
                    .ok_or_else(|| self.lock_error())?;
                record.terminal = Some(IndexPhase::Ready);
            }
            Err(error) => {
                inner.state = State::Failed(attempt, error.clone());
                let record = inner
                    .attempts
                    .get_mut(&attempt)
                    .ok_or_else(|| self.lock_error())?;
                record.terminal = Some(IndexPhase::Failed);
                record.error = Some(error.clone());
            }
        }
        self.changed.notify_all();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };
    fn wait_until(mut condition: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < until, "test synchronization deadline");
            thread::yield_now();
        }
    }
    #[test]
    fn concurrent_first_build_publishes_one_immutable_terminal() {
        let index = Arc::new(LazyIndex::new("scope", "strings", 4).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let (release, receiver) = mpsc::channel();
        let producer = {
            let index = index.clone();
            let calls = calls.clone();
            thread::spawn(move || {
                index
                    .get_or_build(|| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        receiver.recv_timeout(Duration::from_secs(5)).unwrap();
                        Ok(71)
                    })
                    .unwrap()
            })
        };
        wait_until(|| index.audit().unwrap().phase == IndexPhase::Building);
        let waiters = (0..4)
            .map(|_| {
                let index = index.clone();
                let calls = calls.clone();
                thread::spawn(move || {
                    index
                        .get_or_build(|| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(0)
                        })
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        wait_until(|| index.audit().unwrap().attempts[0].joined_waiters.0 == 4);
        release.send(()).unwrap();
        let value = producer.join().unwrap();
        for waiter in waiters {
            let found = waiter.join().unwrap();
            assert!(Arc::ptr_eq(&value, &found));
            assert_eq!(*found, 71);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let audit = index.audit().unwrap();
        assert_eq!(audit.attempts.len(), 1);
        assert_eq!(audit.attempts[0].terminal, Some(IndexPhase::Ready));
        assert!(Arc::ptr_eq(
            &value,
            &index.retry_failed(|| Ok(999)).unwrap()
        ));
    }
    #[test]
    fn joined_failed_attempt_survives_immediate_ready_retry() {
        let index = Arc::new(LazyIndex::<u64>::new("scope", "failure", 4).unwrap());
        let (release, receiver) = mpsc::channel();
        let producer = {
            let index = index.clone();
            thread::spawn(move || {
                let first = index
                    .get_or_build(|| {
                        receiver.recv_timeout(Duration::from_secs(5)).unwrap();
                        Err(MddError::new(
                            ErrorCode::InvalidInput,
                            "test",
                            "original bad index",
                        ))
                    })
                    .unwrap_err();
                assert_eq!(first.code, ErrorCode::InvalidInput);
                index.retry_failed(|| Ok(88)).unwrap()
            })
        };
        wait_until(|| index.audit().unwrap().phase == IndexPhase::Building);
        let waiters = (0..4)
            .map(|_| {
                let index = index.clone();
                thread::spawn(move || {
                    index
                        .get_or_build(|| panic!("a waiter must not become a builder"))
                        .unwrap_err()
                })
            })
            .collect::<Vec<_>>();
        wait_until(|| index.audit().unwrap().attempts[0].joined_waiters.0 == 4);
        release.send(()).unwrap();
        assert_eq!(*producer.join().unwrap(), 88);
        for waiter in waiters {
            let error = waiter.join().unwrap();
            assert_eq!(error.code, ErrorCode::InvalidInput);
            assert_eq!(error.details["index_attempt"], "1");
        }
        let audit = index.audit().unwrap();
        assert_eq!(audit.phase, IndexPhase::Ready);
        assert_eq!(audit.attempts.len(), 2);
        assert_eq!(audit.attempts[0].terminal, Some(IndexPhase::Failed));
        assert_eq!(audit.attempts[1].terminal, Some(IndexPhase::Ready));
        // Deterministically exercise the exact late-wake branch after retry Ready.
        let inner = index.inner.lock().unwrap();
        assert!(matches!(&inner.state, State::Ready(2, _)));
        let original = LazyIndex::joined_failure(&inner, Some(1)).unwrap().unwrap();
        assert_eq!(original.code, ErrorCode::InvalidInput);
        assert_eq!(original.details["index_attempt"], "1");
    }
    #[test]
    fn panic_quota_deadline_failures_are_audited_without_implicit_retry() {
        let index = LazyIndex::<u64>::new("scope", "panic", 3).unwrap();
        assert_eq!(
            index
                .get_or_build(|| panic!("controlled test panic"))
                .unwrap_err()
                .code,
            ErrorCode::InternalFault
        );
        assert_eq!(
            index.get_or_build(|| Ok(1)).unwrap_err().code,
            ErrorCode::InternalFault
        );
        assert_eq!(
            index
                .retry_failed(|| Err(MddError::new(ErrorCode::QuotaExceeded, "test", "budget")))
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            index
                .retry_failed(|| Err(MddError::new(
                    ErrorCode::DeadlineExceeded,
                    "test",
                    "deadline"
                )))
                .unwrap_err()
                .code,
            ErrorCode::DeadlineExceeded
        );
        assert_eq!(
            index.retry_failed(|| Ok(1)).unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
        let audit = index.audit().unwrap();
        assert_eq!(audit.attempts.len(), 3);
        assert_eq!(audit.phase, IndexPhase::Failed);
        assert_eq!(
            audit
                .attempts
                .iter()
                .map(|a| a.error.as_ref().unwrap().code)
                .collect::<Vec<_>>(),
            [
                ErrorCode::InternalFault,
                ErrorCode::QuotaExceeded,
                ErrorCode::DeadlineExceeded
            ]
        );
    }
}
