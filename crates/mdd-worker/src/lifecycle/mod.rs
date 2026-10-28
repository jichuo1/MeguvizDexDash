use mdd_session::{Lifecycle, QueryFailure, WorkerSupervisionLease};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::Serialize;
use std::io::{self, Read};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

enum PipeRead {
    Pending,
    Bytes(usize),
    Eof,
}

#[cfg(target_os = "windows")]
fn prepare_pipe(_: &ChildStdout) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn read_available(pipe: &mut ChildStdout, buffer: &mut [u8]) -> io::Result<PipeRead> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn PeekNamedPipe(
            pipe: *mut c_void,
            buffer: *mut c_void,
            size: u32,
            read: *mut u32,
            available: *mut u32,
            remaining: *mut u32,
        ) -> i32;
    }
    let mut available = 0u32;
    // SAFETY: the owned ChildStdout handle remains live, all optional pointers
    // are NULL, and available points to an initialized writable u32.
    let ok = unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let error = io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(109 | 233)) {
            Ok(PipeRead::Eof)
        } else {
            Err(error)
        };
    }
    if available == 0 {
        return Ok(PipeRead::Pending);
    }
    let count = (available as usize).min(buffer.len());
    match pipe.read(&mut buffer[..count]) {
        Ok(0) => Ok(PipeRead::Eof),
        Ok(count) => Ok(PipeRead::Bytes(count)),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(PipeRead::Eof),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn prepare_pipe(pipe: &ChildStdout) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    // SAFETY: the descriptor is live and owned, F_GETFL has no third argument.
    let flags = unsafe { fcntl(pipe.as_raw_fd(), 3) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // Linux F_SETFL=4 and O_NONBLOCK=0x800; this branch is Linux only.
    // SAFETY: a valid descriptor and the required integer argument are supplied.
    if unsafe { fcntl(pipe.as_raw_fd(), 4, flags | 0x800) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_available(pipe: &mut ChildStdout, buffer: &mut [u8]) -> io::Result<PipeRead> {
    match pipe.read(buffer) {
        Ok(0) => Ok(PipeRead::Eof),
        Ok(count) => Ok(PipeRead::Bytes(count)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(PipeRead::Pending),
        Err(error) => Err(error),
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn prepare_pipe(_: &ChildStdout) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "worker pipe supervision not implemented on this platform",
    ))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn read_available(_: &mut ChildStdout, _: &mut [u8]) -> io::Result<PipeRead> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "worker pipe supervision not implemented on this platform",
    ))
}

#[derive(Clone, Debug, Serialize)]
pub struct WorkerTermination {
    pub cause: String,
    pub exit_code: Option<i32>,
    pub error: MddError,
    pub affected_requests: Vec<QueryFailure>,
    pub stdout_bytes: DecimalU64,
    pub direct_child_reaped: bool,
    pub process_tree_isolated: bool,
}

pub struct Supervisor {
    child: Child,
    stdout: Option<ChildStdout>,
    lifecycle: Lifecycle,
    _supervision: WorkerSupervisionLease,
    started: Instant,
    bytes: u64,
    terminal: Option<WorkerTermination>,
}

impl Supervisor {
    pub fn spawn(mut command: Command, lifecycle: Lifecycle) -> MddResult<Self> {
        let supervision = lifecycle.claim_supervision()?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|error| {
            MddError::new(
                if error.kind() == io::ErrorKind::NotFound {
                    ErrorCode::UnavailableBackend
                } else {
                    ErrorCode::InternalFault
                },
                "worker_spawn",
                error.to_string(),
            )
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "worker_spawn",
                "stdout pipe missing",
            )
        });
        let stdout = match stdout {
            Ok(stdout) => stdout,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        if let Err(error) = prepare_pipe(&stdout) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "worker_spawn",
                error.to_string(),
            ));
        }
        Ok(Self {
            child,
            stdout: Some(stdout),
            lifecycle,
            _supervision: supervision,
            started: Instant::now(),
            bytes: 0,
            terminal: None,
        })
    }

    pub fn process_id(&self) -> u32 {
        self.child.id()
    }

    fn terminate(&mut self, cause: &str, error: MddError) -> MddResult<WorkerTermination> {
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        let exit = match self.child.try_wait() {
            Ok(Some(exit)) => Ok(exit),
            Ok(None) => {
                let _ = self.child.kill();
                self.child.wait()
            }
            Err(error) => Err(error),
        };
        self.stdout.take();
        let failures = self.lifecycle.fail_worker(error.clone())?;
        let report = WorkerTermination {
            cause: cause.to_owned(),
            exit_code: exit.as_ref().ok().and_then(|s| s.code()),
            error,
            affected_requests: failures,
            stdout_bytes: DecimalU64(self.bytes),
            direct_child_reaped: exit.is_ok(),
            process_tree_isolated: false,
        };
        self.terminal = Some(report.clone());
        Ok(report)
    }

    pub fn poll(&mut self) -> MddResult<Option<WorkerTermination>> {
        if let Some(terminal) = &self.terminal {
            return Ok(Some(terminal.clone()));
        }
        let limits = self.lifecycle.limits()?;
        let exited = match self.child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                return self
                    .terminate(
                        "worker_wait_error",
                        MddError::new(ErrorCode::InternalFault, "worker_wait", error.to_string()),
                    )
                    .map(Some);
            }
        };
        let mut buffer = [0u8; 4096];
        for _ in 0..32 {
            let read = self
                .stdout
                .as_mut()
                .map(|pipe| read_available(pipe, &mut buffer));
            match read {
                Some(Ok(PipeRead::Pending)) => break,
                Some(Ok(PipeRead::Bytes(count))) => {
                    let Some(total) = self.bytes.checked_add(count as u64) else {
                        return self
                            .terminate(
                                "stdout_budget",
                                MddError::new(
                                    ErrorCode::QuotaExceeded,
                                    "worker_stdout",
                                    "stdout byte count overflow",
                                ),
                            )
                            .map(Some);
                    };
                    self.bytes = total;
                    if total > limits.max_worker_stdout_bytes {
                        return self
                            .terminate(
                                "stdout_budget",
                                MddError::new(
                                    ErrorCode::QuotaExceeded,
                                    "worker_stdout",
                                    "worker stdout byte budget exceeded",
                                )
                                .detail("budget", "max_worker_stdout_bytes")
                                .detail("limit", limits.max_worker_stdout_bytes.to_string())
                                .detail("observed", total.to_string()),
                            )
                            .map(Some);
                    }
                }
                Some(Ok(PipeRead::Eof)) | None => {
                    return self
                        .terminate(
                            if exited.is_some() {
                                "process_exit_without_terminal"
                            } else {
                                "stdout_eof"
                            },
                            MddError::new(
                                ErrorCode::WorkerLost,
                                "worker_ipc",
                                "worker stdout closed without a complete request terminal",
                            ),
                        )
                        .map(Some);
                }
                Some(Err(error)) => {
                    return self
                        .terminate(
                            "stdout_io_error",
                            MddError::new(ErrorCode::WorkerLost, "worker_ipc", error.to_string()),
                        )
                        .map(Some);
                }
            }
        }
        if exited.is_some() {
            return self
                .terminate(
                    "process_exit_without_terminal",
                    MddError::new(
                        ErrorCode::WorkerLost,
                        "worker",
                        "worker exited; unfinished requests did not receive a complete terminal",
                    ),
                )
                .map(Some);
        }
        if self.started.elapsed() >= Duration::from_millis(limits.deadline_ms) {
            return self
                .terminate(
                    "worker_deadline",
                    MddError::new(
                        ErrorCode::DeadlineExceeded,
                        "worker",
                        "worker lifetime deadline exceeded",
                    )
                    .detail("budget", "deadline_ms")
                    .detail("limit", limits.deadline_ms.to_string()),
                )
                .map(Some);
        }
        Ok(None)
    }

    pub fn wait_for_termination(&mut self, timeout: Duration) -> MddResult<WorkerTermination> {
        let started = Instant::now();
        loop {
            if let Some(terminal) = self.poll()? {
                return Ok(terminal);
            }
            if started.elapsed() >= timeout {
                return self.terminate(
                    "supervisor_wait_deadline",
                    MddError::new(
                        ErrorCode::DeadlineExceeded,
                        "supervisor",
                        "supervisor wait deadline exceeded",
                    ),
                );
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        if self.terminal.is_none() {
            let _ = self.terminate(
                "supervisor_closed",
                MddError::new(
                    ErrorCode::WorkerLost,
                    "worker",
                    "supervisor closed before worker terminal",
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use mdd_session::{QueryBinding, QueryPhase, ResourceLimits};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn runtime(limits: ResourceLimits) -> (Lifecycle, mdd_session::SessionHandle) {
        let runtime = Lifecycle::new(limits).unwrap();
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/generated/minimal-035.dex"),
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap();
        let snapshot = runtime.register_snapshot(Arc::new(snapshot)).unwrap();
        let session = runtime.open_session(&snapshot, limits).unwrap();
        (runtime, session)
    }

    fn prepare(
        runtime: &Lifecycle,
        session: &mdd_session::SessionHandle,
    ) -> mdd_session::QueryHandle {
        runtime
            .prepare_query(
                session,
                QueryBinding {
                    request_key: "lifecycle-test".to_owned(),
                    schema_id: "no-query-result".to_owned(),
                    semantic_version: "lifecycle-only-v1".to_owned(),
                },
                ResourceLimits::default(),
            )
            .unwrap()
    }

    #[cfg(target_os = "windows")]
    fn close_child_stdout() {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetStdHandle(kind: u32) -> *mut c_void;
            fn CloseHandle(handle: *mut c_void) -> i32;
        }
        // SAFETY: this is an isolated test child, with an owned standard output
        // pipe deliberately closed to exercise IPC loss while the child lives.
        unsafe {
            assert_ne!(CloseHandle(GetStdHandle(-11i32 as u32)), 0);
        }
    }

    #[cfg(target_os = "linux")]
    fn close_child_stdout() {
        unsafe extern "C" {
            fn close(fd: i32) -> i32;
        }
        // SAFETY: isolated test child deliberately closes its standard pipe.
        unsafe {
            assert_eq!(close(1), 0);
        }
    }

    #[test]
    fn supervisor_observes_real_process_exit_pipe_close_and_limits() {
        if let Ok(mode) = std::env::var("MDD_LIFECYCLE_TEST_CHILD") {
            match mode.as_str() {
                "nonzero" => std::process::exit(23),
                "zero-eof" => std::process::exit(0),
                "pipe-close" => close_child_stdout(),
                "output-budget" => {
                    std::io::stdout().write_all(&[b'x'; 8192]).unwrap();
                    std::io::stdout().flush().unwrap();
                }
                "deadline" => (),
                _ => panic!("unknown test child mode"),
            }
            loop {
                thread::park_timeout(Duration::from_secs(1));
            }
        }
        for mode in [
            "nonzero",
            "zero-eof",
            "pipe-close",
            "output-budget",
            "deadline",
        ] {
            let limits = ResourceLimits {
                deadline_ms: if mode == "deadline" { 250 } else { 5_000 },
                max_worker_stdout_bytes: if mode == "output-budget" {
                    128
                } else {
                    64 * 1024
                },
                ..ResourceLimits::default()
            };
            let (runtime, session) = runtime(limits);
            let first = prepare(&runtime, &session);
            let second = prepare(&runtime, &session);
            runtime.start_query(&session, &first, 1).unwrap();
            let finished = prepare(&runtime, &session);
            runtime.start_query(&session, &finished, 1).unwrap();
            runtime.complete_execution(&finished).unwrap();
            runtime.finish_delivery(&finished).unwrap();
            let unaffected = Lifecycle::new(limits).unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "lifecycle::tests::supervisor_observes_real_process_exit_pipe_close_and_limits",
                    "--nocapture",
                ])
                .env("MDD_LIFECYCLE_TEST_CHILD", mode);
            let mut supervisor = Supervisor::spawn(command, runtime.clone()).unwrap();
            assert!(runtime.claim_supervision().is_err());
            if matches!(mode, "nonzero" | "zero-eof") {
                let started = Instant::now();
                let exit = loop {
                    if let Some(exit) = supervisor.child.try_wait().unwrap() {
                        break exit;
                    }
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "child exit deadline: {mode}"
                    );
                    thread::sleep(Duration::from_millis(1));
                };
                assert_eq!(exit.code(), Some(if mode == "nonzero" { 23 } else { 0 }));
            }
            let terminal = supervisor
                .wait_for_termination(Duration::from_secs(6))
                .unwrap();
            eprintln!(
                "lifecycle-child mode={mode} cause={} exit={:?} affected={} bytes={} direct_child_reaped={}",
                terminal.cause,
                terminal.exit_code,
                terminal.affected_requests.len(),
                terminal.stdout_bytes.0,
                terminal.direct_child_reaped
            );
            assert!(terminal.direct_child_reaped, "{mode}");
            assert!(!terminal.process_tree_isolated);
            assert_eq!(terminal.affected_requests.len(), 2, "{mode}");
            let expected = match mode {
                "output-budget" => ErrorCode::QuotaExceeded,
                "deadline" => ErrorCode::DeadlineExceeded,
                _ => ErrorCode::WorkerLost,
            };
            assert_eq!(terminal.error.code, expected, "{mode}");
            if mode == "nonzero" {
                assert_eq!(terminal.exit_code, Some(23));
            }
            if mode == "zero-eof" {
                assert_eq!(terminal.exit_code, Some(0));
            }
            if mode == "pipe-close" {
                assert_eq!(terminal.cause, "stdout_eof");
            }
            if mode == "output-budget" {
                assert!(terminal.stdout_bytes.0 > limits.max_worker_stdout_bytes);
            }
            for query in [&first, &second] {
                let status = runtime.query_status(query).unwrap();
                assert_eq!(status.phase, QueryPhase::Failed);
                assert_eq!(status.error.unwrap().code, expected);
                assert!(!status.delivery_complete);
            }
            assert_eq!(
                runtime.query_status(&finished).unwrap().phase,
                QueryPhase::Completed
            );
            assert!(unaffected.claim_supervision().is_ok());
            assert!(supervisor.poll().unwrap().is_some());
        }
    }
}
