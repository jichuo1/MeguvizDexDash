use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
use mdd_session::{Lifecycle, QueryBinding, QueryPhase, ResourceLimits};
use mdd_types::ErrorCode;
use mdd_worker::lifecycle::Supervisor;
use rusqlite::{Connection, Error, ffi};
use serde_json::json;
use std::{
    io::{self, Write},
    path::PathBuf,
    process::Command,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

fn sqlite_interrupt() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let a = Connection::open_in_memory()?;
    let b = Connection::open_in_memory()?;
    let version: String = a.query_row("SELECT sqlite_version()", [], |r| r.get(0))?;
    let options: Vec<String> = a
        .prepare("PRAGMA compile_options")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let interrupt = a.get_interrupt_handle();
    let started = Arc::new(Barrier::new(3));
    let proceed = Arc::new(Barrier::new(3));
    let expired_a = Arc::new(AtomicBool::new(false));
    let expired_b = Arc::new(AtomicBool::new(false));
    let run = |connection: Connection,
               max: i64,
               started: Arc<Barrier>,
               proceed: Arc<Barrier>,
               expired: Arc<AtomicBool>| {
        thread::spawn(move || {
            let began = Instant::now();
            let first = AtomicBool::new(true);
            connection
                .progress_handler(
                    100,
                    Some(move || {
                        if first.swap(false, Ordering::SeqCst) {
                            started.wait();
                            proceed.wait();
                        }
                        let elapsed = began.elapsed() >= Duration::from_secs(2);
                        if elapsed {
                            expired.store(true, Ordering::SeqCst);
                        }
                        elapsed
                    }),
                )
                .expect("install actual progress guard");
            let result=connection.query_row("WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<?1) SELECT sum(x) FROM n",[max],|r|r.get::<_,i64>(0));
            connection
                .progress_handler(0, None::<fn() -> bool>)
                .expect("remove actual progress guard");
            let reusable = connection.query_row("SELECT 7", [], |r| r.get::<_, i64>(0));
            (result, reusable)
        })
    };
    let task_a = run(
        a,
        1_000_000_000,
        Arc::clone(&started),
        Arc::clone(&proceed),
        Arc::clone(&expired_a),
    );
    let task_b = run(
        b,
        200_000,
        Arc::clone(&started),
        Arc::clone(&proceed),
        Arc::clone(&expired_b),
    );
    started.wait();
    interrupt.interrupt();
    proceed.wait();
    let (a, a_reused) = task_a.join().map_err(|_| "SQLite A thread panic")?;
    let (b, b_reused) = task_b.join().map_err(|_| "SQLite B thread panic")?;
    let interrupted = matches!(a,Err(Error::SqliteFailure(error,_)) if error.code==ffi::ErrorCode::OperationInterrupted);
    if !interrupted
        || b.as_ref().ok() != Some(&20_000_100_000)
        || a_reused.as_ref().ok() != Some(&7)
        || b_reused.as_ref().ok() != Some(&7)
        || expired_a.load(Ordering::SeqCst)
        || expired_b.load(Ordering::SeqCst)
    {
        return Err(format!(
            "interrupt isolation failed: a={a:?} b={b:?} reused={a_reused:?}/{b_reused:?}"
        )
        .into());
    }
    Ok(
        json!({"case":"two-live-connections-interrupt-isolation","sqlite_version":version,"compile_options":options,"a_error":"OperationInterrupted","b_sum":"20000100000","connection_reuse_values":[7,7],"watchdog_fired":false,"scope":"connection-level evidence only; query token ownership remains bridge integration"}),
    )
}

fn supervisor() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated/minimal-035.dex");
    let snapshot = Arc::new(Snapshot::capture(
        &[InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )?);
    let limits = ResourceLimits {
        max_threads: 4,
        deadline_ms: 250,
        ..ResourceLimits::default()
    };
    let life = Lifecycle::new(limits)?;
    let s = life.register_snapshot(snapshot)?;
    let session = life.open_session(&s, limits)?;
    let prepare = || {
        life.prepare_query(
            &session,
            QueryBinding {
                request_key: "real-worker-probe".into(),
                schema_id: "rows".into(),
                semantic_version: "v1".into(),
            },
            limits,
        )
    };
    let done = prepare()?;
    life.start_query(&session, &done, 1)?;
    life.complete_execution(&done)?;
    life.finish_delivery(&done)?;
    let computing = prepare()?;
    life.start_query(&session, &computing, 1)?;
    let spool = prepare()?;
    life.start_query(&session, &spool, 1)?;
    life.complete_execution(&spool)?;
    let mut command = Command::new(std::env::current_exe()?);
    command.arg("--owned-worker-child");
    let mut supervisor = Supervisor::spawn(command, life.clone())?;
    let pid = supervisor.process_id();
    let report = supervisor.wait_for_termination(Duration::from_secs(2))?;
    let a = life.query_status(&computing)?;
    let b = life.query_status(&spool)?;
    let old = life.query_status(&done)?;
    if report.cause != "worker_deadline"
        || report.error.code != ErrorCode::DeadlineExceeded
        || report.affected_requests.len() != 2
        || !report.direct_child_reaped
        || a.phase != QueryPhase::Failed
        || b.phase != QueryPhase::Failed
        || !b.execution_complete
        || b.delivery_complete
        || old.phase != QueryPhase::Completed
    {
        return Err(format!("worker propagation failed: {report:?} {a:?} {b:?} {old:?}").into());
    }
    Ok(
        json!({"case":"real-hard-worker-deadline-all-unfinished","owned_child_pid":pid,"termination":report,"computing_query":a,"unconsumed_spool_query":b,"prior_complete_query":old,"scope":"owned direct child reaped; process-tree isolation remains false"}),
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arg = std::env::args()
        .nth(1)
        .ok_or("usage: --sqlite | --supervisor")?;
    if arg == "--owned-worker-child" {
        io::stdout().write_all(b"owned-test-worker-ready\n")?;
        io::stdout().flush()?;
        let began=Instant::now();
        while began.elapsed()<Duration::from_secs(3) {
            thread::sleep(Duration::from_millis(10));
        }
        std::process::exit(97);
    }
    let result = match arg.as_str() {
        "--sqlite" => sqlite_interrupt()?,
        "--supervisor" => supervisor()?,
        _ => return Err("unknown probe".into()),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
