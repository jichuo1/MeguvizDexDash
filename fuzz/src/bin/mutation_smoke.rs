use mdd_parser_fuzz::{MAX_INPUT, Observation, TARGETS, run};
use serde_json::json;
use std::{env, fs, path::Path, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: mutation-smoke CORPUS_ROOT MUTATIONS_PER_SEED".into());
    }
    let mutations: usize = args[2].parse()?;
    if !(1..=4096).contains(&mutations) {
        return Err("mutation budget must be 1..4096".into());
    }
    let start = Instant::now();
    let mut reports = Vec::new();
    for target in TARGETS {
        let mut paths = fs::read_dir(Path::new(&args[1]).join(target))?
            .map(|v| v.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        if paths.is_empty() {
            return Err(format!("empty corpus {target}").into());
        }
        let mut count = 0u64;
        let mut totals = Observation::default();
        let target_start = Instant::now();
        for path in &paths {
            let seed = fs::read(path)?;
            if seed.len() > MAX_INPUT {
                return Err("oversize seed".into());
            }
            totals.add(run(target, &seed));
            count += 1;
            for iteration in 0..mutations {
                let mut bytes = seed.clone();
                // Fixed deterministic index/bit/truncation/extension schedule, no RNG/global state.
                let at = iteration.wrapping_mul(4051).wrapping_add(17);
                if !bytes.is_empty() {
                    let index = at % bytes.len();
                    match iteration % 4 {
                        0 => bytes[index] ^= 1 << (iteration % 8),
                        1 => bytes.truncate(index),
                        2 => bytes[index] = (iteration >> 2) as u8,
                        _ => {
                            if bytes.len() < MAX_INPUT {
                                bytes.insert(index, 0xff);
                            }
                        }
                    }
                } else {
                    bytes.push(iteration as u8);
                }
                totals.add(run(target, &bytes));
                count += 1;
            }
        }
        reports.push(
            json!({"target":target,"seed_files":paths.len(),"executions":count,
            "seconds":target_start.elapsed().as_secs_f64(),"accepted_parser_calls":totals.accepted,
            "rejected_parser_calls":totals.rejected,"validated_headers":totals.header,
            "decoded_strings":totals.strings,"metadata_successes":totals.metadata,
            "code_items":totals.code_items,"encoded_value_nodes":totals.value_nodes,
            "archive_members":totals.archive_members}),
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"schema_version":"mdd.parser-mutation-smoke.v1",
        "seed":"deterministic-index-4051-offset-17-v1","mutations_per_seed":mutations,
        "seconds":start.elapsed().as_secs_f64(),"targets":reports,"sanitizer":null,
        "coverage_instrumented":false,"crashes":0,"scope":"bounded deterministic mutation; not format completeness or G1 qualification"}))?
    );
    Ok(())
}
