use chrono::Utc;
use rand::rngs::OsRng;
use rand::Rng;
use rayon::prelude::*;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use statrs::distribution::DiscreteCDF;
use statrs::distribution::{Binomial, Discrete};
use std::fs::File;
use std::io::BufReader;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::u32;

#[derive(Deserialize)]
struct MicList {
    mic: Vec<i32>,
}

#[derive(Serialize, Debug)]
struct Issue {
    i: u32,
    odd_count: u32,
    even_count: u32,
}

fn find_threshold_odd_count(total_mics: u32, error_threshold: f64) -> u32 {
    let binom = Binomial::new(0.5, total_mics.into()).unwrap();
    for odd_count in (0..=total_mics).rev() {
        let p_value = binom.cdf(odd_count as u64) as f64 * 2.0; // two sided
        if p_value <= error_threshold {
            return odd_count;
        }
    }
    total_mics
}

fn test_bit_quality(mic_list: &[i32], verbose: bool) -> Vec<Issue> {
    let total_mics = mic_list.len() as u32;
    let error_threshold = 0.0000001;
    let threshold_odd_count = find_threshold_odd_count(total_mics, error_threshold);
    let expected_even = total_mics - threshold_odd_count;

    let issues = Arc::new(Mutex::new(Vec::new()));
    let chunk_size = u32::MAX / 10000;
    let counter = Arc::new(AtomicUsize::new(0));
    let in_percent = error_threshold as f64 * 100.0;

    println!("Count of MIC: {:?}", total_mics);
    println!(
        "Odd count threasold for {:?}% : {:?}",
        in_percent, threshold_odd_count
    );

    (0..=u32::MAX).into_par_iter().for_each(|i| {
        if i % chunk_size == 0 {
            let progress = counter.fetch_add(1, Ordering::SeqCst) + 1;
            println!("Progress: {:.2}%", 100.0 * (progress as f64 / 10000.0));
        }

        let mut odd_count = 0;
        for &mic in mic_list {
            let mic = mic as u32; // convert all signed mic
            let and_result = i & mic;
            let bit_count = and_result.count_ones();
            let parity = bit_count & 1;
            if parity == 1 {
                odd_count += 1;
            }
        }
        if odd_count < threshold_odd_count || odd_count > expected_even {
            let mut issues = issues.lock().unwrap();
            issues.push(Issue {
                i,
                odd_count,
                even_count: total_mics - odd_count,
            });
        }
    });

    Arc::try_unwrap(issues).unwrap().into_inner().unwrap()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("../all_mic.json")?;
    let reader = BufReader::new(file);
    let mic_list: MicList = serde_json::from_reader(reader)?;
    let start_time = Utc::now();
    println!("Start time: {}", start_time);
    let issues = test_bit_quality(&mic_list.mic, false);
    let end_time = Utc::now();
    println!("End time: {}", end_time);
    let issue_json = json!({ "issues": issues });
    let mut issue_file = File::create("../issue.json")?;
    serde_json::to_writer_pretty(&issue_file, &issue_json)?;
    Ok(())
}
