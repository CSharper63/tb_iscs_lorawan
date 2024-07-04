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

#[derive(Serialize, Debug, Deserialize)]
struct Issue {
    i: u32,
    odd_count: u32,
    even_count: u32,
}

#[derive(Deserialize)]
struct IssueList {
    issues: Vec<Issue>,
}

#[derive(Serialize)]
struct IssueHex {
    i: String,
    odd_count: u32,
    even_count: u32,
}

#[derive(Serialize)]
struct IssueListHex {
    issues: Vec<IssueHex>,
}

#[derive(Serialize)]
struct IHexList {
    i_tab: Vec<String>,
}

#[derive(Serialize)]
struct IBinList {
    i_tab: Vec<String>,
}

#[derive(Deserialize)]
struct FrmPayloadList {
    frmpayload: Vec<String>,
}

fn find_threshold_odd_count(total_blocks: u32, error_threshold: f64) -> u32 {
    let binom = Binomial::new(0.5, total_blocks.into()).unwrap();
    for odd_count in (0..=total_blocks).rev() {
        let p_value = binom.cdf(odd_count as u64) as f64 * 2.0; // two sided
        if p_value <= error_threshold {
            return odd_count;
        }
    }
    total_blocks
}

fn truncate_frm_payload(frmpayload_list: &FrmPayloadList) -> Vec<i32> {
    frmpayload_list
        .frmpayload
        .iter()
        .filter_map(|hex_str| {
            if let Ok(full_value) = u64::from_str_radix(hex_str, 16) {
                let truncated_value = (full_value & 0xFFFFFFFF) as i32;
                Some(truncated_value)
            } else {
                None
            }
        })
        .collect()
}

fn read_json<T: for<'de> serde::Deserialize<'de>>(
    path: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let data = serde_json::from_reader(reader)?;
    Ok(data)
}

fn write_json(path: &str, data: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&file, data)?;
    Ok(())
}

fn convert_issues_to_hex(issue_list: IssueList) -> IssueListHex {
    let issues_hex: Vec<IssueHex> = issue_list
        .issues
        .into_iter()
        .map(|issue| IssueHex {
            i: format!("{:X}", issue.i),
            odd_count: issue.odd_count,
            even_count: issue.even_count,
        })
        .collect();
    IssueListHex { issues: issues_hex }
}

fn test_bit_quality(list_blocks: &[i32]) -> Vec<Issue> {
    let total_blocks = list_blocks.len() as u32;
    let error_threshold = 0.0000001;
    let threshold_odd_count = find_threshold_odd_count(total_blocks, error_threshold);
    let expected_even = total_blocks - threshold_odd_count;

    let issues = Arc::new(Mutex::new(Vec::new()));
    let chunk_size = u32::MAX / 10000;
    let counter = Arc::new(AtomicUsize::new(0));
    let in_percent = error_threshold as f64 * 100.0;

    println!("Count of blocks: {:?}", total_blocks);
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
        for &mic in list_blocks {
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
                even_count: total_blocks - odd_count,
            });
        }
    });

    Arc::try_unwrap(issues).unwrap().into_inner().unwrap()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // process mic list
    /* let mic_list: MicList = read_json("../all_frmpayload.json")?;
    let start_time = Utc::now();
    let issues = test_bit_quality(&mic_list.mic);
    let end_time = Utc::now();
    println!("Start time: {}", start_time);
    println!("End time: {}", end_time);
    write_json("../issue_mic.json", &json!({ "issues": issues }))?; */

    // process frm payload
    /* let frmpayload_list = read_json("../all_frmpayload.json")?;
    let truncated_mic_list = truncate_frm_payload(&frmpayload_list);

    let start_time = Utc::now();
    let issues = test_bit_quality(&truncated_mic_list);
    let end_time = Utc::now();
    println!("Start time: {}", start_time);
    println!("End time: {}", end_time);
    write_json("../issue_frmpayload.json", &json!({ "issues": issues }))?; */

    // convert i to hex:
    let issue_list: IssueList = read_json("../issue_frmpayload.json")?;
    let issues_hex = convert_issues_to_hex(issue_list);
    write_json(
        "output_frmpayload_hex.json",
        &json!({ "issue_frmpayload.json": issues_hex }),
    )?;

    Ok(())
}
