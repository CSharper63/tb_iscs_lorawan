use aes::Aes128;

use ccm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, OsRng},
    consts::{U10, U13},
    Ccm,
};
use chrono::Utc;
use cliclack::log;

use cliclack::ProgressBar;
use cmac::digest::core_api::CoreWrapper;
use cmac::CmacCore;
use cmac::Mac;

use rand::RngCore;
use rayon::prelude::*;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use statrs::distribution::Binomial;
use statrs::distribution::DiscreteCDF;
use std::fs::File;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::u32;

#[derive(Serialize, Debug, Deserialize)]
struct Issue {
    i: u32,
    odd_count: u32,
    even_count: u32,
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

/* fn read_json<T: for<'de> serde::Deserialize<'de>>(
    path: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let data = serde_json::from_reader(reader)?;
    Ok(data)
} */

fn write_json(path: &str, data: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(&file, data)?;
    Ok(())
}

pub type Aes128Ccm = Ccm<Aes128, U10, U13>;

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:X}", byte))
        .collect::<Vec<_>>()
        .join("")
}

// used lib:
// https://crates.io/crates/cmac
// https://crates.io/crates/ccm
fn generate_sample_data(
    num: u32,
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), Box<dyn std::error::Error>> {
    // todo test une clé pour tous les ciphertexts et une pour les CMAC

    let start_time = Utc::now();

    let ciphertexts = Arc::new(Mutex::new(Vec::new()));
    let mac_tags = Arc::new(Mutex::new(Vec::new()));
    log::info(format!("Generating {} ciphertexts and MAC", num)).unwrap();

    (0..=num).into_par_iter().for_each(|counter: u32| {
        // Encrypt with AES-CCM a random 4-bytes sequence with an incremental counter
        let key = Aes128Ccm::generate_key(&mut OsRng);

        if key.len() != 16 {
            eprintln!(
                "Invalid key length: {}. Key must be 16 bytes long.",
                key.len()
            );
            return;
        }

        // generate 10 bytes plaintext
        let mut plaintext = [0u8; 4];
        OsRng.fill_bytes(&mut plaintext);

        // generate keystream of CCM
        let stream = Aes128Ccm::new(&key);

        // generate 13-bytes nonce based on incremental counter
        let mut nonce = [0u8; 13]; // must be 13 byte
        nonce[..4].copy_from_slice(&counter.to_be_bytes());

        let nonce = GenericArray::from_slice(&nonce);

        // encrypt cipher text
        let ciphertext = match stream.encrypt(nonce, plaintext.as_ref()) {
            Ok(ct) => ct,
            Err(e) => {
                eprintln!("Encryption error: {}", e);
                return;
            }
        };

        // generate new key for mac
        let key = Aes128Ccm::generate_key(&mut OsRng);
        // Encrypt then MAC
        let mut mac = match <CoreWrapper<CmacCore<Aes128>> as KeyInit>::new_from_slice(&key) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to initialize MAC: {:?}", e);
                return;
            }
        };

        mac.update(ciphertext.as_slice());
        let result = mac.finalize();
        let tag_bytes = result.into_bytes();

        // These are used to store raw ciphers and mac
        let mut ciphertexts_lock = ciphertexts.lock().unwrap();

        ciphertexts_lock.push(ciphertext[0..4].to_vec());

        let mut mac_tags_lock = mac_tags.lock().unwrap();
        mac_tags_lock.push(tag_bytes[0..4].to_vec());
    });

    let ciphertexts_lock = ciphertexts.lock().unwrap();
    let ciphertexts_hex: Vec<String> = ciphertexts_lock
        .iter()
        .map(|bytes| bytes_to_hex_string(bytes))
        .collect();

    let mac_tags_lock = mac_tags.lock().unwrap();
    let mac_tags_hex: Vec<String> = mac_tags_lock
        .iter()
        .map(|bytes| bytes_to_hex_string(bytes))
        .collect();
    log::info("Exporting to json files...").unwrap();

    write_json("ciphertexts.json", &json!({"ciphertext":ciphertexts_hex}))?;

    write_json("mac.json", &json!({"mac": mac_tags_hex}))?;
    let end_time = Utc::now();

    log::warning(format!(
        "Start time: {}\nEnd time: {}",
        start_time, end_time
    ))
    .unwrap();

    Ok((ciphertexts_lock.to_vec(), mac_tags_lock.to_vec()))
}

// truncate is not a problem while trying to
fn test_bit_quality(
    list_blocks: &[Vec<u8>],
    error_threshold: f64,

    export_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Utc::now();
    // convert the vector byte to integer representation
    log::info(format!(
        "Converting {:?} bytes blocks to integer representation",
        list_blocks.len()
    ))
    .unwrap();

    let list_blocks: Vec<u32> = list_blocks
        .iter()
        .map(|b| {
            // !("{:X?}", b);
            let t = u32::from_be_bytes(b.as_slice().try_into().unwrap());
            t
        })
        .collect();

    let total_blocks = list_blocks.len() as u32;

    let threshold_odd_count = find_threshold_odd_count(total_blocks, error_threshold);

    // init vec counter from 0 to
    let odd_counters: Arc<Mutex<Vec<u32>>> =
        Arc::new(Mutex::new(vec![0; total_blocks.try_into().unwrap()]));

    //let expected_even = total_blocks - threshold_odd_count;

    let chunk_size = u32::MAX / 100000;
    let counter = Arc::new(AtomicUsize::new(0));
    let in_percent = error_threshold as f64 * 100.0;

    log::info(format!(
        "- Count of blocks: {:?}\n- Odd count threasold for {:?}% : {:?}\n- Testing {} masks over {} data blocks",
        total_blocks, in_percent, threshold_odd_count, u32::MAX, total_blocks
    ))
    .unwrap();

    let pb = Arc::new(Mutex::new(ProgressBar::new(u32::MAX as u64)));
    pb.lock().unwrap().start("Starting iterations...");
    (0..=u32::MAX).into_par_iter().for_each(|i| {
        if i % chunk_size == 0 {
            let progress = counter.fetch_add(1, Ordering::SeqCst) + 1;
            //println!("Progress: {:.2}%", 100.0 * (progress as f64 / 100000.0));
            pb.lock().unwrap().inc(progress.try_into().unwrap()); // Update the progress bar
        }

        let mut odd_count = 0;
        for mic in &list_blocks {
            let and_result = i & mic;
            let bit_count = and_result.count_ones();
            let parity = bit_count & 1;
            if parity == 1 {
                odd_count += 1;
            }
        }
        /* if odd_count < threshold_odd_count || odd_count > expected_even {
            let mut issues = issues.lock().unwrap();
            issues.push(Issue {
                i,
                odd_count,
                even_count: total_blocks - odd_count,
            });
            // faire un tableau histogramme
            // je veux une taille de 100 bucket -> 0 max quantity du nombre de message /100
        } */

        let mut counters = odd_counters.lock().unwrap();
        if odd_count < counters.len() {
            counters[odd_count] += 1;
        } else {
            log::error(format!(
                "odd_count {} exceeds counter length {}",
                odd_count,
                counters.len()
            ))
            .unwrap();
        }
    });
    pb.lock().unwrap().stop("Iterations finished...");
    let counters = Arc::try_unwrap(odd_counters).unwrap().into_inner().unwrap();

    log::info(format!("Count result exported in {:?}", export_name)).unwrap();
    write_json("odd_counters.json", &json!({ "counters": counters}))?;

    let end_time = Utc::now();

    log::warning(format!(
        "Start time: {}\nEnd time: {}",
        start_time, end_time
    ))
    .unwrap();

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match generate_sample_data(10000) {
        Ok((ciphertexts, mac_tags)) => {
            // next ->
            // for each ciphertext

            let _ = test_bit_quality(&ciphertexts, 0.0000001, "odd_dist_cipher.json");
            let _ = test_bit_quality(&mac_tags, 0.0000001, "odd_dist_mac.json");

            /*             let issues_mac = test_bit_quality(&mac_tags);
            write_json("/issue_mac.json", &json!({ "issues": issues_mac }))?; */
        }
        Err(e) => eprintln!("Error: {}", e),
    }
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
    /* let issue_list: IssueList = read_json("../issue_frmpayload.json")?;
    let issues_hex = convert_issues_to_hex(issue_list);
    write_json(
        "output_frmpayload_hex.json",
        &json!({ "issue_frmpayload.json": issues_hex }),
    )?; */

    Ok(())
}
