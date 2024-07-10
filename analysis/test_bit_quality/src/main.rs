use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::u32;
use std::{fs::File, io::Read};

use aes::Aes128;
use ccm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, OsRng},
    consts::{U10, U13},
    Ccm,
};
use chrono::Utc;
use cliclack::log;
use cmac::digest::core_api::CoreWrapper;
use cmac::CmacCore;
use cmac::Mac;
use rand::RngCore;
use rayon::prelude::*;
use serde::de::Unexpected::Option;
use serde::Deserialize;
use serde::Serialize;
use serde_json::{json, Value};
use statrs::distribution::Binomial;
use statrs::distribution::DiscreteCDF;

#[derive(Serialize, Debug, Deserialize)]
struct Issue {
    i: u32,
    odd_count: u32,
    even_count: u32,
}

#[derive(Debug, Deserialize)]
struct LoRaWanPacket {
    content: Value,
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

enum TestType {
    Binomial,
    OddCountOnly,
}

fn test_bit_quality(
    list_blocks: &Vec<u32>,
    error_threshold: std::option::Option<f64>,
    export_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Utc::now();
    // convert the vector byte to integer representation
    log::info(format!(
        "Converting {:?} bytes blocks to integer representation",
        list_blocks.len()
    ))
    .unwrap();

    let test_type = if error_threshold.is_some() {
        TestType::Binomial
    } else {
        TestType::OddCountOnly
    };

    let iterations = u32::MAX;

    let total_blocks = list_blocks.len() as u32;

    // progression parameters
    let ratio = 10000;
    let chunk_size = iterations / ratio;
    let counter = Arc::new(AtomicUsize::new(0));
    let in_percent = error_threshold.unwrap() as f64 * 100.0;

    let update_progress = |i: u32| {
        if i % chunk_size == 0 {
            let progress = counter.fetch_add(1, Ordering::SeqCst) + 1;
            println!("Progress: {:.2}%", 100.0 * (progress as f64 / ratio as f64));
        }
    };

    // init of param for each test
    match test_type {
        // this branch will init the binomial test, finding the threshold and compute the test based on 4 bytes block on value AND f fonction in 2**32 range
        TestType::Binomial => {
            let threshold_odd_count =
                find_threshold_odd_count(total_blocks, error_threshold.unwrap()) as usize;
            let expected_even = total_blocks as usize - threshold_odd_count;

            let issues = Arc::new(Mutex::new(Vec::new()));

            log::info(format!(
                "- Count of blocks: {:?}\n- Odd count threasold for {:?}% : {:?}\n- Testing {} masks over {} data blocks",
                total_blocks, in_percent, threshold_odd_count, iterations, total_blocks
            ))
            .unwrap();

            // this code will be replicated to avoid perf issue while compute if condition if Binomial or oddCountOnly.
            (0..=iterations).into_par_iter().for_each(|i| {
                update_progress(i);

                let mut odd_count: usize = 0;
                for &mic in list_blocks {
                    let and_result = i & mic;
                    let bit_count = and_result.count_ones();
                    let parity = bit_count & 1;
                    if parity == 1 {
                        odd_count += 1;
                    }
                }
                // executing test
                if odd_count < threshold_odd_count || odd_count > expected_even {
                    let mut issues = issues.lock().unwrap();
                    issues.push(Issue {
                        i,
                        odd_count: odd_count as u32,
                        even_count: total_blocks - odd_count as u32,
                    });
                }
            });

            // export while test is finished:
            let issue_json =
                json!({ "invalid":  Arc::try_unwrap(issues).unwrap().into_inner().unwrap() });
            write_json(export_name, &json!({ "invalid": issue_json}))?;
        }
        // this branch will count all 1-bit odd of the AND(4-byte_bloc, f_function) f_function in 0-2**32
        TestType::OddCountOnly => {
            let odd_counters: Arc<Vec<AtomicUsize>> =
                Arc::new((0..total_blocks + 1).map(|_| AtomicUsize::new(0)).collect());

            log::info(format!(
                "- Count of blocks: {:?}\n- Testing {} masks over {} data blocks",
                total_blocks, iterations, total_blocks
            ))
            .unwrap();

            // running test
            (0..=iterations).into_par_iter().for_each(|i| {
                update_progress(i);

                let mut odd_count: usize = 0;
                for &mic in list_blocks {
                    let and_result = i & mic;
                    let bit_count = and_result.count_ones();
                    let parity = bit_count & 1;
                    if parity == 1 {
                        odd_count += 1;
                    }
                }

                odd_counters[odd_count].fetch_add(1, Ordering::SeqCst);
            });

            // export atomic counters to usize vector
            let counters: Vec<usize> = odd_counters
                .iter()
                .map(|counter| counter.load(Ordering::SeqCst))
                .collect();
            // export json
            write_json(export_name, &json!({ "counters": counters}))?;
            log::info(format!("Count result exported in {:?}", export_name)).unwrap();
        }
    }

    let end_time = Utc::now();

    log::warning(format!(
        "Start time: {}\nEnd time: {}",
        start_time, end_time
    ))
    .unwrap();

    Ok(())
}

fn extract_mic_cipher(path: &str) -> Result<(Vec<u32>, Vec<u32>), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    File::open(path).unwrap().read_to_end(&mut bytes).unwrap();
    let packets: Vec<LoRaWanPacket> = serde_json::from_slice(&bytes).unwrap();

    let mut packet_ciphertexts: Vec<u32> = Vec::new();
    let mut packet_mic: Vec<u32> = Vec::new();

    for packet in packets {
        // get only packet with FRMPayload
        if let Some(frm_payload) = packet.content.get("FRMPayload") {
            // get only packet with content in payload
            if !frm_payload.as_str().unwrap_or("").is_empty() && packet.content.get("MIC").is_some()
            {
                // get only content with min 4 bytes
                if frm_payload.as_str().unwrap().as_bytes().len() >= 4 {
                    let payload = u32::from_be_bytes(
                        frm_payload.as_str().unwrap().as_bytes()[0..4]
                            .try_into()
                            .unwrap(),
                    );

                    packet_ciphertexts.push(payload);

                    let mic = packet.content.get("MIC").unwrap().as_i64().unwrap() as u32;

                    packet_mic.push(mic);
                };
            }
        }
    }

    Ok((packet_mic, packet_ciphertexts))
}

enum DataSet {
    Synthetic,
    Real,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seleted_dataset = DataSet::Real;

    match seleted_dataset {
        DataSet::Synthetic => match generate_sample_data(10000) {
            Ok((ciphertexts, mac_tags)) => {
                let ciphertexts = ciphertexts
                    .iter()
                    .map(|b| {
                        let t = u32::from_be_bytes(b.as_slice().try_into().unwrap());
                        t
                    })
                    .collect();

                let mac_tags: Vec<u32> = mac_tags
                    .iter()
                    .map(|b| {
                        let t = u32::from_be_bytes(b.as_slice().try_into().unwrap());
                        t
                    })
                    .collect();

                let _ = test_bit_quality(&ciphertexts, None, "odd_dist_cipher.json");
                let _ = test_bit_quality(&mac_tags, None, "odd_dist_mac.json");
            }
            Err(e) => eprintln!("Error: {}", e),
        },
        // tested on commit: 905fd51e26a3b6916bebeb95a8219690274613d9
        // min threshold 0.0000001
        DataSet::Real => match extract_mic_cipher("wss_messages.json") {
            Ok((ciphertexts, mac_tags)) => {
                let _ = test_bit_quality(
                    &ciphertexts,
                    Some(0.0000001),
                    "real_binomial_test_cipher.json",
                );
                let _ = test_bit_quality(&mac_tags, Some(0.0000001), "real_binomial_test_mac.json");
            }
            Err(e) => eprintln!("Error: {}", e),
        },
    }

    Ok(())
}
