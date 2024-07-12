use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::u32;
use std::{fs::File, io::Read};

use aes::Aes128;
use ccm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, OsRng},
    consts::{U10, U13},
    Ccm,
};
use chrono::Utc;
use cmac::digest::core_api::CoreWrapper;
use cmac::CmacCore;
use cmac::Mac;
use rand::RngCore;
use rayon::prelude::*;
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

// used lib:
// https://crates.io/crates/cmac
// https://crates.io/crates/ccm
fn generate_sample_data(num: u32) -> Result<(Vec<u32>, Vec<u32>), Box<dyn std::error::Error>> {
    let start_time = Utc::now();

    let ciphertexts = Mutex::new(Vec::new());
    let mac_tags = Mutex::new(Vec::new());
    println!("Generating {} ciphertexts and MAC", num);

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
        let tag_bytes = u32::from_le_bytes(tag_bytes.as_slice().try_into().unwrap());

        // convert vec u8 to u32
        let ciphertext = u32::from_le_bytes(ciphertext.as_slice().try_into().unwrap());

        // These are used to store raw ciphers and mac
        let mut ciphertexts_lock = ciphertexts.lock().unwrap();

        //
        ciphertexts_lock.push(ciphertext);

        let mut mac_tags_lock = mac_tags.lock().unwrap();
        mac_tags_lock.push(tag_bytes);
    });

    let ciphertexts = ciphertexts.into_inner().unwrap();

    let ciphertexts_hex: Vec<String> = ciphertexts
        .iter()
        .map(|bytes| format!("{:X?}", bytes))
        .collect();

    let mac_tags = mac_tags.into_inner().unwrap();
    let mac_tags_hex: Vec<String> = mac_tags
        .iter()
        .map(|bytes| format!("{:X?}", bytes))
        .collect();
    println!("Exporting to json files...");

    write_json("ciphertexts.json", &json!({"ciphertext":ciphertexts_hex}))?;

    write_json("mac.json", &json!({"mac": mac_tags_hex}))?;
    let end_time = Utc::now();

    println!("Start time: {}\nEnd time: {}", start_time, end_time);

    Ok((ciphertexts, mac_tags))
}

enum TestType {
    Binomial { threshold: f64 },
    OddCountOnly,
}

fn test_bit_quality(
    list_blocks: &Vec<u32>,
    test_type: TestType,
    export_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Utc::now();
    // convert the vector byte to integer representation
    println!(
        "Converting {:?} bytes blocks to integer representation",
        list_blocks.len()
    );

    let iterations = u32::MAX;

    let total_blocks = list_blocks.len() as u32;

    // progression parameters
    let ratio = 1000;
    let chunk_size = iterations / ratio;
    let counter = AtomicUsize::new(0);

    let update_progress = |i: u32| {
        if i % chunk_size == 0 {
            let progress = counter.fetch_add(1, Ordering::Relaxed) + 1;
            println!("Progress: {:.2}%", 100.0 * (progress as f64 / ratio as f64));
        }
    };

    // init of param for each test
    match test_type {
        // this branch will init the binomial test, finding the threshold and compute the test based on 4 bytes block on value AND f fonction in 2**32 range
        TestType::Binomial { threshold } => {
            let threshold_odd_count = find_threshold_odd_count(total_blocks, threshold) as usize;
            let expected_even = total_blocks as usize - threshold_odd_count;

            let issues: Vec<AtomicUsize> =
                (0..total_blocks + 1).map(|_| AtomicUsize::new(0)).collect();

            let in_percent = threshold as f64 * 100.0;

            println!(
                "- Binomial test\n- Count of blocks: {:?}\n- Odd count threasold for {:?}% : {:?}\n- Testing {} masks over {} data blocks",
                total_blocks, in_percent, threshold_odd_count, iterations, total_blocks
            );

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
                    issues[odd_count].fetch_add(1, Ordering::Relaxed);
                }
            });

            // export while test is finished:
            write_json(export_name, &json!({ "invalid_odd": issues}))?;
        }
        // this branch will count all 1-bit odd of the AND(4-byte_bloc, f_function) f_function in 0-2**32
        TestType::OddCountOnly => {
            let odd_counters: Vec<AtomicUsize> =
                (0..total_blocks + 1).map(|_| AtomicUsize::new(0)).collect();

            println!(
                "- Odd count test\n- Count of blocks: {:?}\n- Testing {} masks over {} data blocks",
                total_blocks, iterations, total_blocks
            );

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

                odd_counters[odd_count].fetch_add(1, Ordering::Relaxed);
            });

            // export json
            write_json(export_name, &json!({ "counters": odd_counters}))?;
            println!("Count result exported in {:?}", export_name);
        }
    }

    let end_time = Utc::now();

    println!("Start time: {}\nEnd time: {}", start_time, end_time);

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
        let Some(frm_payload) = packet.content.get("FRMPayload") else {
            continue;
        };

        // get only packet with content in payload
        let Some(payload) = frm_payload.as_str() else {
            continue;
        };
        //print!("payload: {:?}", payload);

        // get only if mic exists
        let Some(mic) = packet.content.get("MIC") else {
            continue;
        };

        // get only content with min 4 bytes -> 8*4 bytes as it s a string
        if payload.len() < 8 {
            continue;
        };

        let payload = match u32::from_str_radix(&payload[0..8], 16) {
            Ok(payload) => payload,
            Err(e) => {
                eprintln!("error: {}", e);
                continue;
            }
        };

        // add only if unique
        if !packet_ciphertexts.contains(&payload) {
            packet_ciphertexts.push(payload);
        }

        let mic = mic.as_i64().unwrap() as u32;

        if !packet_mic.contains(&mic) {
            packet_mic.push(mic);
        }
    }

    Ok((packet_mic, packet_ciphertexts))
}

enum DataSet {
    Synthetic,
    Real,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let selected_dataset = DataSet::Real;
    match selected_dataset {
        DataSet::Synthetic => match generate_sample_data(30000) {
            Ok((ciphertexts, mac_tags)) => {
                // binomial test only
                let _ = test_bit_quality(
                    &ciphertexts,
                    TestType::Binomial {
                        threshold: 0.0000001,
                    },
                    format!(
                        "{}_synthetic_binomial_test_ciphertexts.json",
                        ciphertexts.len()
                    )
                    .as_str(),
                );
                let _ = test_bit_quality(
                    &mac_tags,
                    TestType::Binomial {
                        threshold: 0.0000001,
                    },
                    format!("{}_synthetic_binomial_test_mac.json", mac_tags.len()).as_str(),
                );
                // odd count test only
                let _ = test_bit_quality(
                    &ciphertexts,
                    TestType::OddCountOnly,
                    format!("{}_synthetic_odd_test_ciphertexts.json", ciphertexts.len()).as_str(),
                );
                let _ = test_bit_quality(
                    &mac_tags,
                    TestType::OddCountOnly,
                    format!("{}_synthetic_odd_test_mac.json", mac_tags.len()).as_str(),
                );
            }
            Err(e) => eprintln!("Error: {}", e),
        },
        // tested on commit: 3a78ecf0e98642999d25865305c28a348804e3d6
        // min threshold 0.0000001
        DataSet::Real => match extract_mic_cipher("wss_messages.json") {
            Ok((ciphertexts, mac_tags)) => {
                // binomial test only
                let _ = test_bit_quality(
                    &ciphertexts,
                    TestType::Binomial {
                        threshold: 0.0000001,
                    },
                    format!("{}_real_binomial_test_ciphertexts.json", ciphertexts.len()).as_str(),
                );
                let _ = test_bit_quality(
                    &mac_tags,
                    TestType::Binomial {
                        threshold: 0.0000001,
                    },
                    format!("{}_real_binomial_test_mac.json", mac_tags.len()).as_str(),
                );
                // odd count test only
                let _ = test_bit_quality(
                    &ciphertexts,
                    TestType::OddCountOnly,
                    format!("{}_real_odd_test_ciphertexts.json", ciphertexts.len()).as_str(),
                );
                let _ = test_bit_quality(
                    &mac_tags,
                    TestType::OddCountOnly,
                    format!("{}_real_odd_test_mac.json", mac_tags.len()).as_str(),
                );
            }
            Err(e) => eprintln!("Error: {}", e),
        },
    };

    Ok(())
}
