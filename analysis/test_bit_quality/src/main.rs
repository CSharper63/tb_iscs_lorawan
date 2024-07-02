use rand::rngs::OsRng;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use statrs::distribution::DiscreteCDF;
use statrs::distribution::{Binomial, Discrete};
use std::fs::File;
use std::io::BufReader;

#[derive(Deserialize)]
struct MicList {
    mic: Vec<i32>,
}

fn find_threshold_odd_count(total_mics: u32, error_threasold: f64) -> u32 {
    // 50 % is the expected proba for a success
    let binom = Binomial::new(0.5, total_mics.into()).unwrap();
    println!("{:?}", binom.p());
    for odd_count in (0..=total_mics).rev() {
        let p_value = binom.cdf(odd_count as u64) as f64 * 2.0; // two sided

        if p_value <= error_threasold {
            return odd_count;
        }
    }

    total_mics
}

fn test_bit_quality(mic_list: &[i32], verbose: bool) {
    let mut odd_counts = Vec::new();

    let total_mics = mic_list.len() as u32;
    let error_threasold = 0.00001;

    let threshold_odd_count = find_threshold_odd_count(total_mics, error_threasold);
    let in_percent = error_threasold as f64 * 100.0;
    println!("Count of MIC: {:?}", total_mics);
    println!(
        "Odd count threasold for {:?}% : {:?}",
        in_percent, threshold_odd_count
    );

    let expected_even = total_mics - threshold_odd_count;

    //let mut rng = OsRng;

    for i in 0..=u32::MAX {
        /* let mut even_count = 0; */
        let mut odd_count = 0;

        if verbose {
            println!("i 32-bit : {:032b}", i);
            println!("-------------------------------------------------------");
        }

        for &mic in mic_list {
            let mic = mic as u32; // convert all signed mic

            if verbose {
                println!("mic:            {:032b}", mic);
            }

            let and_result = i & mic;
            if verbose {
                println!("AND:     {:032b}", and_result);
            }

            let bit_count = and_result.count_ones();
            let parity = bit_count & 1;
            if verbose {
                println!("bits set to 1:  {}", bit_count);
            }

            /* if parity == 0 {
                even_count += 1;
                if verbose {
                    println!("Even number of 1 bits");
                }
            }  */
            if parity == 1 {
                odd_count += 1;
                if verbose {
                    println!("Odd number of 1 bits");
                }
            }

            if verbose {
                println!("XOR of all AND results: {:032b}", and_result);
            }
        }
        if odd_count < threshold_odd_count || odd_count > expected_even {
            /* even_counts.push(even_count); */
            println!("Test failed with {:?}, odd: {:?}", i, odd_count);
            odd_counts.push(odd_count);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("../all_mic.json")?;
    let reader = BufReader::new(file);

    let mic_list: MicList = serde_json::from_reader(reader)?;

    test_bit_quality(&mic_list.mic, false);

    /* println!("Even counts: {:?}", even_counts);
    println!("Odd counts: {:?}", odd_counts); */

    // export to files
    /*     let even_counts_json = json!({ "even_counts": even_counts });
    let odd_counts_json = json!({ "odd_counts": odd_counts });


    let mut even_counts_file = File::create("../even_counts2.json")?;
    serde_json::to_writer_pretty(&even_counts_file, &even_counts_json)?;

    let mut odd_counts_file = File::create("../odd_counts2.json")?;
    serde_json::to_writer_pretty(&odd_counts_file, &odd_counts_json)?; */

    Ok(())
}
