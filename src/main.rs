use std::env;
use std::process;
use hex::decode;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use web3::types::Address;
use clap::Parser;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
struct Args {
  /// Deployer address in hex format, defaults to dummy deployer address
  #[arg(long)]
  deployer_address: Address,
  /// Create2 deploy bytecode hash in hex format, defaults to Axelar CreateDeploy bytecode hash
  #[arg(long, default_value = "6803d80924868e122b4d95a102318f0b1b97bcecc0ef62c3c7835b4198f98a28")]
  bytecode_hash: String,
  /// Start of the address in hex format
  #[arg(long, value_parser)]
  start_with: String,
  /// End of the address in hex format (optional)
  #[arg(long, value_parser)]
  end_with: Option<String>,
  /// Number of salts to find
  #[arg(short, long, default_value_t = 1)]
  count: usize,
}

fn create3_address(deployer: Address, salt: &[u8], bytecode_hash: &[u8]) -> Address {
  let mut hasher = Keccak256::new();
  hasher.update(&[0xff]);
  hasher.update(deployer.as_bytes());
  hasher.update(salt);
  hasher.update(bytecode_hash);
  let deployer_hash = hasher.finalize();
  let deployer_address = Address::from_slice(&deployer_hash[12..]);

  let mut hasher = Keccak256::new();
  hasher.update(&[0xd6, 0x94]);
  hasher.update(deployer_address.as_bytes());
  hasher.update(&[0x01]);
  let deployed_hash = hasher.finalize();
  Address::from_slice(&deployed_hash[12..])
}

fn find_salts(
  deployer: Address,
  start_with: &str,
  end_with: Option<&str>,
  bytecode_hash: &[u8],
  count: usize,
) -> Vec<String> {
  let start_with_lower = start_with.to_lowercase();
  let start_with_bytes = decode(&start_with_lower[2..]).expect("Invalid start_with prefix");

  let end_with_bytes = end_with.map(|end_with| {
      let end_with_lower = end_with.to_lowercase();
      decode(&end_with_lower[2..]).expect("Invalid end_with suffix")
  });

  let found_salts = AtomicUsize::new(0);
  let pb = ProgressBar::new(count as u64);
  let style = ProgressStyle::default_bar()
      .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
      .unwrap_or_else(|_| ProgressStyle::default_bar());
  pb.set_style(style.progress_chars("##-"));

  let start_time = Instant::now();

  let salts: Vec<String> = (0u128..u128::MAX)
      .into_par_iter()
      .filter_map(|salt_int| {
          if found_salts.load(Ordering::Relaxed) >= count {
            process::exit(0);
          }
          let salt_bytes = salt_int.to_be_bytes();
          let address = create3_address(deployer, &salt_bytes, bytecode_hash);
          let address_bytes = address.0.to_vec();

          if address_bytes.starts_with(&start_with_bytes)
              && end_with_bytes
                  .as_ref()
                  .map_or(true, |end_with_bytes| address_bytes.ends_with(end_with_bytes))
          {
              let current_count = found_salts.fetch_add(1, Ordering::Relaxed);
              if current_count < count {
                  pb.set_position((current_count + 1) as u64);

                  // Print the salt as it's found
                  println!("Salt {}: {}, Address: 0x{:x}", current_count, hex::encode(salt_bytes), address);

                  // Update time estimate only if a 1+ salts have been found
                  if current_count > 1 {
                      let elapsed = start_time.elapsed();
                      let estimated_remaining =
                          (elapsed / current_count as u32) * (count - current_count) as u32;
                      pb.set_message(format!(
                          "Estimated remaining: {:?}",
                          estimated_remaining
                      ));
                  }

                  Some(hex::encode(salt_bytes))
              } else {
                  None
              }
          } else {
              None
          }
      })
      .collect();

  pb.finish_with_message("Mining complete");

  salts
}

fn main() {
  let args = Args::parse_from(env::args_os());
  let deployer = args.deployer_address;
  let bytecode_hash = decode(&args.bytecode_hash[2..]).expect("Invalid bytecode_hash");
  let start_with = &args.start_with;
  let end_with = args.end_with.as_deref();
  let count = args.count;

  find_salts(
    deployer,
    start_with,
    end_with,
    &bytecode_hash,
    count,
  );
}
