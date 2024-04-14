use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use sha2::{Sha256, Sha512, Digest};
use md5;
use blake2::{Blake2b};
use whirlpool::Whirlpool;

fn main() {
    // Read command-line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [file_path | input_data]", args[0]);
        return;
    }

    let input_data = match read_input_data(&args[1]) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Error reading input data: {}", err);
            return;
        }
    };

    // Call the hashing function with the input data
    hash_data(&input_data);
}

// Function to read input data from a file or treat it as a string
fn read_input_data(input: &str) -> Result<Vec<u8>, std::io::Error> {
    if Path::new(input).exists() {
        let mut file = File::open(input)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    } else {
        Ok(input.as_bytes().to_vec())
    }
}

// Function to hash the input data using multiple algorithms
fn hash_data(input_data: &[u8]) {
    let salt = b"my_salt";

    // SHA-256 hashing
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(salt); // Update the hasher with the salt
    sha256_hasher.update(input_data); // Update the hasher with the input data
    let sha256_result = sha256_hasher.finalize(); // Finalize the hash and get the result
    println!("SHA-256 Hash: {:x}", sha256_result);

    // SHA-512 hashing
    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(salt);
    sha512_hasher.update(input_data);
    let sha512_result = sha512_hasher.finalize();
    println!("SHA-512 Hash: {:x}", sha512_result);

    // MD5 hashing
    let mut md5_hasher = md5::Context::new();
    md5_hasher.consume(salt); // Update the hasher with the salt
    md5_hasher.consume(input_data); // Update the hasher with the input data
    let md5_hash = md5_hasher.compute(); // Compute the hash and get the result
    println!("MD5 Hash: {:x}", md5_hash);

    // Blake2b hashing
    // let mut blake2b_hasher = Blake2b::new();
    // blake2b_hasher.update(salt);
    // blake2b_hasher.update(input_data);
    // let blake2b_result = blake2b_hasher.finalize();// Finalize the hash and get the result
    // println!("Blake2b Hash: {:x}", blake2b_result);

    // Whirlpool hashing
    let mut whirlpool_hasher = Whirlpool::new();
    whirlpool_hasher.update(salt);
    whirlpool_hasher.update(input_data);
    let whirlpool_result = whirlpool_hasher.finalize();
    println!("Whirlpool Hash: {:x}", whirlpool_result);
}