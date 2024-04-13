use aes_gcm_siv::{
    aead::Aead, KeyInit, Nonce
};
use env_logger;
use log::{error, info};
use rand::{thread_rng, Rng};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

fn main() {
    // Initialize logger
    env_logger::init();

    let input_file_path = get_input_file_path();
    let input_data = read_input_data(&input_file_path);
    let key = get_encryption_key();

    let encrypted_data = encrypt_data(&input_data, &key);
    write_encrypted_data(&encrypted_data);

    let decrypted_data = decrypt_data(&encrypted_data, &key);
    println!("Decrypted data: {:?}", String::from_utf8_lossy(&decrypted_data));
}

// Get input file path from user
fn get_input_file_path() -> String {
    let mut input_file_path = String::new();
    println!("Enter input file path: ");
    io::stdin()
        .read_line(&mut input_file_path)
        .expect("Failed to read input file path");
    input_file_path.trim().to_string()
}

// Read input data from file
fn read_input_data(input_file_path: &str) -> Vec<u8> {
    let mut input_data = Vec::new();
    if Path::new(input_file_path).exists() {
        let mut file = File::open(input_file_path).expect("Failed to open input file");
        file.read_to_end(&mut input_data)
            .expect("Failed to read input data");
        info!("Input data read from file: {}", input_file_path);
    } else {
        error!("Input file not found: {}", input_file_path);
        std::process::exit(1);
    }
    input_data
}

// Get encryption key from user securely
fn get_encryption_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    println!("Enter encryption key (32 bytes): ");
    io::stdin().read_exact(&mut key).expect("Failed to read encryption key");
    info!("Encryption key obtained");
    key
}

// Encrypt input data using AES-GCM-SIV algorithm
fn encrypt_data(input_data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let aead = aes_gcm_siv::Aes256GcmSiv::new(key);
    let nonce = Nonce::from_slice(&thread_rng().gen::<[u8; 12]>());
    let ciphertext = aead
        .encrypt(nonce, input_data)
        .expect("Encryption failed");

    let mut encrypted_data = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);
    info!("Data encrypted successfully");
    encrypted_data
}

// Write encrypted data to a file
fn write_encrypted_data(encrypted_data: &[u8]) {
    let mut output_file = File::create("encrypted_data.bin").expect("Failed to create output file");
    output_file
        .write_all(encrypted_data)
        .expect("Failed to write encrypted data");
    info!("Encrypted data written to encrypted_data.bin");
}

// Decrypt encrypted data using AES-GCM-SIV algorithm
fn decrypt_data(encrypted_data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let aead = aes_gcm_siv::Aes256GcmSiv::new(key);
    let nonce = Nonce::from_slice(&encrypted_data[..12]);
    let decrypted_data = aead
        .decrypt(nonce, &encrypted_data[12..])
        .expect("Decryption failed");
    info!("Data decrypted successfully");
    decrypted_data
}