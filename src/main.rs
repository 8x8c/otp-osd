use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

// ----- Key traits/types from cipher crate -----
use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher}; // no StreamCipherSeek if you don't need random seeking
use cipher::generic_array::GenericArray;
use rand::RngCore;

fn main() -> io::Result<()> {
    // We'll assume you keep a 32-byte key in "key.key"
    let master_key_file = "key.key";

    // ------------------------------------------------------------------------
    // 1. Parse Command-Line
    //    e.g.:
    //       ./c encrypt input.bin output.bin
    //       ./c decrypt input.bin output.bin
    //       ./c encrypt -over file.bin
    //       ./c decrypt -over file.bin
    // ------------------------------------------------------------------------
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage:");
        eprintln!("  {} encrypt <input_file> <output_file>", args[0]);
        eprintln!("  {} decrypt <input_file> <output_file>", args[0]);
        eprintln!("  {} encrypt -over <input_file>", args[0]);
        eprintln!("  {} decrypt -over <input_file>", args[0]);
        std::process::exit(1);
    }

    let command = args[1].as_str();
    let (input_path, output_path, atomic_overwrite) = match args.len() {
        4 if &args[2] == "-over" => (args[3].clone(), args[3].clone(), true),
        4 => (args[2].clone(), args[3].clone(), false),
        _ => {
            eprintln!("Incorrect arguments provided.");
            std::process::exit(1);
        }
    };

    // ------------------------------------------------------------------------
    // 2. Read 32-byte master key from file
    // ------------------------------------------------------------------------
    let master_key = fs::read(master_key_file).map_err(|e| {
        eprintln!("Error reading '{}': {}", master_key_file, e);
        e
    })?;
    if master_key.len() != 32 {
        eprintln!("Master key must be exactly 32 bytes. Found {}.", master_key.len());
        std::process::exit(1);
    }

    // Build a GenericArray<u8, 32> from the slice
    let key_array = GenericArray::from_slice(&master_key);

    // ------------------------------------------------------------------------
    // 3. Command: encrypt or decrypt
    // ------------------------------------------------------------------------
    match command {
        "encrypt" => {
            let input_data = fs::read(&input_path).map_err(|e| {
                eprintln!("Error reading '{}': {}", input_path, e);
                e
            })?;

            // Generate a 12-byte nonce (commonly used size for ChaCha20)
            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);

            // Create a GenericArray<u8, 12> for the nonce
            let nonce_array = GenericArray::from_slice(&nonce_bytes);

            // Build the cipher
            let mut cipher = ChaCha20::new(key_array, nonce_array);

            // XOR-encrypt in memory
            let mut encrypted_data = input_data.clone();
            cipher.apply_keystream(&mut encrypted_data);

            // Prepend nonce to ciphertext
            let mut final_output = Vec::with_capacity(nonce_bytes.len() + encrypted_data.len());
            final_output.extend_from_slice(&nonce_bytes);
            final_output.extend_from_slice(&encrypted_data);

            // Output
            if atomic_overwrite {
                atomic_overwrite_file(&input_path, &final_output)?;
            } else {
                fs::write(&output_path, &final_output)?;
            }
            println!("Encrypted successfully.");
        }

        "decrypt" => {
            let file_data = fs::read(&input_path).map_err(|e| {
                eprintln!("Error reading '{}': {}", input_path, e);
                e
            })?;

            if file_data.len() < 12 {
                eprintln!("File too small; no room for 12-byte nonce.");
                std::process::exit(1);
            }

            let nonce_part = &file_data[0..12];
            let ciphertext = &file_data[12..];

            // Create GenericArray<u8, 12> from the nonce
            let nonce_array = GenericArray::from_slice(nonce_part);

            // Build cipher
            let mut cipher = ChaCha20::new(key_array, nonce_array);

            // XOR-decrypt in memory
            let mut decrypted_data = ciphertext.to_vec();
            cipher.apply_keystream(&mut decrypted_data);

            // Output
            if atomic_overwrite {
                atomic_overwrite_file(&input_path, &decrypted_data)?;
            } else {
                fs::write(&output_path, &decrypted_data)?;
            }
            println!("Decrypted successfully.");
        }

        _ => {
            eprintln!("Unknown command '{}'. Use 'encrypt' or 'decrypt'.", command);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Overwrites the original file atomically by writing to a temp file and renaming.
fn atomic_overwrite_file(original_path: &str, data: &[u8]) -> io::Result<()> {
    let input_file_path = Path::new(original_path);
    let tmp_path = input_file_path
        .with_file_name(format!(
            "{}.tmp",
            input_file_path.file_name().unwrap().to_string_lossy()
        ));

    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;
        tmp_file.write_all(data)?;
        tmp_file.flush()?;
        tmp_file.sync_all()?;
    }

    fs::rename(&tmp_path, &input_file_path)?;
    Ok(())
}


