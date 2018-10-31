// aez.rs - The rust bindings wrapper.
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

extern crate libc;

use std::ptr;
use self::libc::c_int;

use super::aez_binding::{aez_setup_encrypt, aez_setup_decrypt};
use super::error::AezDecryptionError;

pub const AEZ_KEY_SIZE: usize = 48;
pub const AEZ_NONCE_SIZE: usize = 16;


pub fn encrypt(key: &[u8; AEZ_KEY_SIZE], nonce: &[u8; AEZ_NONCE_SIZE], mesg: &Vec<u8>) -> Vec<u8> {
    let mut ciphertext = vec![0u8; mesg.len()];
    unsafe {
        aez_setup_encrypt(key as *const u8, nonce as *const u8, ptr::null(), 0, 0, mesg.as_ptr(), mesg.len(), ciphertext.as_mut_ptr());
    }
    ciphertext
}


pub fn decrypt(key: &[u8; AEZ_KEY_SIZE], nonce: &[u8; AEZ_NONCE_SIZE], mesg: &Vec<u8>) -> Result<Vec<u8>, AezDecryptionError> {
    let mut plaintext = vec![0u8; mesg.len()];
    let mut ret: c_int = 0;
    unsafe {
        ret = aez_setup_decrypt(key as *const u8, nonce as *const u8, ptr::null(), 0, 0, mesg.as_ptr(), mesg.len(), plaintext.as_mut_ptr());
    }
    if ret != 0 {
        return Err(AezDecryptionError::DecryptionError);
    }
    Ok(plaintext)
}


#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use super::*;
    use self::rustc_serialize::hex::FromHex;
    use std::fs::File;
    use std::path::PathBuf;
    use std::io::prelude::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key_str = "ec6dc9fb5e68dbc2a7615c67baf5b8e472953b84918f1e0c4e01cf43387535d292c4be5657849d84246c7253a3252577";
        let key = key_str.from_hex().unwrap();
        let nonce_str = "05ef180b20d561bf6024a4ecf725fc17";
        let nonce = nonce_str.from_hex().unwrap();
        let mut key_array = [0u8; AEZ_KEY_SIZE];
        key_array.clone_from_slice(&key);
        let mut nonce_array = [0u8; AEZ_NONCE_SIZE];
        nonce_array.clone_from_slice(&nonce);

        let m_str = "82ed7abbe93cb1a7ec2d1072f591c058237ff54fc4d44d86cb07c0620675b56b";
        let c_str = "8adacd91e46ed69d6c7396c0933eb4d5c125b202875e496cb32f49fb3304e489";
        let plaintext = m_str.from_hex().unwrap();
        let ciphertext = c_str.from_hex().unwrap();

        let case_plaintext = decrypt(&key_array, &nonce_array, &ciphertext).unwrap();
        assert_eq!(plaintext, case_plaintext);
    }

    fn get_test_file_path(filename: String) -> PathBuf {
        let mut path = PathBuf::from(file!());
        path.pop();
        path.pop();
        path.pop();
        path.push("testdata/");
        path.push(filename);
        path
    }

    fn get_test_data(filename: String) -> String {
        let extract_tests_path = get_test_file_path(filename);
        let mut f = File::open(extract_tests_path).unwrap();
        let mut contents = String::new();
        f.read_to_string(&mut contents).unwrap();
        contents
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct ExtractTestCase {
        k: String,
        nonce: String,
        data: Vec<String>,
        tau: u32,
        m: String,
        c: String,
    }

    #[test]
    fn test_encrypt_no_ad_vectors() {
        let cases_str = get_test_data("encrypt_no_ad.json".to_string());
        let cases: Vec<ExtractTestCase> = serde_json::from_str(&cases_str).unwrap();
        for case in cases {
            if case.tau != 0 || case.nonce.from_hex().unwrap().len() != 16 {
                continue
            }
            let key = case.k.from_hex().unwrap();
            let nonce = case.nonce.from_hex().unwrap();
            let plaintext = case.m.from_hex().unwrap();
            let ciphertext = case.c.from_hex().unwrap();
            let mut key_array = [0u8; AEZ_KEY_SIZE];
            key_array.clone_from_slice(&key);
            let mut nonce_array = [0u8; AEZ_NONCE_SIZE];
            nonce_array.clone_from_slice(&nonce);
            let case_ciphertext = encrypt(&key_array, &nonce_array, &plaintext);
            assert_eq!(case_ciphertext, ciphertext);
            let case_plaintext = decrypt(&key_array, &nonce_array, &ciphertext).unwrap();
            assert_eq!(case_plaintext, plaintext);
        }
    }
}
