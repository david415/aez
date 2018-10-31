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
    use self::rustc_serialize::hex::{FromHex, ToHex};
    use std::fs::File;
    use std::path::PathBuf;
    use std::io::prelude::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key_str = "f499be9a1dd859c1471156baed30ba7b35f19abf8e94a7868410a79ce61bdb5b995bd0e69592ff677875e5d693388e3d";
        let key = key_str.from_hex().unwrap();
        let nonce_str = "facef44b512767cd889f2abea615beef";
        let nonce = nonce_str.from_hex().unwrap();
        let s = String::from("We must defend our own privacy if we expect to have any. \
                              We must come together and create systems which allow anonymous transactions to take place. \
                              People have been defending their own privacy for centuries with whispers, darkness, envelopes, \
                              closed doors, secret handshakes, and couriers. The technologies of the past did not allow for strong \
                              privacy, but electronic technologies do.");
        let _s_len = s.len();
        let string_bytes = s.into_bytes();
        let mut payload = vec![0u8; 500];
        payload[0.._s_len].copy_from_slice(&string_bytes);
        let mut key_array = [0u8; AEZ_KEY_SIZE];
        key_array.clone_from_slice(&key);
        let mut nonce_array = [0u8; AEZ_NONCE_SIZE];
        nonce_array.clone_from_slice(&nonce);
        let ciphertext = encrypt(&key_array, &nonce_array, &payload);
        let plaintext = decrypt(&key_array, &nonce_array, &ciphertext).unwrap();
        assert_eq!(payload.as_slice(), plaintext.as_slice());
        //let out_str = String::from_utf8_lossy(&plaintext);
        //println!("plaintext! {}", out_str)
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

            println!("plaintext {} ciphertext {}", plaintext.to_hex(), ciphertext.to_hex());
            
            let mut key_array = [0u8; AEZ_KEY_SIZE];
            key_array.clone_from_slice(&key);
            let mut nonce_array = [0u8; AEZ_NONCE_SIZE];
            nonce_array.clone_from_slice(&nonce);

            let case_plaintext = decrypt(&key_array, &nonce_array, &ciphertext).unwrap();
            assert_eq!(case_plaintext, plaintext);
            
            //let case_ciphertext = encrypt(&key_array, &nonce_array, &plaintext);
            //assert_eq!(case_ciphertext, ciphertext);
            //let case_plaintext = decrypt(&key_array, &nonce_array, &case_ciphertext).unwrap();
        }
    }
}
