// aez.rs - The rust bindings for a hardware optimized AEZ implemented in C.
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
use super::error::AezDecryptionError;


pub const AEZ_KEY_SIZE: usize = 48;
pub const AEZ_NONCE_SIZE: usize = 16;


extern "C" {
    fn aez_setup_encrypt(key: *const u8, nonce: *const u8,
                         ad: *const u8, adlen: usize, alen: usize,
                         src: *const u8, srclen: usize, dst: *mut u8);

    fn aez_setup_decrypt(key: *const u8, nonce: *const u8,
                         ad: *const u8, adlen: usize, alen: usize,
                         src: *const u8, srclen: usize, dst: *mut u8) -> c_int;
}




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
    use std::ptr;
    use self::rustc_serialize::hex::FromHex;
    use std::fs::File;
    use std::path::PathBuf;
    use std::io::prelude::*;

    #[test]
    fn test_simple_bindings_usage() {
        let key_str = "ec6dc9fb5e68dbc2a7615c67baf5b8e472953b84918f1e0c4e01cf43387535d292c4be5657849d84246c7253a3252577";
        let key = key_str.from_hex().unwrap();
        let nonce_str = "05ef180b20d561bf6024a4ecf725fc17";
        let nonce = nonce_str.from_hex().unwrap();
        let plaintext_str = String::from("As computer scientists and cryptographers, we are twice culpable when it
comes to mass surveillance: computer science created the technologies that
underlie our communications infrastructure, and that are now turning it into
an apparatus for surveillance and control; while cryptography contains within it
the underused potential to help redirect this tragic turn.");
        let plaintext = plaintext_str.as_bytes();
        let mut case_ciphertext = vec![0u8; plaintext.len()];
        let mut case_plaintext = vec![0u8; plaintext.len()];
        unsafe {
            aez_setup_encrypt(key.as_ptr(), nonce.as_ptr(),
                              ptr::null(), 0, 0,
                              plaintext.as_ptr(), plaintext.len(), case_ciphertext.as_mut_ptr());
            aez_setup_decrypt(key.as_ptr(), nonce.as_ptr(),
                              ptr::null(), 0, 0,
                              case_ciphertext.as_ptr(), case_ciphertext.len(), case_plaintext.as_mut_ptr());
            assert_eq!(plaintext, case_plaintext.as_slice());
        }
    }

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

        let c_str = "ff2e5f36255d0c2609a13df1b822da4bdc688c344ae818d7b0f19d55f12bdabba2b25587af44104996a0e6f80f667cddb3a004dae49b3010ef593bf117e559b749f6f11e54865c636bbdd14d7d1313e700e9a83c4941c1e4e9a17d8bd15a9a9d2a90e70ceb1d66c4fba68c5ddc521b5a178cc269b910c8271ec9288468d2e048e80ec1ceee8744023ca28dc8ec4abc62735158dfc2c8d3fa4a3b99d268cbdce0e3d3cece217125577a69dc0fb41d52aa7f2520d3b7e785858ac0e4114de0a1cb91feca6c1fb953be61c69a01a1ff5306e2c533d82a63ae69c21e0e68aced3adb557a22a20d298dd8439151b1ea5e7a74e5d42541b232017f800253d58b5603bec2a49fe0ad8fbd5d6551f24be09f854b67237e21dfd7609ab76441840684dad376c9717de1b4214e9475b8f4418120ddd62adb2c04ab20cabb08a827f6fd188430173a4422d127a0c67f2b762be39510dc6191c5bef4094508372e92caaec3f95d9ee64f9a15231c7cfc80cc9a7efb30c5b0062a2b2f0364d8f9d833ff00225cba6d6559aaa521e9ff60ccc4968632177186174e3c17e32b42458206f657958eb33d9452707bf5805926ee4d4704eb5191d9be0d46085045cd9d75590ae67d33b31e9e8028ab4d3ffd86e2d67f782926720670ccae514fb4a211ca10533a0651ec97a162ee8891d6c4fbf3512439d498f0c6905c5aa81b6875359d2f9019bced45afa91a0a48e3fc4ae2ec752bd0af58034155a8c9ceeed9635954d840757e80e3604bdd3b1673fd03c9ef3a395f9408a6c8daa84e950bfc745ed5249f4c6c123c1f3eb1136b510bc7a29f90247109";
        let ciphertext = c_str.from_hex().unwrap();
        let plaintext_str = String::from("I am not optimistic. The figure of the heroic cryptographer sweeping in to
save the world from totalitarian surveillance is ludicrous. And in a world where
intelligence agencies stockpile and exploit countless vulnerabilities, obtain CA
secret keys, subvert software-update mechanisms, infiltrate private companies
with moles, redirect online discussions in favored directions, and exert enormous
influence on standards bodies, cryptography alone will be an ineffectual response.
At best, cryptography might be a tool for creating possibilities within contours
circumscribed by other forces.");
        let plaintext = plaintext_str.into_bytes();
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
