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

use std::ptr;

use super::aez_binding::{aez_setup_encrypt, aez_setup_decrypt};


pub fn encrypt(key: &[u8; 48], nonce: &[u8; 16], mesg: &Vec<u8>) -> Vec<u8> {
    let mut ciphertext = vec![0u8; mesg.len()];
    unsafe {
        aez_setup_encrypt(key as *const u8, nonce as *const u8, ptr::null(), 0, 0, mesg.as_ptr(), mesg.len(), ciphertext.as_mut_ptr());
    }
    ciphertext
}


pub fn decrypt(key: &[u8; 48], nonce: &[u8; 16], mesg: &Vec<u8>) -> Vec<u8> {
    let mut plaintext = vec![0u8; mesg.len()];
    unsafe {
        aez_setup_decrypt(key as *const u8, nonce as *const u8, ptr::null(), 0, 0, mesg.as_ptr(), mesg.len(), plaintext.as_mut_ptr());
    }
    plaintext
}


#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use super::*;
    use self::rustc_serialize::hex::{FromHex};

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
        let mut key_array = [0u8; 48];
        key_array.clone_from_slice(&key);
        let mut nonce_array = [0u8; 16];
        nonce_array.clone_from_slice(&nonce);
        let ciphertext = encrypt(&key_array, &nonce_array, &payload);
        let plaintext = decrypt(&key_array, &nonce_array, &ciphertext);
        assert_eq!(payload.as_slice(), plaintext.as_slice());
        //let out_str = String::from_utf8_lossy(&plaintext);
        //println!("plaintext! {}", out_str)
    }
}
