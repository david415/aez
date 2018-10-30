// aez_binding.rs - The rust bindings for a hardware optimized AEZ implemented in C.
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

extern "C" {
    fn aez_setup_encrypt(key: *const u8, nonce: *const u8,
                         ad: *const u8, adlen: usize, alen: usize,
                         src: *const u8, srclen: usize, dst: *mut u8);
    fn aez_setup_decrypt(key: *const u8, nonce: *const u8,
                         ad: *const u8, adlen: usize, alen: usize,
                         src: *const u8, srclen: usize, dst: *mut u8);
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use super::*;
    use std::ptr;
    use self::rustc_serialize::hex::{ToHex, FromHex};

    #[test]
    fn test_bindings1() {
        let key_str = "f499be9a1dd859c1471156baed30ba7b35f19abf8e94a7868410a79ce61bdb5b995bd0e69592ff677875e5d693388e3d";
        let key = key_str.from_hex().unwrap();
        let nonce_str = "f44b512767cd889f2abea615";
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
        let ad = [0u8; 16];
        let mut ciphertext = vec![0u8; payload.len()];
        let mut plaintext = vec![0u8; payload.len()];
        unsafe {
            aez_setup_encrypt(key.as_ptr(), nonce.as_ptr(),
                              &ad as *const u8, 0, 0,
                              payload.as_ptr(), payload.len(), ciphertext.as_mut_ptr());
            aez_setup_decrypt(key.as_ptr(), nonce.as_ptr(),
                              &ad as *const u8, 0, 0,
                              ciphertext.as_ptr(), ciphertext.len(), plaintext.as_mut_ptr());
            let out_str = String::from_utf8_lossy(&plaintext);
            assert_eq!(payload.as_slice(), plaintext.as_slice());
        }
    }
}
