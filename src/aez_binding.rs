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

extern crate libc;

use self::libc::c_int;

extern "C" {
    pub fn Decrypt(K: *const u8, kbytes: usize, N: *const u8, nbytes: usize,
                   AD: *const u8, adbytes: *const u8, veclen: usize, abytes: usize,
                   M: *const u8, mbytes: usize, C: *const u8) -> c_int;

    pub fn aez_setup_encrypt(key: *const u8, nonce: *const u8,
                             ad: *const u8, adlen: usize, alen: usize,
                             src: *const u8, srclen: usize, dst: *mut u8);

    pub fn aez_setup_decrypt(key: *const u8, nonce: *const u8,
                             ad: *const u8, adlen: usize, alen: usize,
                             src: *const u8, srclen: usize, dst: *mut u8) -> c_int;
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use super::*;
    use std::ptr;
    use self::rustc_serialize::hex::FromHex;

    #[test]
    fn test_simple_bindings_usage() {
        let key_str = "ec6dc9fb5e68dbc2a7615c67baf5b8e472953b84918f1e0c4e01cf43387535d292c4be5657849d84246c7253a3252577";
        let key = key_str.from_hex().unwrap();
        let nonce_str = "05ef180b20d561bf6024a4ecf725fc17";
        let nonce = nonce_str.from_hex().unwrap();
        let m_str = "82ed7abbe93cb1a7ec2d1072f591c058237ff54fc4d44d86cb07c0620675b56b";
        let plaintext = m_str.from_hex().unwrap();
        let mut case_ciphertext = vec![0u8; plaintext.len()];
        let mut case_plaintext = vec![0u8; plaintext.len()];
        unsafe {
            aez_setup_encrypt(key.as_ptr(), nonce.as_ptr(),
                              ptr::null(), 0, 0,
                              plaintext.as_ptr(), plaintext.len(), case_ciphertext.as_mut_ptr());
            aez_setup_decrypt(key.as_ptr(), nonce.as_ptr(),
                              ptr::null(), 0, 0,
                              case_ciphertext.as_ptr(), case_ciphertext.len(), case_plaintext.as_mut_ptr());
            assert_eq!(plaintext.as_slice(), case_plaintext.as_slice());
        }
    }
}
