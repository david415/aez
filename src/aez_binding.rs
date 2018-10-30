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
    extern crate rand;

    use super::*;
    use std::ptr;
    use self::rustc_serialize::hex::ToHex;
    use self::rand::Rng;
    use self::rand::os::OsRng;

    fn os_rng() -> OsRng {
        OsRng::new().unwrap()
    }

    #[test]
    fn test_bindings1() {
        let mut rng = os_rng();
        let mut key = vec![0u8; 48];
        rng.fill_bytes(&mut key);
        let s = String::from("We must defend our own privacy");
        let _s_len = s.len();
        let payload = s.into_bytes();
        let out_str1 = String::from_utf8_lossy(&payload);
        println!("plaintext! {}", out_str1);
        let mut nonce = vec![0u8; 16];
        rng.fill_bytes(&mut nonce);
        let ad = vec![0u8; 16];
        let mut ciphertext = vec![0u8; payload.len()];
        let mut plaintext = vec![0u8; payload.len()];
        unsafe {
            aez_setup_encrypt(key.as_ptr(), nonce.as_ptr(),
                              ad.as_ptr(), 16, 1,
                              payload.as_ptr(), payload.len(), ciphertext.as_mut_ptr());
            println!("ciphertext! {}", ciphertext.to_hex());
            aez_setup_encrypt(key.as_ptr(), nonce.as_ptr(),
                              ad.as_ptr(), 16, 1,
                              ciphertext.as_ptr(), ciphertext.len(), plaintext.as_mut_ptr());
            let out_str = String::from_utf8_lossy(&plaintext);
            println!("plaintext! {}", out_str);
            assert_eq!(payload.as_slice(), plaintext.as_slice());
        }
    }
}
