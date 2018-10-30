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

use self::libc::size_t;

extern "C" {
    type aez_ctx_t;

    // aez_ctx_t *aez_setup(unsigned char *key, unsigned keylen) {
    fn aez_setup(key: *const u8, keylen: usize) -> *mut aez_ctx_t;

    // void aez_encrypt(aez_ctx_t *ctx, char *n, unsigned nbytes,
    //          char *ad, unsigned adbytes, unsigned abytes,
    //          char *src, unsigned bytes, char *dst) {
    fn aez_encrypt(ctx: *mut aez_ctx_t, nonce: *const u8, nonce_len: usize,
                   ad: *const u8, ad_len: usize, a_len: usize, src: *const u8,
                   src_len: usize, dst: *mut u8);

    // int aez_decrypt(aez_ctx_t *ctx, char *n, unsigned nbytes,
    //          char *ad, unsigned adbytes, unsigned abytes,
    //          char *src, unsigned bytes, char *dst) {
    fn aez_decrypt(ctx: *mut aez_ctx_t, nonce: *const u8, nonce_len: usize,
                   ad: *const u8, ad_len: usize, a_len: usize, src: *const u8,
                   src_len: usize, dst: *mut u8);
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
        let mut key = [0u8; 48];
        rng.fill_bytes(&mut key);

        let s = String::from("We must defend our own privacy if we expect to have any. \
                              We must come together and create systems which allow anonymous transactions to take place. \
                              People have been defending their own privacy for centuries with whispers, darkness, envelopes, \
                              closed doors, secret handshakes, and couriers. The technologies of the past did not allow for strong \
                              privacy, but electronic technologies do.");
        let _s_len = s.len();
        let string_bytes = s.into_bytes();

        let nonce = [0u8; 12];
        let ad = vec![0u8; 16];
        let a_len = 0;

        let mut ciphertext = vec![0u8; 500];
        let mut payload = vec![0u8; 500];
        payload[0.._s_len].copy_from_slice(&string_bytes);

        let mut plaintext = vec![0u8; 500];

        unsafe {
            let ctx = aez_setup(&key as *const u8, key.len());
            aez_encrypt(ctx, &nonce as *const u8, nonce.len(), ad.as_ptr(), 0, 0, payload.as_ptr(), payload.len(), ciphertext.as_mut_ptr());
            println!("ciphertext! {}", ciphertext.to_hex());

            aez_decrypt(ctx, &nonce as *const u8, nonce.len(), ad.as_ptr(), 0, 0, ciphertext.as_ptr(), ciphertext.len(), plaintext.as_mut_ptr());
            let out_str = String::from_utf8_lossy(&plaintext);
            println!("plaintext! {}", out_str);

            assert_eq!(payload.as_slice(), plaintext.as_slice());
        }
    }
}
