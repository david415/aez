 // aez.rs - The rust AEZ wrapper implementation.
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

extern crate blake2b;
extern crate subtle;
extern crate byteorder;


use std::ptr;
use self::byteorder::{ByteOrder, BigEndian};
use self::blake2b::blake2b;
use self::subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

use super::aez_amd64::{EXTRACTED_KEY_SIZE, BLOCK_SIZE, DBL_CONSTS,
                       RoundAesni, xor_bytes_1x16,
                       aez_core_pass_1_amd64_aesni,
                       aez_core_pass_2_amd64_aesni};

pub fn memwipe(val: &mut [u8]) {
    let zeros = vec![0u8; val.len()];
    unsafe {
        ptr::copy_nonoverlapping(&zeros[0] as *const u8, &mut val[0] as *mut u8, val.len());
    }
}

fn extract(k: &[u8], extracted_key: &mut [u8; EXTRACTED_KEY_SIZE]) {
    if k.len() == EXTRACTED_KEY_SIZE {
        extracted_key.clone_from_slice(k);
    } else {
        let h = blake2b(EXTRACTED_KEY_SIZE, k);
        let mut hash = Vec::new();
        hash.extend(h.iter());
        extracted_key.clone_from_slice(&hash);
        memwipe(hash.as_mut());
        drop(hash);
    }
}

fn double_block(p: &mut [u8; BLOCK_SIZE]) {
    let tmp = p[0].clone();
    let mut i = 0;
    while i < 15 {
        p[i] = (p[i] << 1) | (p[i+1] >> 7);
        i = i + 1;
    }
    let one = 1;
    let s = (tmp>>7).ct_eq(&one).unwrap_u8();
    let one_three_five = 135;
    p[15] = (p[15] << 1) ^ u8::conditional_select(&s, &one_three_five, Choice::from(0));
}

fn mult_block(x: u32, src: &[u8; BLOCK_SIZE], dst: &mut [u8; BLOCK_SIZE]) {
    let mut t = [8; BLOCK_SIZE];
    let mut r = [8; BLOCK_SIZE];
    t.clone_from_slice(src);
    let mut i = x;
    while i != 0 {
        if i & 1 != 0 {
            xor_bytes_1x16(&r.clone(), &t, &mut r)
        }
        double_block(&mut t);
        i >>= 1;
    }
    dst.clone_from_slice(&r);
    memwipe(&mut t);
    memwipe(&mut r);
}

fn one_zero_pad(src: &[u8], sz: usize, dst: &mut [u8; BLOCK_SIZE]) {
    memwipe(dst);
    dst.clone_from_slice(&src[..sz]);
    dst[sz] = 0x80;
}

#[derive(Clone, Default)]
struct EState {
    i: [[u8; 16]; 2],
    j: [[u8; 16]; 3],
    l: [[u8; 16]; 8],
    aes: RoundAesni,
}

impl EState {
    pub fn new(k: &[u8]) -> EState {
        let mut extracted_key = [0u8; EXTRACTED_KEY_SIZE];

        extract(k, &mut extracted_key);

        let mut e = EState::default();
        e.j[0].clone_from_slice(&extracted_key[..16]);   // 1I
        mult_block(2, &e.i[0].clone(), &mut e.i[1]);     // 2I

        e.j[0].clone_from_slice(&extracted_key[16..32]); // 1J
        mult_block(2, &e.j[0].clone(), &mut e.j[1]);     // 2J
        mult_block(2, &e.j[1].clone(), &mut e.j[2]);     // 4J

	// The upstream `aesni` code only stores L1, L2, and L4, but it has
	// the benefit of being written in a real language that has vector
	// intrinsics.

        e.l[1].clone_from_slice(&extracted_key[32..48]);               // L1
        mult_block(2, &e.l[1].clone(), &mut e.l[2]);                   // L2 = L1*2
        xor_bytes_1x16(&e.l[2].clone(), &e.l[1].clone(), &mut e.l[3]); // L3 = L2+L1
        mult_block(2, &e.l[2].clone(), &mut e.l[4]);                   // L4 = L2*2
        xor_bytes_1x16(&e.l[4].clone(), &e.l[1].clone(), &mut e.l[5]); // L5 = L4+L1
        mult_block(2, &e.l[3].clone(), &mut e.l[6]);                   // L6 = L3*2
        xor_bytes_1x16(&e.l[6].clone(), &e.l[1].clone(), &mut e.l[7]); // L7 = L6+L1

        e.aes = RoundAesni::new(extracted_key);
        memwipe(&mut extracted_key);
        e
    }

    pub fn reset(&mut self) {
        let mut i = 0;
        while i < self.i.len() {
            memwipe(&mut self.i[i]);
            i += 1;
        }
        i = 0;
        while i < self.j.len() {
            memwipe(&mut self.j[i]);
            i += 1;
        }
        i = 0;
        while i < self.l.len() {
            memwipe(&mut self.l[i]);
            i += 1;
        }
    }

    pub fn aez_core_pass1(&self, src: &[u8], dst: &mut [u8], x: &[u8; BLOCK_SIZE], sz: usize) {
        aez_core_pass_1_amd64_aesni(src, dst, x, &self.i[0], &self.l[0], &self.aes.keys, &DBL_CONSTS, sz)
    }

    pub fn aez_core_pass2(&self, src: &[u8], dst: &mut [u8], y: &[u8; BLOCK_SIZE], s: &[u8; BLOCK_SIZE], sz: usize) {
        aez_core_pass_2_amd64_aesni(dst, y, s, &self.j[0], &self.i[1], &self.l[0], &self.aes.keys, &DBL_CONSTS, sz);
    }

    pub fn aez_hash(&self, nonce: &[u8], ad: Option<&Vec<Vec<u8>>>, tau: u32, result: &mut [u8; BLOCK_SIZE]) {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut sum = [0u8; BLOCK_SIZE];
        let mut i = [0u8; BLOCK_SIZE];
        let mut j = [0u8; BLOCK_SIZE];

	// Initialize sum with hash of tau
        BigEndian::write_u32(&mut buf[12..], tau);
        xor_bytes_1x16(&self.j[0].clone(), &self.j[1], &mut j);
        self.aes.aes4(&j, &self.i[1], &self.l[1], &buf, &mut sum);

        // Hash nonce, accumulate into sum
        let mut n_bytes = nonce.len() as u32;
        i.clone_from_slice(&self.i[1]);
        let mut n = nonce;
        let mut x = 0;
        while n_bytes >= BLOCK_SIZE as u32 {
            self.aes.aes4(&self.j[2], &i, &self.l[x%8], &n[..BLOCK_SIZE], &mut buf);
            xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
            n = &n[BLOCK_SIZE..];
            if x % 8 == 0 {
                double_block(&mut i);
            }
            n_bytes = n_bytes - BLOCK_SIZE as u32;
            x = x + 1;
        }
        if n_bytes > 0 || nonce.len() == 0 {
            memwipe(&mut buf);
            buf.clone_from_slice(&n);
            buf[n_bytes as usize] = 0x80;
            self.aes.aes4(&self.j[2], &self.i[0], &self.l[0], &buf.clone(), &mut buf);
            xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
        }

        // Hash each vector element, accumulate into sum
        if ad.is_some() {
            x = 0;
            while x < ad.unwrap().len() {
                let mut p = ad.unwrap()[x].clone();
                let is_empty = p.len() == 0;
                let mut bytes = p.len();
                i.clone_from_slice(&self.i[1]);
                mult_block(5+x as u32, &self.j[0], &mut j);
                let mut y = 0;
                while bytes >= BLOCK_SIZE {
                    self.aes.aes4(&j, &i, &self.l[y%8], &p[..BLOCK_SIZE], &mut buf); // E(5+k,i)
                    xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
                    p = p[BLOCK_SIZE..].to_vec();
                    if y % 8 == 0 {
                        double_block(&mut i);
                    }
                    y = y+1;
                    bytes = bytes - BLOCK_SIZE;
                }
                if bytes > 0 || is_empty {
                    memwipe(&mut buf);
                    buf.clone_from_slice(&p);
                    buf[bytes] = 0x80;
                    self.aes.aes4(&j, &self.i[0], &self.l[0], &buf.clone(), &mut buf);
                    xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
                }
                x += 1;
            }
        }

        memwipe(&mut i);
        memwipe(&mut j);
        result.clone_from_slice(&sum);
    }

    pub fn aez_prf(&self, delta: &[u8; BLOCK_SIZE], tau: usize, result: &mut [u8]) {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut ctr = [0u8; BLOCK_SIZE];
        let mut t = tau;
        let mut off = 0;
        while t >= BLOCK_SIZE {
            xor_bytes_1x16(&delta, &ctr, &mut buf);
            &self.aes.aes10(&self.l[3], &buf.clone(), &mut buf); // E(-1,3)
            result[off..].clone_from_slice(&buf);

            let mut i = 15;
            loop {
                ctr[i] += 1;
                i -= 1;
                if ctr[i+1] != 0 {
                    break
                }
            }

            t -= BLOCK_SIZE;
            off += BLOCK_SIZE;
        }
        if t > 0 {
            xor_bytes_1x16(&delta, &ctr, &mut buf);
            self.aes.aes10(&self.l[3], &buf.clone(), &mut buf); // E(-1,3)
        }

        memwipe(&mut buf);
    }
}


// Encrypt encrypts and authenticates the plaintext, authenticates the
// additional data, and appends the result to ciphertext, returning the
// updated slice.  The length of the authentication tag in bytes is specified
// by tau.  The plaintext and dst slices MUST NOT overlap.
pub fn encrypt(key: &[u8], nonce: &[u8], additional_data: &[u8], tau: usize, plaintext: &[u8], dst: &[u8]) {

}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use super::*;
    use self::rustc_serialize::hex::ToHex;

    #[test]
    fn test_memwipe() {
        let mut fu = vec![0x3u8; 20];
        let zeros = vec![0u8; 20];
        memwipe(&mut fu);
        assert_eq!(zeros, fu);
    }

    #[test]
    fn test_extract() {
        let fu = vec![0x3u8; EXTRACTED_KEY_SIZE-5];
        let mut out = [0u8; EXTRACTED_KEY_SIZE];
        extract(&fu, &mut out);
    }

    #[test]
    fn test_estate_new() {
        let k = vec![0x77u8; 333];
        let mut s = EState::new(&k);
        println!("key is {}", s.aes.keys.to_hex());
    }
}
