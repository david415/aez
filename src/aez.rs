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


extern crate subtle;
extern crate blake2b;

use std::ptr;
use self::blake2b::blake2b;
use self::subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

use super::aez_amd64::{EXTRACTED_KEY_SIZE,
                       aez_aes_4_amd64_aesni,
                       aez_aes_10_amd64_aesni,
                       reset_amd64_sse2,
                       xor_bytes_1x16_amd64_sse2,
                       xor_bytes_4x16_amd64_sse2,
                       BLOCK_SIZE};


pub fn xor_bytes_1x16(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE], dst: &mut [u8; BLOCK_SIZE]) {
    xor_bytes_1x16_amd64_sse2(a, b, dst);
}

pub fn xor_bytes_4x16(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE], c: &[u8; BLOCK_SIZE], d: &[u8; BLOCK_SIZE], dst: &mut [u8; BLOCK_SIZE]) {
    xor_bytes_4x16_amd64_sse2(a, b, c, d, dst);
}

pub fn memwipe(val: &mut [u8]) {
    let zeros = vec![0u8; val.len()];
    unsafe {
        ptr::copy_nonoverlapping(&zeros[0] as *const u8, &mut val[0] as *mut u8, val.len());
    }
}

#[derive(Clone)]
pub struct RoundAesni {
    pub keys: [u8; EXTRACTED_KEY_SIZE],
}

impl Default for RoundAesni {
    fn default() -> RoundAesni {
        RoundAesni{
            keys: [0u8; EXTRACTED_KEY_SIZE],
        }
    }
}

impl RoundAesni {
    pub fn new(keys: [u8; EXTRACTED_KEY_SIZE]) -> RoundAesni {
        RoundAesni {
            keys: keys,
        }
    }

    pub fn reset(&mut self) {
        memwipe(&mut self.keys.to_vec());
        reset_amd64_sse2();
    }

    /// Warning: all args must be heap allocated or this function may seg fault.
    pub fn aes4(&self, j: &[u8], i: &[u8], l: &[u8], src: &[u8], dst: &mut [u8]) {
        aez_aes_4_amd64_aesni(j, i, l, &self.keys, src, dst);
    }

    /// Warning: all args must be heap allocated or this function may seg fault.
    pub fn aes10(&self, l: &[u8], src: &[u8], dst: &mut [u8]) {
        aez_aes_10_amd64_aesni(l, &self.keys, src, dst);
    }
}

fn xor_bytes(a: &[u8], b: &[u8], dst: &mut [u8]) {
    if a.len() < dst.len() || b.len() < dst.len() {
        panic!("aez: xor_bytes: len");
    }
    let mut i = 0;
    while i < dst.len() {
        dst[i] = a[i] ^ b[i];
        i += 1;
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
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;
    extern crate rand;
    
    use super::*;
    use self::rustc_serialize::hex::{FromHex, ToHex};
    use self::rand::Rng;
    use self::rand::os::OsRng;
    use std::fs::File;
    use std::path::PathBuf;
    use std::io::prelude::*;


    fn os_rng() -> OsRng {
        OsRng::new().expect("failure to create an OS RNG")
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

    #[derive(Serialize, Deserialize, Debug)]
    struct TestCase {
        a: String,
        b: String,
    }
    
    fn get_test_data(filename: String) -> Vec<TestCase> {
        let extract_tests_path = get_test_file_path(filename);
        let mut f = File::open(extract_tests_path).unwrap();
        let mut contents = String::new();
        f.read_to_string(&mut contents).unwrap();
        let deserialized: Vec<TestCase> = serde_json::from_str(&contents).unwrap();
        deserialized
    }
    
    #[test]
    fn test_extract() {
        let cases = get_test_data("extract.json".to_string());
        for case in cases {
            let a = case.a.from_hex().unwrap();
            let b = case.b.from_hex().unwrap();
            let mut extracted_key = [0u8; EXTRACTED_KEY_SIZE];
            extract(&a, &mut extracted_key);
            assert_eq!(&b, &extracted_key.to_vec());
        }
    }

}
