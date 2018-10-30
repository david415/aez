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
extern crate rustc_serialize;
extern crate byteorder;


use std::ptr;
use self::byteorder::{ByteOrder, BigEndian};
use self::blake2b::blake2b;
use self::subtle::{Choice, ConstantTimeEq, ConditionallySelectable};
use self::rustc_serialize::hex::{FromHex, ToHex};

use super::aez_amd64::{EXTRACTED_KEY_SIZE,
                       aez_aes_4_amd64_aesni,
                       aez_aes_10_amd64_aesni,
                       reset_amd64_sse2,
                       xor_bytes_1x16_amd64_sse2,
                       xor_bytes_4x16_amd64_sse2,
                       BLOCK_SIZE};


pub fn xor_bytes_1x16(a: Vec<u8>, b: Vec<u8>, dst: Vec<u8>) -> Vec<u8> {
    xor_bytes_1x16_amd64_sse2(a, b, &mut dst);
    dst
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
    pub fn aes4(&self, j: Vec<u8>, i: Vec<u8>, l: Vec<u8>, src: Vec<u8>, dst: &mut [u8]) {
        aez_aes_4_amd64_aesni(j.as_ref(), i.as_ref(), l.as_ref(), &self.keys, src.as_ref(), dst);
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
    let zero = 0;
    let one_three_five = 135;
    p[15] = (p[15] << 1) ^ u8::conditional_select(&zero, &one_three_five, Choice::from(s));
}

fn mult_block(x: u32, src: &[u8; BLOCK_SIZE], dst: &mut [u8; BLOCK_SIZE]) {
    let mut t = [0u8; BLOCK_SIZE];
    let mut r = vec![];
    t.clone_from_slice(src);
    let mut i = x;
    while i != 0 {
        if i & 1 != 0 {
            r = xor_bytes_1x16(r.to_vec(), t.to_vec(), r);
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
        e.i[0].clone_from_slice(&extracted_key[..16]);   // 1I
        mult_block(2, &e.i[0].clone(), &mut e.i[1]);     // 2I

        e.j[0].clone_from_slice(&extracted_key[16..32]); // 1J
        mult_block(2, &e.j[0].clone(), &mut e.j[1]);     // 2J
        mult_block(2, &e.j[1].clone(), &mut e.j[2]);     // 4J

	// The upstream `aesni` code only stores L1, L2, and L4, but it has
	// the benefit of being written in a real language that has vector
	// intrinsics.

        e.l[1].clone_from_slice(&extracted_key[32..48]);               // L1
        mult_block(2, &e.l[1].clone(), &mut e.l[2]);                   // L2 = L1*2
        xor_bytes_1x16(e.l[2].to_vec(), e.l[1].to_vec(), &mut e.l[3].to_vec()); // L3 = L2+L1
        mult_block(2, &e.l[2].clone(), &mut e.l[4]);                   // L4 = L2*2
        xor_bytes_1x16(e.l[4].to_vec(), e.l[1].to_vec(), &mut e.l[5].to_vec()); // L5 = L4+L1
        mult_block(2, &e.l[3].clone(), &mut e.l[6]);                   // L6 = L3*2
        xor_bytes_1x16(e.l[6].to_vec(), e.l[1].to_vec(), &mut e.l[7].to_vec()); // L7 = L6+L1

        e.aes = RoundAesni::new(extracted_key);
        memwipe(&mut extracted_key);
        e
    }

    pub fn aez_hash(&self, nonce: &[u8], ad: Option<&Vec<Vec<u8>>>, tau: u32, result: &mut [u8; BLOCK_SIZE]) {
        let mut buf = vec![0u8; BLOCK_SIZE];
        let mut sum = vec![0u8; BLOCK_SIZE];
        let mut i = vec![0u8; BLOCK_SIZE];
        let mut j = vec![0u8; BLOCK_SIZE];

	// Initialize sum with hash of tau
        BigEndian::write_u32(&mut buf[12..], tau);

        j = xor_bytes_1x16(self.j[0].to_vec(), self.j[1].to_vec(), j.to_vec());
        println!("yow1");
        
        self.aes.aes4(j, self.i[1].to_vec(), self.l[1].to_vec(), buf, &mut sum);
        println!("yow2");

        println!("sum is {}", sum.to_hex());

        
        // Hash nonce, accumulate into sum
        // let mut n_bytes = nonce.len() as u32;
        // i.clone_from_slice(&self.i[1]);
        // let mut n = nonce;
        // let mut x = 0;
        // while n_bytes >= BLOCK_SIZE as u32 {
        //     self.aes.aes4(&self.j[2], &i, &self.l[x%8], &n[..BLOCK_SIZE], &mut buf);
        //     xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
        //     n = &n[BLOCK_SIZE..];
        //     if x % 8 == 0 {
        //         double_block(&mut i);
        //     }
        //     n_bytes = n_bytes - BLOCK_SIZE as u32;
        //     x = x + 1;
        // }
        // if n_bytes > 0 || nonce.len() == 0 {
        //     memwipe(&mut buf);
        //     buf = [0u8; BLOCK_SIZE];
        //     buf.clone_from_slice(&n);
        //     buf[n_bytes as usize] = 0x80;
        //     self.aes.aes4(&self.j[2], &self.i[0], &self.l[0], &buf.clone(), &mut buf);
        //     xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
        // }

        // // Hash each vector element, accumulate into sum
        // if ad.is_some() {
        //     x = 0;
        //     while x < ad.unwrap().len() {
        //         let mut p = ad.unwrap()[x].clone();
        //         let is_empty = p.len() == 0;
        //         let mut bytes = p.len();
        //         i.clone_from_slice(&self.i[1]);
        //         mult_block(5+x as u32, &self.j[0], &mut j);
        //         let mut y = 0;
        //         while bytes >= BLOCK_SIZE {
        //             self.aes.aes4(&j, &i, &self.l[y%8], &p[..BLOCK_SIZE], &mut buf); // E(5+k,i)
        //             xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
        //             p = p[BLOCK_SIZE..].to_vec();
        //             if y % 8 == 0 {
        //                 double_block(&mut i);
        //             }
        //             y = y+1;
        //             bytes = bytes - BLOCK_SIZE;
        //         }
        //         if bytes > 0 || is_empty {
        //             memwipe(&mut buf);
        //             buf.clone_from_slice(&p);
        //             buf[bytes] = 0x80;
        //             self.aes.aes4(&j, &self.i[0], &self.l[0], &buf.clone(), &mut buf);
        //             xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
        //         }
        //         x += 1;
        //     }
        // }

        memwipe(&mut i);
        //memwipe(&mut j);
        result.clone_from_slice(&sum);
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
    
    fn get_test_data(filename: String) -> String {
        let extract_tests_path = get_test_file_path(filename);
        let mut f = File::open(extract_tests_path).unwrap();
        let mut contents = String::new();
        f.read_to_string(&mut contents).unwrap();
        contents
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct ExtractTestCase {
        a: String,
        b: String,
    }

    #[test]
    fn test_extract() {
        let cases_str = get_test_data("extract.json".to_string());
        let cases: Vec<ExtractTestCase> = serde_json::from_str(&cases_str).unwrap();
        for case in cases {
            let a = case.a.from_hex().unwrap();
            let b = case.b.from_hex().unwrap();
            let mut extracted_key = [0u8; EXTRACTED_KEY_SIZE];
            extract(&a, &mut extracted_key);
            assert_eq!(&b, &extracted_key.to_vec());
        }
    }

    #[test]
    fn test_xor_block() {
        let mut src = [0u8; BLOCK_SIZE];
        let mut dst = [0u8; BLOCK_SIZE];
        src.clone_from_slice(&"b17167cf7aedba2711ef1d67a7b796fd".from_hex().unwrap());
        xor_bytes_1x16(&dst.clone(), &src, &mut dst);
        println!("xor dst is {}", dst.to_hex());
    }

    #[test]
    fn test_double_block() {
        let mut src = [0u8; BLOCK_SIZE];
        src.clone_from_slice(&"b17167cf7aedba2711ef1d67a7b796fd".from_hex().unwrap());
        double_block(&mut src);
        println!("double block is src {}", src.to_hex());
    }
    
    #[test]
    fn test_mult_block() {
        let mut src = [0u8; BLOCK_SIZE];
        let mut dst = [0u8; BLOCK_SIZE];
        src.clone_from_slice(&"b17167cf7aedba2711ef1d67a7b796fd".from_hex().unwrap());
        mult_block(2, &src, &mut dst);
        println!("output of mult_block 2 {} is {}", src.to_hex(), dst.to_hex());
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct HashVector {
        k: String,
        tau: u32,
        data: Vec<String>,
        v: String,
    }    
    
    #[test]
    fn test_aez_hash() {
        let cases_str = get_test_data("hash.json".to_string());
        let cases: Vec<HashVector> = serde_json::from_str(&cases_str).unwrap();
        for case in cases {
            let k = case.k.from_hex().unwrap();
            let mut data: Vec<Vec<u8>> = vec![];
            for v in case.data {
                let d = v.from_hex().unwrap();
                data.push(d);
            }

            let mut nonce = vec![];
            let mut ad: Vec<Vec<u8>> = vec![];
            let v = case.v.from_hex().unwrap();
            if data.len() > 0 {
                nonce = vec![0u8; data[0].len()];
                nonce.clone_from_slice(&data[0]);
                if data.len() > 1 {
                    ad = vec![vec![]; data[1..].len()];
                    ad.clone_from_slice(&data[1..]);
                }
            }

            let mut result = [0u8; BLOCK_SIZE];

            let mut e = EState::new(&k);
            e.aez_hash(&nonce, Some(&ad), case.tau, &mut result);
        }
    }

    //#[test]
    fn test_estate_new() {
        let k = vec![1,2,3];
        let e = EState::new(&k);
        println!("i 0 {} i 1 {}", e.i[0].to_hex(), e.i[1].to_hex());
        println!("j 0 {} j 1 {} j 2 {}", e.j[0].to_hex(), e.j[1].to_hex(), e.j[2].to_hex());

        for v in e.l.iter() {
            println!("v {}", v.to_hex());
        }
    }
}
