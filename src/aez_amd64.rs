// aez_asm.rs - The rust wrapper around AMD64 assembler AEZ helper functions.
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

pub const BLOCK_SIZE: usize = 16;
pub const EXTRACTED_KEY_SIZE: usize = 3 * 16;

pub const DBL_CONSTS: [u8; 32] = [
        // PSHUFB constant
	0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,

	// Mask constant
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x87, 0x00, 0x00, 0x00,
];

extern "C" {
    fn cpuidAMD64(cpu_params: *const u32);
    fn resetAMD64SSE2();
    fn xorBytes1x16AMD64SSE2(a: *const u8, b: *const u8, dst: *mut u8);
    fn xorBytes4x16AMD64SSE2(a: *const u8, b: *const u8, c: *const u8, d: *const u8, dst: *mut u8);
    fn aezAES4AMD64AESNI(j: *const u8, i: *const u8, l: *const u8, k: *const u8, src: *const u8, dst: *mut u8);
    fn aezAES10AMD64AESNI(l: *const u8, k: *const u8, src: *const u8, dst: *mut u8);
    fn aezCorePass1AMD64AESNI(src: *const u8, dst: *mut u8, x: *const u8, i: *const u8, l: *const u8, k: *const u8, consts: *const u8, sz: c_int);
    fn aezCorePass2AMD64AESNI(dst: *mut u8,  y: *const u8, s: *const u8, j: *const u8, i: *const u8, l: *const u8, k: *const u8, consts: *const u8, sz: c_int);
}

pub fn reset_amd64_sse2() {
    unsafe {
        resetAMD64SSE2();
    }
}

pub fn cpuid_amd64(cpu_params: &u32) {
    unsafe {
        cpuidAMD64(cpu_params as *const u32);
    }
}

pub fn xor_bytes_1x16_amd64_sse2(a: Vec<u8>, b: Vec<u8>, dst: &mut Vec<u8>) {
    unsafe {
        xorBytes1x16AMD64SSE2(&a[0] as *const u8, &b[0] as *const u8, &mut dst[0] as *mut u8);
    }
}

pub fn xor_bytes_4x16_amd64_sse2(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE], c: &[u8; BLOCK_SIZE], d: &[u8; BLOCK_SIZE], dst: &mut [u8; BLOCK_SIZE]) {
    unsafe {
        xorBytes4x16AMD64SSE2(&a[0] as *const u8, &b[0] as *const u8, &c[0] as *const u8, &d[0] as *const u8, &mut dst[0] as *mut u8);
    }
}

pub fn aez_aes_4_amd64_aesni(j: &[u8], i: &[u8], l: &[u8], k: &[u8], src: &[u8], dst: &mut [u8]) {
    unsafe {
        aezAES4AMD64AESNI(&j[0] as *const u8,
                          &i[0] as *const u8,
                          &l[0] as *const u8,
                          &k[0] as *const u8,
                          &src[0] as *const u8,
                          &mut dst[0] as *mut u8);
    }
}

pub fn aez_aes_10_amd64_aesni(l: &[u8], k: &[u8], src: &[u8], dst: &mut[u8]) {
    unsafe {
        aezAES10AMD64AESNI(&l[0] as *const u8, &k[0] as *const u8, &src[0] as *const u8, &mut dst[0] as *mut u8);
    }
}

pub fn aez_core_pass_1_amd64_aesni(src: &[u8], dst: &mut [u8], x: &[u8], i: &[u8], l: &[u8], k: &[u8], consts: &[u8], sz: usize) {
    unsafe {
        aezCorePass1AMD64AESNI(&src[0] as *const u8,
                               &mut dst[0] as *mut u8,
                               &x[0] as *const u8,
                               &i[0] as *const u8,
                               &l[0] as *const u8,
                               &k[0] as *const u8,
                               &consts[0] as *const u8,
                               sz as c_int);
    }
}

pub fn aez_core_pass_2_amd64_aesni(dst: &mut [u8], y: &[u8], s: &[u8], j: &[u8], i: &[u8], l: &[u8], k: &[u8], consts: &[u8], sz: usize) {
    unsafe {
        aezCorePass2AMD64AESNI(&mut dst[0] as *mut u8,
                               &y[0] as *const u8,
                               &s[0] as *const u8,
                               &j[0] as *const u8,
                               &i[0] as *const u8,
                               &l[0] as *const u8,
                               &k[0] as *const u8,
                               &consts[0] as *const u8,
                               sz as c_int);
    }
}



// #[cfg(test)]
// mod tests {
//     extern crate rustc_serialize;

//     use super::*;
//     use self::rustc_serialize::hex::ToHex;

//     #[test]
//     fn test_reset_amd64_sse2() {
//         reset_amd64_sse2();
//     }

//     #[test]
//     fn test_xor_bytes_1x16_amd64_sse2() {
//         let a = [1u8; BLOCK_SIZE];
//         let b = [0xffu8; BLOCK_SIZE];
//         let mut dst = [0u8; BLOCK_SIZE];
//         xor_bytes_1x16_amd64_sse2(&a, &b, &mut dst);
//     }

//     #[test]
//     fn test_xor_bytes_4x16_amd64_sse2() {
//         let a = [1u8; BLOCK_SIZE];
//         let b = [0xffu8; BLOCK_SIZE];
//         let c = [1u8; BLOCK_SIZE];
//         let d = [0x23u8; BLOCK_SIZE];
//         let mut dst = [0u8; BLOCK_SIZE];
//         xor_bytes_4x16_amd64_sse2(&a, &b, &c, &d, &mut dst);
//     }

    // #[test]
    // fn test_aez_aes_4_amd64_aesni() {
    //     let j = vec![1u8; BLOCK_SIZE];
    //     let i = vec![0xFFu8; BLOCK_SIZE];
    //     let l = vec![1u8; BLOCK_SIZE];
    //     let k = vec![0x13u8; BLOCK_SIZE];
    //     let src = vec![0xAAu8; BLOCK_SIZE];
    //     let mut dst = vec![0u8; BLOCK_SIZE];
    //     aez_aes_4_amd64_aesni(&j, &i, &l, &k, &src, &mut dst);
    // }

//     #[test]
//     fn test_aez_aes_10_amd64_aesni() {
//         let l = vec![1u8; BLOCK_SIZE];
//         let k = vec![0x13u8; BLOCK_SIZE];
//         let src = vec![0xAAu8; BLOCK_SIZE];
//         let mut dst = vec![0u8; BLOCK_SIZE];
//         aez_aes_10_amd64_aesni(&l, &k, &src, &mut dst);
//     }

//     #[test]
//     fn test_aez_core_pass_1_amd64_aesni() {
//         let src = [0xAAu8; BLOCK_SIZE];
//         let mut dst = [0u8; BLOCK_SIZE];
//         let x = [1u8; BLOCK_SIZE];
//         let i = [0x13u8; BLOCK_SIZE];
//         let l = [1u8; BLOCK_SIZE];
//         let k = [0x13u8; BLOCK_SIZE];
//         let consts = [1u8; BLOCK_SIZE];
//         let sz = 10;
//         aez_core_pass_1_amd64_aesni(&src, &mut dst, &x, &i, &l, &k, &consts, sz);
//     }

//     #[test]
//     fn test_aez_core_pass_2_amd64_aesni() {
//         let mut dst = [0u8; BLOCK_SIZE];
//         let y = [1u8; BLOCK_SIZE];
//         let s = [0x13u8; BLOCK_SIZE];
//         let j = [5u8; BLOCK_SIZE];
//         let i = [0x13u8; BLOCK_SIZE];
//         let l = [1u8; BLOCK_SIZE];
//         let k = [0x13u8; BLOCK_SIZE];
//         let consts = [1u8; BLOCK_SIZE];
//         let sz = 30;
//         aez_core_pass_2_amd64_aesni(&mut dst, &y, &s, &j, &i, &l, &k, &consts, sz);
//     }

//     #[test]
//     fn test_supports_aesni() {
//         assert_eq!(supports_aesni(), true);
//     }
// }
