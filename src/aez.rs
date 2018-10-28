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
                       xor_bytes_1x16_amd64_sse2,
                       xor_bytes_4x16_amd64_sse2,
                       cpuid_amd64, reset_amd64_sse2,
                       aez_aes_4_amd64_aesni,
                       aez_aes_10_amd64_aesni,
                       aez_core_pass_1_amd64_aesni,
                       aez_core_pass_2_amd64_aesni};
use super::errors::AezDecryptError;

const ZERO_BLOCK: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];



pub fn xor_bytes_1x16(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE], dst: &mut [u8; BLOCK_SIZE]) {
    xor_bytes_1x16_amd64_sse2(a, b, dst);
}

pub fn xor_bytes_4x16(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE], c: &[u8; BLOCK_SIZE], d: &[u8; BLOCK_SIZE], dst: &mut [u8; BLOCK_SIZE]) {
    xor_bytes_4x16_amd64_sse2(a, b, c, d, dst);
}

pub fn supports_aesni() -> bool {
    let aesni_bit = 1 << 25;

    // Check for AES-NI support.
    // CPUID.(EAX=01H, ECX=0H):ECX.AESNI[bit 25]==1
    let mut regs = vec![1u32; 4];
    cpuid_amd64(&mut regs[0]);
    regs[2] & aesni_bit != 0
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

    pub fn aes4(&self, j: &[u8], i: &[u8], l: &[u8], src: &[u8], dst: &mut [u8]) {
        aez_aes_4_amd64_aesni(j, i, l, &self.keys, src, dst);
    }

    pub fn aes10(&self, l: &[u8], src: &[u8], dst: &mut [u8]) {
        aez_aes_10_amd64_aesni(l, &self.keys, src, dst);
    }
}

pub fn memwipe(val: &mut [u8]) {
    let zeros = vec![0u8; val.len()];
    unsafe {
        ptr::copy_nonoverlapping(&zeros[0] as *const u8, &mut val[0] as *mut u8, val.len());
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
        //self.aes.aes4(&j, &self.i[1], &self.l[1], &buf, &mut sum);

        // Hash nonce, accumulate into sum
        let mut n_bytes = nonce.len() as u32;
        i.clone_from_slice(&self.i[1]);
        let mut n = nonce;
        let mut x = 0;
        while n_bytes >= BLOCK_SIZE as u32 {
            //self.aes.aes4(&self.j[2], &i, &self.l[x%8], &n[..BLOCK_SIZE], &mut buf);
            //xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
            n = &n[BLOCK_SIZE..];
            if x % 8 == 0 {
                double_block(&mut i);
            }
            n_bytes = n_bytes - BLOCK_SIZE as u32;
            x = x + 1;
        }
        if n_bytes > 0 || nonce.len() == 0 {
            //memwipe(&mut buf);
            buf = [0u8; BLOCK_SIZE];
            buf.clone_from_slice(&n);
            buf[n_bytes as usize] = 0x80;
            //self.aes.aes4(&self.j[2], &self.i[0], &self.l[0], &buf.clone(), &mut buf);
            //xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
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
                    //self.aes.aes4(&j, &i, &self.l[y%8], &p[..BLOCK_SIZE], &mut buf); // E(5+k,i)
                    //xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
                    p = p[BLOCK_SIZE..].to_vec();
                    if y % 8 == 0 {
                        double_block(&mut i);
                    }
                    y = y+1;
                    bytes = bytes - BLOCK_SIZE;
                }
                if bytes > 0 || is_empty {
                    //memwipe(&mut buf);
                    buf.clone_from_slice(&p);
                    buf[bytes] = 0x80;
                    //self.aes.aes4(&j, &self.i[0], &self.l[0], &buf.clone(), &mut buf);
                    //xor_bytes_1x16(&sum.clone(), &buf, &mut sum);
                }
                x += 1;
            }
        }

        //memwipe(&mut i);
        //memwipe(&mut j);
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

    pub fn aez_core(&self, delta: &[u8; BLOCK_SIZE], src: &[u8], d: u32, dst: &mut [u8]) {
        let mut tmp = [0u8; BLOCK_SIZE];
        let mut x = [0u8; BLOCK_SIZE];
        let mut y = [0u8; BLOCK_SIZE];
        let mut s = [0u8; BLOCK_SIZE];
        let dst_len = dst.len();
        let mut dst_orig = vec![0u8; dst_len];
        dst_orig.clone_from_slice(&dst);
        let mut src_orig = vec![0u8; src.len()];
        src_orig.clone_from_slice(&src);

        let mut frag_bytes = src.len() % 32;
        let initial_bytes = src.len() - frag_bytes - 32;

        // Compute X and store intermediate results
	// Pass 1 over in[0:-32], store intermediate values in out[0:-32]
        if src.len() >= 64 {
            self.aez_core_pass1(src, dst, &x, initial_bytes);
        }

        // Finish X calculation
        let mut _src = vec![0u8; src[initial_bytes..].len()];
        _src.clone_from_slice(&src[initial_bytes..]);
        let mut src_c = vec![0u8; src.len()];
        src_c.clone_from_slice(&_src);
        if frag_bytes >= BLOCK_SIZE {
            self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[4], &src_c[..BLOCK_SIZE], &mut tmp);
            xor_bytes_1x16(&x.clone(), &tmp, &mut x);
            one_zero_pad(&src_c[BLOCK_SIZE..], frag_bytes-BLOCK_SIZE, &mut tmp);
            self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[5], &tmp.clone(), &mut tmp);
            xor_bytes_1x16(&x.clone(), &tmp, &mut x);
        } else {
            one_zero_pad(&src_c, frag_bytes, &mut tmp);
            &self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[4], &tmp.clone(), &mut tmp);
            xor_bytes_1x16(&x.clone(), &tmp, &mut x);
        }

        // Calculate S
        dst.clone_from_slice(&dst_orig[src_orig.len()-32..]);
        src_c.clone_from_slice(&src_orig[src_orig.len()-32..]);
        self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[(1+d as usize)%8], &src_c[BLOCK_SIZE..2*BLOCK_SIZE], &mut tmp);
        let mut out_block = [0u8; BLOCK_SIZE];
        out_block.clone_from_slice(&dst[..BLOCK_SIZE]);
        let mut in_block = [0u8; BLOCK_SIZE];
        in_block.clone_from_slice(&src_c[..BLOCK_SIZE]);
        xor_bytes_4x16(&x, &in_block, &delta, &tmp, &mut out_block);
	// XXX/performance: Early abort if tag is corrupted.

	// Pass 2 over intermediate values in out[32..]. Final values written
        dst.clone_from_slice(&dst_orig);
        let mut dst_buf = vec![0u8; dst.len()];
        dst_buf.clone_from_slice(&dst);
        if src_c.len() >= 64 {
            self.aez_core_pass2(&src_c, &mut dst_buf, &y, &s, initial_bytes);
        }

        // Finish Y calculation and finish encryption of fragment bytes
        let mut new_dst = vec![0u8; dst[initial_bytes..].len()];
        new_dst.clone_from_slice(&dst[initial_bytes..]);
        dst.clone_from_slice(&new_dst);
        let mut new_src = vec![0u8; src_c[initial_bytes..].len()];
        new_src.clone_from_slice(&src_c[initial_bytes..]);
        src_c.clone_from_slice(&new_src);

        if frag_bytes >= BLOCK_SIZE {
            self.aes.aes10(&self.l[4], &s, &mut tmp); // E(-1,4)
            let mut dst_block = [0u8; BLOCK_SIZE];
            let mut src_block = [0u8; BLOCK_SIZE];
            src_block.clone_from_slice(&src_c);
            xor_bytes_1x16(&src_block, &tmp, &mut dst_block);
            dst[..BLOCK_SIZE].clone_from_slice(&dst_block);
            self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[4], &dst[..BLOCK_SIZE], &mut tmp);
            let mut src_y = [0u8; BLOCK_SIZE];
            src_y.clone_from_slice(&y);
            xor_bytes_1x16(&src_y, &tmp, &mut y);

            let mut dst_block = [0u8; BLOCK_SIZE];
            dst_block.clone_from_slice(&dst[BLOCK_SIZE..]);
            dst.clone_from_slice(&dst_block);
            let mut src_block = [0u8; BLOCK_SIZE];
            src_block.clone_from_slice(&src_c[BLOCK_SIZE..]);
            src_c.clone_from_slice(&src_block);
            frag_bytes -= BLOCK_SIZE;

            self.aes.aes10(&self.l[5], &s, &mut tmp);
            xor_bytes(&src_c, &tmp.clone(), &mut tmp[..frag_bytes]);
            dst.clone_from_slice(&tmp[..frag_bytes]);
            memwipe(&mut tmp[frag_bytes..]);
            tmp[frag_bytes] = 0x80;
            self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[5], &tmp.clone(), &mut tmp);
            xor_bytes_1x16(&y.clone(), &tmp, &mut y);
        } else if frag_bytes > 0 {
            self.aes.aes10(&self.l[4], &s, &mut tmp); // E(-1,4)
            xor_bytes(&src_c, &tmp.clone(), &mut tmp[..frag_bytes]);
            dst.clone_from_slice(&tmp[..frag_bytes]);
            memwipe(&mut tmp[frag_bytes..]);
            tmp[frag_bytes] = 0x80;
            self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[4], &tmp.clone(), &mut tmp); // E(0,4)
            xor_bytes_1x16(&y.clone(), &tmp, &mut y);
        }

        // Finish encryption of last two blocks
        dst.clone_from_slice(&dst_orig[src_orig.len()-32..]);
        self.aes.aes10(&self.l[(2-d as usize)%8], &dst[BLOCK_SIZE..], &mut tmp);
        let mut dst_block = [0u8; BLOCK_SIZE];
        let mut ma_dst = [0u8; BLOCK_SIZE];
        ma_dst.clone_from_slice(&dst);
        xor_bytes_1x16(&ma_dst, &tmp, &mut dst_block);
        dst[..BLOCK_SIZE].clone_from_slice(&dst_block);
        self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[(2-d as usize) % 8], &dst[..BLOCK_SIZE], &mut tmp); // E(0,2-d)
        let mut dst_block = [0u8; BLOCK_SIZE];
        xor_bytes_4x16(&tmp, &dst_block.clone(), &delta, &y, &mut dst_block);
        dst[BLOCK_SIZE..].clone_from_slice(&dst_block);
        tmp.clone_from_slice(&dst[..BLOCK_SIZE]);
        dst_block.clone_from_slice(&dst[BLOCK_SIZE..]);
        dst[..BLOCK_SIZE].clone_from_slice(&dst_block);
        dst[BLOCK_SIZE..].clone_from_slice(&tmp);

        memwipe(&mut x);
        memwipe(&mut y);
        memwipe(&mut s);
    }

    pub fn aez_tiny(&self, delta: &[u8; BLOCK_SIZE], src: &[u8], d: u32, dst: &mut [u8]) {
        let mut rounds: u32 = 0;
        let mut i: u32 = 0;
        let mut j: u32 = 0;
        let mut l = [0u8; BLOCK_SIZE];
        let mut r = [0u8; BLOCK_SIZE];
        let mut step: i8 = 0;
        let mut mask = 0x00;
        let mut pad = 0x80;
        let mut tmp = [0u8; BLOCK_SIZE*2];
        let mut buf = [0u8; BLOCK_SIZE*2];

        let mut i = 7;
        let src_bytes = src.len();
        if src_bytes == 1 {
            rounds = 24;
        } else if src_bytes == 2 {
            rounds = 16;
        } else if src_bytes < 16 {
            rounds = 10;
        } else {
            i = 6;
            rounds = 8;
        }

        // Split (inbytes*8)/2 bits into L and R. Beware: May end in nibble.
        l.clone_from_slice(&src[..(src_bytes+1)/2]);
        r.clone_from_slice(&src[src_bytes/2..src_bytes/2+(src_bytes+1)/2]);
        if src_bytes&1 != 0 {
            let mut k = 0;
            while k < src_bytes/2 {
                r[k] = (r[k] << 4) | (r[k+1] >> 4);
                k += 1;
            }
            r[src_bytes/2] = r[src_bytes/2] << 4;
            pad = 0x08;
            mask = 0xf0;
        }
        if d != 0 {
            if src_bytes < 16 {
                memwipe(&mut buf[..BLOCK_SIZE]);
                buf.clone_from_slice(&src);
                buf[0] |= 0x80;
                let mut dst_block = [0u8; BLOCK_SIZE];
                let mut buf_block = [0u8; BLOCK_SIZE];
                buf_block.clone_from_slice(&buf[..BLOCK_SIZE]);
                xor_bytes_1x16(&delta, &buf_block, &mut dst_block);
                buf[..BLOCK_SIZE].clone_from_slice(&dst_block);
                self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[3], &buf[..BLOCK_SIZE], &mut tmp); // E(0,3)
                l[0] ^= (tmp[0] & 0x80);
            }
            j = rounds - 1;
            step = -1;
        } else {
            step = 1;
        }
        let mut k: u32 = 0;
        while k < rounds/2 {
            memwipe(&mut buf[..BLOCK_SIZE]);
            buf.clone_from_slice(&r[..(src_bytes+1)/2]);
            buf[src_bytes/2] = (buf[src_bytes/2] & mask) | pad;
            let mut buf_block = [0u8; BLOCK_SIZE];
            let mut buf_clone = [0u8; BLOCK_SIZE];
            buf_clone.clone_from_slice(&buf);
            xor_bytes_1x16(&buf_clone, &delta, &mut buf_block);
            buf.clone_from_slice(&buf_block);
            buf[15] ^= j as u8;
            let mut l_block = [0u8; BLOCK_SIZE];
            let mut tmp_block = [0u8; BLOCK_SIZE];
            tmp_block.clone_from_slice(&tmp);
            let mut l_clone = [0u8; BLOCK_SIZE];
            l_clone.clone_from_slice(&l);
            xor_bytes_1x16(&l_clone, &tmp_block, &mut l_block);
            l[..BLOCK_SIZE].clone_from_slice(&l_block);

            memwipe(&mut buf[..BLOCK_SIZE]);
            buf.clone_from_slice(&l[..(src_bytes+1)/2]);
            buf[src_bytes/2] = (buf[src_bytes/2] & mask) | pad;
            let mut buf_block = [0u8; BLOCK_SIZE];
            buf_clone.clone_from_slice(&buf);
            xor_bytes_1x16(&buf_clone, &delta, &mut buf_block);
            buf[..BLOCK_SIZE].clone_from_slice(&buf_block);
            buf[15] ^= j as u8 + step as u8;
            self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[i], &buf[..BLOCK_SIZE], &mut tmp); // E(0,i)
            let mut r_block = [0u8; BLOCK_SIZE];
            tmp_block.clone_from_slice(&tmp);
            xor_bytes_1x16(&r, &tmp_block, &mut r_block);
            r[..BLOCK_SIZE].clone_from_slice(&r_block);
            j = j+2*step as u32;
            k += 1;
        }
        buf.clone_from_slice(&r[..src_bytes/2]);
        buf[src_bytes/2..].clone_from_slice(&l[..(src_bytes+1)/2]);
        if src_bytes&1 != 0 {
            let mut k = src_bytes - 1;
            while k > src_bytes/2 {
                buf[k] = (buf[k] >> 4) | (buf[k-1] << 4);
                k -= 1;
            }
            buf[src_bytes/2] = (l[0] >> 4) | (r[src_bytes/2] & 0xf0);
        }
        dst.clone_from_slice(&buf[..src_bytes]);
        if src_bytes < 16 && d == 0 {
            memwipe(&mut buf[src_bytes..BLOCK_SIZE]);
            buf[0] |= 0x80;
            let mut buf_block = [0u8; BLOCK_SIZE];
            let mut buf_clone = [0u8; BLOCK_SIZE];
            buf_clone.clone_from_slice(&buf);
            xor_bytes_1x16(&delta, &buf_clone, &mut buf_block);
            buf[..BLOCK_SIZE].clone_from_slice(&buf_block);
            self.aes.aes4(&ZERO_BLOCK, &self.i[1], &self.l[3], &buf[..BLOCK_SIZE], &mut tmp);
            dst[0] ^= tmp[0] & 0x80;
        }
        memwipe(&mut tmp);
    }

    fn encipher(&self, delta: &[u8; BLOCK_SIZE], src: &[u8], dst: &mut [u8]) {
        if src.len() == 0 {
            return
        }

        if src.len() < 32 {
            self.aez_tiny(delta, src, 0, dst);
        } else {
            self.aez_core(delta, src, 0, dst);
        }
    }

    fn decipher(&self, delta: &[u8; BLOCK_SIZE], src: &[u8], dst: &mut [u8]) {
        if src.len() == 0 {
            return
        }

        if src.len() < 32 {
            self.aez_tiny(delta, src, 1, dst);
        } else {
            self.aez_core(delta, src, 1, dst);
        }
    }
}


// Encrypt encrypts and authenticates the plaintext, authenticates the
// additional data, and appends the result to ciphertext, returning the
// updated slice.  The length of the authentication tag in bytes is specified
// by tau.  The plaintext and dst slices MUST NOT overlap.
pub fn encrypt(key: &[u8], nonce: &[u8], additional_data: Option<&Vec<Vec<u8>>>, tau: usize, plaintext: &[u8], dst: &mut [u8]) -> Vec<u8> {
    let mut delta = [0u8; BLOCK_SIZE];
    let mut x: Vec<u8> = Vec::new();
    let dst_sz = dst.len();
    let x_sz = plaintext.len() + tau;
    if dst.len() >= dst_sz + x_sz {
        let mut slice = vec![0u8; dst_sz + x_sz];
        slice.clone_from_slice(&dst[..dst_sz + x_sz]);
        dst.clone_from_slice(&slice);
    } else {
        x = vec![0u8; dst.len()];
        x.clone_from_slice(&dst);
        dst.clone_from_slice(&x);
    }
    x = vec![0u8; dst[dst_sz..].len()];
    x.clone_from_slice(&dst[dst_sz..]);

    let mut e = EState::new(&key);
    e.aez_hash(&nonce, additional_data, tau as u32 *8, &mut delta);
    if plaintext.len() == 0 {
        e.aez_prf(&delta, tau, &mut x);
    } else {
        memwipe(&mut x[plaintext.len()..]);
        x = vec![0u8; plaintext.len()];
        x.clone_from_slice(&plaintext);
        let mut src_x = vec![0u8; x.len()];
        src_x.clone_from_slice(&x);
        e.encipher(&delta, &src_x, &mut x);
    }
    e.reset();
    dst.to_vec()
}

// Decrypt decrypts and authenticates the ciphertext, authenticates the
// additional data, and if successful appends the resulting plaintext to the
// provided slice and returns the updated slice and true.  The length of the
// expected authentication tag in bytes is specified by tau.  The ciphertext
// and dst slices MUST NOT overlap.
pub fn decrypt(key: &[u8], nonce: &[u8], additional_data: Option<&Vec<Vec<u8>>>, tau: usize, ciphertext: &[u8], dst: &mut [u8]) -> Result<Vec<u8>, AezDecryptError> {
    if ciphertext.len() < tau {
        return Err(AezDecryptError::ShortCiphertext);
    }

    let mut delta = [0u8; BLOCK_SIZE];
    let mut sum: u8 = 0;
    let mut x = vec![];
    let dst_sz = dst.len();
    let x_sz = ciphertext.len();

    if dst.len() >= dst_sz + x_sz {
        let mut slice = vec![0u8; dst_sz + x_sz];
        slice.clone_from_slice(&dst[..dst_sz + x_sz]);
        dst.clone_from_slice(&slice);
    } else {
        x = vec![0u8; dst_sz + x_sz];
        x.clone_from_slice(&dst);
        dst.clone_from_slice(&x);
    }
    x.clone_from_slice(&dst[dst_sz..]);

    let mut e = EState::new(&key);
    e.aez_hash(&nonce, additional_data, tau as u32 *8, &mut delta);
    if ciphertext.len() == tau {
        e.aez_prf(&delta, tau, &mut x);
        let mut i = 0;
        while i < tau {
            sum |= x[i] ^ ciphertext[i];
            i += 1;
        }
        x = vec![0u8; dst_sz];
        x.clone_from_slice(&dst);
        dst.clone_from_slice(&x);
    } else {
        e.decipher(&delta, &ciphertext, &mut x);
    }
    if sum != 0 {
        return Err(AezDecryptError::InvalidCiphertext);
    }
    e.reset();
    Ok(dst.to_vec())
}


#[cfg(test)]
mod tests {
    extern crate rustc_serialize;
    extern crate rand;

    use super::*;
    use self::rustc_serialize::hex::ToHex;
    use self::rand::Rng;
    use self::rand::os::OsRng;

    fn os_rng() -> OsRng {
        OsRng::new().expect("failure to create an OS RNG")
    }

    //#[test]
    fn test_memwipe() {
        let mut fu = vec![0x3u8; 20];
        let zeros = vec![0u8; 20];
        memwipe(&mut fu);
        assert_eq!(zeros, fu);
    }

    //#[test]
    fn test_encrypt_decrypt() {
        let mut rng = os_rng();
        let mut key = [0u8; 384];
        rng.fill_bytes(&mut key);
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let tau = 16; // XXX
        const TEST_PLAINTEXT: &'static [u8] = b"Hello there world, I'm just a test string";
        let plaintext: Vec<u8> = TEST_PLAINTEXT.to_owned();
        let mut dst = vec![0u8; plaintext.len()];
        let _dst = encrypt(&key, &nonce, None, tau, &plaintext, &mut dst);
    }

    //#[test]
    fn test_aez_hash() {
        let mut rng = os_rng();
        let mut key = [0u8; 384];
        rng.fill_bytes(&mut key);
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let mut e = EState::new(&key);
        let tau = 16; // XXX
        let mut delta = [0u8; BLOCK_SIZE];
        e.aez_hash(&nonce, None, tau as u32 *8, &mut delta);
    }

    #[test]
    fn test_round_aesni_aes4_wtf() {
        //let j = vec![1u8; BLOCK_SIZE];
        let mut j = [0u8; BLOCK_SIZE];
        let i = vec![0xFFu8; BLOCK_SIZE];
        let l = vec![1u8; BLOCK_SIZE];
        let what_the_fuck = 0;
        //let apple = 1;
        //let i: [[u8; 16]; 2] = [[0u8; 16]; 2];
        //let l: [[u8; 16]; 8] = [[0u8; 16]; 8];
        let src = vec![0xAAu8; BLOCK_SIZE];
        let mut dst = vec![0u8; BLOCK_SIZE];
        let mut rng = os_rng();
        let mut key = [0u8; EXTRACTED_KEY_SIZE];
        rng.fill_bytes(&mut key);

        let mut round_aesni = RoundAesni::new(key);
        round_aesni.aes4(&j, &i, &l, &src, &mut dst);
        //round_aesni.aes4(&j, &i[1], &l[1], &src, &mut dst);
        round_aesni.reset();
    }
    
    //#[test]
    fn test_round_aesni_aes4() {
        let mut rng = os_rng();
        let mut key = [0u8; EXTRACTED_KEY_SIZE];
        rng.fill_bytes(&mut key);
        let mut round_aesni = RoundAesni::new(key);
        let mut buf = [0u8; BLOCK_SIZE];
        let mut sum = [0u8; BLOCK_SIZE];
        let mut block_j = [0u8; BLOCK_SIZE];
        let i: [[u8; 16]; 2] = [[0u8; 16]; 2];
        let l: [[u8; 16]; 8] = [[0u8; 16]; 8];
        let tau = 16;
        BigEndian::write_u32(&mut buf[12..], tau);
        //round_aesni.aes4(&block_j, &i[1], &l[1], &buf, &mut sum);        
        round_aesni.reset();
    }
}
