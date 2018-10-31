// aez_benchmark_test.rs - aez benchmarks
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

#[macro_use]
extern crate criterion;
extern crate rand;
extern crate aez;
extern crate rustc_serialize;

use self::rustc_serialize::hex::FromHex;

use criterion::Criterion;
use aez::aez::{encrypt, decrypt, AEZ_KEY_SIZE, AEZ_NONCE_SIZE};

pub const FORWARD_PAYLOAD_SIZE: usize = 50 * 1024;


fn criterion_aez_decrypt_benchmark(c: &mut Criterion) {
    let mut payload = vec![0u8; FORWARD_PAYLOAD_SIZE];
    let s = String::from("We must defend our own privacy if we expect to have any. \
                          We must come together and create systems which allow anonymous transactions to take place. \
                          People have been defending their own privacy for centuries with whispers, darkness, envelopes, \
                          closed doors, secret handshakes, and couriers. The technologies of the past did not allow for strong \
                          privacy, but electronic technologies do.");
    let _s_len = s.len();
    let string_bytes = s.into_bytes();
    payload[.._s_len].copy_from_slice(&string_bytes);

    let key_str = "f499be9a1dd859c1471156baed30ba7b35f19abf8e94a7868410a79ce61bdb5b995bd0e69592ff677875e5d693388e3d";
    let key = key_str.from_hex().unwrap();
    let nonce_str = "facef44b512767cd889f2abea615beef";
    let nonce = nonce_str.from_hex().unwrap();    
    let mut key_array = [0u8; AEZ_KEY_SIZE];
    key_array.clone_from_slice(&key);
    let mut nonce_array = [0u8; AEZ_NONCE_SIZE];
    nonce_array.clone_from_slice(&nonce);
    let ciphertext = encrypt(&key_array, &nonce_array, &payload);

    c.bench_function("aez decrypt", move |b| b.iter(|| {
        let _plaintext = decrypt(&key_array, &nonce_array, &ciphertext);
    }));
}


criterion_group!(benches, criterion_aez_decrypt_benchmark);
criterion_main!(benches);
