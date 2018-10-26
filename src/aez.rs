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

use super::aez_amd64::cpuid_amd64;


pub fn supports_aesni() -> bool {
    let aesni_bit = 1 << 25;

    // Check for AES-NI support.
    // CPUID.(EAX=01H, ECX=0H):ECX.AESNI[bit 25]==1
    let mut regs = vec![1u32; 4];
    cpuid_amd64(&mut regs[0]);
    regs[2] & aesni_bit != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports_aesni() {
        assert_eq!(supports_aesni(), true);
    }
}
