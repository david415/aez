// error.rs - AEZ error types
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

//! AEZ error types.

use std::error::Error;
use std::fmt;


#[derive(Debug)]
pub enum AezDecryptionError {
    DecryptionError,
}

impl fmt::Display for AezDecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::AezDecryptionError::*;
        match *self {
            DecryptionError => write!(f, "Decryption error."),
        }
    }
}

impl Error for AezDecryptionError {
    fn description(&self) -> &str {
        "I'm a AezDecryptionError."
    }

    fn cause(&self) -> Option<&Error> {
        use self::AezDecryptionError::*;
        match *self {
            DecryptionError => None,
        }
    }
}
