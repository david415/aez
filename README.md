
# aez
[![](https://travis-ci.org/david415/aez.png?branch=master)](https://www.travis-ci.org/david415/aez) [![](https://img.shields.io/crates/v/aez.svg)](https://crates.io/crates/aez) [![](https://docs.rs/aez/badge.svg)](https://docs.rs/aez/)

This crate provides a rust wrapper around Yawning's AEZ which is
implemented in AMD64 assembler.


# status

This is a work-in-progress and is NOT ready for use.


# building

You can see the assembler is in a python script called 'artifacts/aez_amd64.py'.
That is to say, the assembler is written using a python library called peachpy
which is capable of outputing various binary formats.

https://github.com/Maratyszcza/PeachPy

Using peachpy we build our static object file like this:

python -m peachpy.x86_64 -mabi=sysv -mimage-format=elf -o libaez.a aez_amd64.py


# acknowledgments

Thanks to Yawning Angel for the AMD64 assembler AEZ implementation. This library is
a Rust wrapper around Yawning Angel's AMD64 assembler AEZ implementation
which you can find here:

https://git.schwanenlied.me/yawning/aez.git


# license

The license file has been included in the root directory of this crate
and is entitled **LICENSE_AGPL**, the GNU AFFERO GENERAL PUBLIC LICENSE.

HOWEVER, everything under the 'artifacts' subdirectory was written by
Yawning Angel and is thus licensed using CC0 1.0 Universal, the which
is included in teh root directory of this crate and is entitled
**LICENSE_CC0**.