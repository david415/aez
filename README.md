
# aez
[![](https://travis-ci.org/david415/aez.png?branch=master)](https://www.travis-ci.org/david415/aez) [![](https://img.shields.io/crates/v/aez.svg)](https://crates.io/crates/aez) [![](https://docs.rs/aez/badge.svg)](https://docs.rs/aez/)


This rust crate provides a hardware accelerated AEZ wide-block cipher
library. I use Yawning's assembler source code which implements AEZ
in AMD64 AES-NI hardware accelerated assembler. Additionally the
golang components code from Yawning's AEZ implementation are also
ported here to rust.

# unsafe

Therefore this crate is a mix of safe rust code and unsafe rust code
which wraps some assembler which is most definitely unsafe.


# warning

This code has not been formally audited by a cryptographer. It
therefore should not be considered safe or correct. Use it at your own
risk!



# compatibility status

If the AMD64 AES-NI hardware acceleration capability is not present
it is possible to make the library "fallback" to a pure rust AEZ implementation.
This is the approach taken in Yawning's golang library however here I
am lazy and have done no such thing. No AES-NI? Sad panda. Too bad. :(



# status

This is a work-in-progress and is NOT ready for use.



# usage

To import `aez`, add the following to the dependencies section of
your project's `Cargo.toml`:
```toml
aez = "^0.0.0"
```
Then import the crate as:
```rust,no_run
extern crate aez;
```


# assembler?

You can see the assembler is in a python script called 'artifacts/aez_amd64.py'.
That is to say, the assembler is written using a python library called peachpy
which is capable of outputing various assembler and binary formats.

https://github.com/Maratyszcza/PeachPy

Using peachpy we build our static object file like this:
```
python -m peachpy.x86_64 -mabi=sysv -mimage-format=elf -o libaez.a aez_amd64.py
```

HOWEVER, this assumes you have peachpy properly installed; instead this rust
crates builds the library from the assembler source file. I used peachpy to
convert Yawning's original AMD64 assembler written in python 'aez_amd64.py'
and convert it into an assembler source file with C preprocessors:

```
python -m peachpy.x86_64 -mabi=sysv -S -o aez_amd64.S aez_amd64.py
```



# acknowledgments

Thanks to Yawning Angel for the AMD64 AES-NI hardware accelerated
assembler AEZ implementation. This library is a Rust wrapper around
Yawning Angel's AMD64 assembler, which you can find here:

https://git.schwanenlied.me/yawning/aez.git



# license

The license file has been included in the root directory of this crate
and is entitled **LICENSE_AGPL**, the GNU AFFERO GENERAL PUBLIC LICENSE.

HOWEVER, everything under the **aez_amd64_aesni_asm** subdirectory was written by
Yawning Angel and is thus licensed using CC0 1.0 Universal, which
is included in the root directory of this crate and is entitled
**LICENSE_CC0**.