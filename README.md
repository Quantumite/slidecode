# Slidecode README

## General Information
- Author: Austin Norby
- Date: 05/15/2022
- Python Module Name: slidecode
- Description: SlideCode is a shellcode wrapper that uses four, 4-byte (i386) or 8-byte (x86_64), keys but XOR encodes each byte with the next key. In this way, most bytes are XOR encoded multiple times. In order to use slidecode, you must provide it with binary shellcode that needs to be encoded. Slidecode will encode the original shellcode using the multiple XOR key algorithm and attach a header and trailer to the shellcode. The header and trailer, by default, are null-free, and if the encoded payload contains nulls it is possible to use one, two, three, or four different keys to remove the null bytes after encoding. This encoded shellcode can then be used as part of an exploit just like any other shellcode. Now supports 32-bit and 64-bit shellcode!
- Tested on Windows 11 with Python 3.8.5 and Windbg

## Video Link
- [Link](https://youtu.be/TqMWnprlpXo) (old)

## Installation
- Requires python to be installed
  - Tested with Python 3.8.5
- Install with pip once code is downloaded to the slidecode folder.
```sh
pip install -e ./slidecode/
```
- Run using it as a python module
```sh
python -m slidecode -h
```

## Help Menu
```sh
usage: __main__.py [-h] [--in-file IN_FILE] [--out-file OUT_FILE] [--verbose] [--keys KEYS] [--trailer TRAILER]

SlideCode is a shellcode wrapper that uses 4, 4-byte keys but XOR encodes each byte with the next key. In this way,
most bytes are XOR encoded multiple times.

optional arguments:
  -h, --help            show this help message and exit
  --in-file IN_FILE, -i IN_FILE
                        Pass in the filename of the shellcode to be encoded.
  --out-file OUT_FILE, -o OUT_FILE
                        Pass in the filename for the ouput of the encoded shellcode. Default: shellcode_output.bin
  --verbose, -v         Pass in this flag for verbose information during shellcode encoding.
  --keys KEYS, -k KEYS  Use this argument to pass in new key values. These key values should be in hexadecimal format
                        without any prefixes. i.e. -k ABCDABCD and not -k \xAB\xCD\xAB\xCD and also not -k 0xABCDABCD. Defaults: 12233445, 9944aa72, bccddeef, aaaaaaaa
  --trailer TRAILER, -t TRAILER
                        Use this flag to change the trailer that is appended to the encoded shellcode that is used by
                        the decoder. Default: aabbccdd. i.e. -t 90909090 and not -t \x90\x90\x90\x90 and also not -t
                        0x90919293.
  --64                  If you are creating a 64-bit payload, use this flag.
```

## Examples

- Use defaults with input file, shellcode.bin
```sh
python -m slidecode -i shellcode.bin
```

- Use defaults with input and output files and be verbose
```sh
python -m slidecode -v -i shellcode.bin -o encoded_shellcode.bin
```

- Wrap shellcode and modify the trailer bytes to be 0x90919091 with input file, shellcode.bin
```sh
python -m slidecode -i shellcode.bin -t 90919091
```

- Wrap shellcode and modify the trailer and XOR keys while providing input and output files while being verbose.
```sh
python -m slidecode -v --in shellcode.bin --out encoded_shellcode.bin -k aaaaaaaa,ffffffff,12121212,79797979 -t cccccccc
```

- Wrap 64-bit shellcode with input and output files
```sh
python -m slidecode --in shellcode.bin --out encoded_shellcode.bin --64
```

## Additional Resources
- [Online Assembler/Disassembler](https://defuse.ca/online-x86-assembler.htm)
- [Windbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windows-debugging)
