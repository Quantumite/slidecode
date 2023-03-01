# Slidecode Assembly

## Assemble Instructions
- `nasm -o shellcode_header.bin header.asm`
- `nasm -o shellcode_header64.bin header64.asm`

## Description
- This is the assembly code for the shellcode_header.bin and shellcode_header64.bin binary code included in the slidecode python package.
- Supports 32-bit and 64-bit Intel architecture shellcode
- NULL-free