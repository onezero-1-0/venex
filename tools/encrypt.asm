
; Constants for the expansion functions
section .data
	chacha20_constants_256: db 0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33
	chacha20_constants_128 db 0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B

	chacha20_key db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	chacha20_nonce db 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00

	entmsg db "Enter value: ", 0
	entmsg_len equ $ - entmsg
	
	msg times 128 db 0
	msg_len equ $ - msg

section .bss
	chacha20_state resb 64

	

section .text
	global chacha20_Full

chacha20_Full:
	;rdi is message pointer
	;r14 is length of message
	;key nouce are already setups we only need rdi and r14
	push rbp
	mov rbp,rsp

	mov rdi,rcx
	mov r14,rdx
	mov r15,r8
    mov r8,chacha20_state
    mov r9,chacha20_key
    call chacha20_init_256
    mov r8,chacha20_state
    mov r9,chacha20_nonce
    call chacha20_set_iv

    ;encrypt
    mov r8,chacha20_state
    mov r9,rdi ;message
    mov r10,r14
    mov r11,r15
    call chacha20_process
	mov rax,rdi
	leave
	ret



;==============
; ChaCha20 implementation
; Based on public domain ChaCha20 specification
chacha20_QR:
	; Step 1
	add eax, ebx
	xor edx, eax
	rol edx, 16

	; Step 2
	add ecx, edx
	xor ebx, ecx
	rol ebx, 12

	; Step 3
	add eax, ebx
	xor edx, eax
	rol edx, 8

	; Step 4
	add ecx, edx
	xor ebx, ecx
	rol ebx, 7

	ret

; Performs double round operation
; Input: rdi points to 16 dword array
; Modifies: rax, rbx, rcx, rdx, rsi
; Output: modified in-place
chacha20_DR:
	; First column
	mov eax, [rdi+4*0]
	mov ebx, [rdi+4*4]
	mov ecx, [rdi+4*8]
	mov edx, [rdi+4*12]
	call chacha20_QR
	mov [rdi+4*0], eax
	mov [rdi+4*4], ebx
	mov [rdi+4*8], ecx
	mov [rdi+4*12], edx
	
	; Second column
	mov eax, [rdi+4*1]
	mov ebx, [rdi+4*5]
	mov ecx, [rdi+4*9]
	mov edx, [rdi+4*13]
	call chacha20_QR
	mov [rdi+4*1], eax
	mov [rdi+4*5], ebx
	mov [rdi+4*9], ecx
	mov [rdi+4*13], edx
	
	; Third column
	mov eax, [rdi+4*2]
	mov ebx, [rdi+4*6]
	mov ecx, [rdi+4*10]
	mov edx, [rdi+4*14]
	call chacha20_QR
	mov [rdi+4*2], eax
	mov [rdi+4*6], ebx
	mov [rdi+4*10], ecx
	mov [rdi+4*14], edx
	
	; Fourth column
	mov eax, [rdi+4*3]
	mov ebx, [rdi+4*7]
	mov ecx, [rdi+4*11]
	mov edx, [rdi+4*15]
	call chacha20_QR
	mov [rdi+4*3], eax
	mov [rdi+4*7], ebx
	mov [rdi+4*11], ecx
	mov [rdi+4*15], edx

	; Diagonal 1
	mov eax, [rdi+4*0]
	mov ebx, [rdi+4*5]
	mov ecx, [rdi+4*10]
	mov edx, [rdi+4*15]
	call chacha20_QR
	mov [rdi+4*0], eax
	mov [rdi+4*5], ebx
	mov [rdi+4*10], ecx
	mov [rdi+4*15], edx

	; Diagonal 2
	mov eax, [rdi+4*1]
	mov ebx, [rdi+4*6]
	mov ecx, [rdi+4*11]
	mov edx, [rdi+4*12]
	call chacha20_QR
	mov [rdi+4*1], eax
	mov [rdi+4*6], ebx
	mov [rdi+4*11], ecx
	mov [rdi+4*12], edx

	; Diagonal 3
	mov eax, [rdi+4*2]
	mov ebx, [rdi+4*7]
	mov ecx, [rdi+4*8]
	mov edx, [rdi+4*13]
	call chacha20_QR
	mov [rdi+4*2], eax
	mov [rdi+4*7], ebx
	mov [rdi+4*8], ecx
	mov [rdi+4*13], edx

	; Diagonal 4
	mov eax, [rdi+4*3]
	mov ebx, [rdi+4*4]
	mov ecx, [rdi+4*9]
	mov edx, [rdi+4*14]
	call chacha20_QR
	mov [rdi+4*3], eax
	mov [rdi+4*4], ebx
	mov [rdi+4*9], ecx
	mov [rdi+4*14], edx

	ret

; ChaCha20 core hash function
; Input: rsi - source 16 dword array, rdi - destination 16 dword array
; Modifies: rax, rbx, rcx, rdx, stack
; Output: result stored in destination
chacha20_core:
	push rbp
	
	; Process rounds on output
	push rsi
	mov rbp, 10
.round_iter: 
	call chacha20_DR
	dec rbp
	jnz .round_iter
	pop rsi
	
	; Combine with original input
	mov rcx, 15
.combine_loop: 
	mov edx, [rsi+4*rcx]
	add [rdi+4*rcx], edx
	dec rcx
	jge .combine_loop
	
	pop rbp
	ret



; Expands 32-byte key into ChaCha20 state
; Input: r8 - 32-byte key, r9 - 16-byte nonce, rsi - destination
; Modifies: rdi
chacha20_expand_256:
	lea rdi, [rel chacha20_constants_256]
	
	push rax
	mov eax, [rdi+4*0]
	mov [rsi+4*0], eax
	mov eax, [rdi+4*1]
	mov [rsi+4*5], eax
	mov eax, [rdi+4*2]
	mov [rsi+4*10], eax
	mov eax, [rdi+4*3]
	mov [rsi+4*15], eax
	
	mov eax, [r8+4*0]
	mov [rsi+4*1], eax
	mov eax, [r8+4*1]
	mov [rsi+4*2], eax
	mov eax, [r8+4*2]
	mov [rsi+4*3], eax
	mov eax, [r8+4*3]
	mov [rsi+4*4], eax

	mov eax, [r8+4*4]
	mov [rsi+4*11], eax
	mov eax, [r8+4*5]
	mov [rsi+4*12], eax
	mov eax, [r8+4*6]
	mov [rsi+4*13], eax
	mov eax, [r8+4*7]
	mov [rsi+4*14], eax
	
	mov eax, [r9+4*0]
	mov [rsi+4*6], eax
	mov eax, [r9+4*1]
	mov [rsi+4*7], eax
	mov eax, [r9+4*2]
	mov [rsi+4*8], eax
	mov eax, [r9+4*3]
	mov [rsi+4*9], eax
	pop rax
	
	mov rdi, rsi
	call chacha20_core
	ret



; Expands 16-byte key into ChaCha20 state
; Input: r8 - 16-byte key, r9 - 16-byte nonce, rsi - destination
; Modifies: rdi, stack
chacha20_expand_128:
	add rsp, 64
	lea rdi, [rel chacha20_constants_128]
	
	push rax
	mov eax, [rdi+4*0]
	mov [rsi+4*0], eax
	mov eax, [rdi+4*1]
	mov [rsi+4*5], eax
	mov eax, [rdi+4*2]
	mov [rsi+4*10], eax
	mov eax, [rdi+4*3]
	mov [rsi+4*15], eax
	
	mov eax, [r8+4*0]
	mov [rsi+4*1], eax
	mov eax, [r8+4*1]
	mov [rsi+4*2], eax
	mov eax, [r8+4*2]
	mov [rsi+4*3], eax
	mov eax, [r8+4*3]
	mov [rsi+4*4], eax

	mov eax, [r8+4*0]
	mov [rsi+4*11], eax
	mov eax, [r8+4*1]
	mov [rsi+4*12], eax
	mov eax, [r8+4*2]
	mov [rsi+4*13], eax
	mov eax, [r8+4*3]
	mov [rsi+4*14], eax
	
	mov eax, [r9+4*0]
	mov [rsi+4*6], eax
	mov eax, [r9+4*1]
	mov [rsi+4*7], eax
	mov eax, [r9+4*2]
	mov [rsi+4*8], eax
	mov eax, [r9+4*3]
	mov [rsi+4*9], eax
	pop rax
	
	mov rdi, rsi
	call chacha20_core
	ret



; Initialize cipher state with 256-bit key
; Input: r8 - state pointer, r9 - key pointer (256 bits)
; Output: state initialized
chacha20_init_256:
	mov rax, r8
	
	lea rcx, [rel chacha20_constants_256]
	mov edx, [rcx+4*0]
	mov [rax+4*0], edx
	mov edx, [rcx+4*1]
	mov [rax+4*1], edx
	mov edx, [rcx+4*2]
	mov [rax+4*2], edx
	mov edx, [rcx+4*3]
	mov [rax+4*3], edx
	
	mov rcx, r9
	mov edx, [rcx+4*0]
	mov [rax+4*4], edx
	mov edx, [rcx+4*1]
	mov [rax+4*5], edx
	mov edx, [rcx+4*2]
	mov [rax+4*6], edx
	mov edx, [rcx+4*3]
	mov [rax+4*7], edx
	mov edx, [rcx+4*4]
	mov [rax+4*8], edx
	mov edx, [rcx+4*5]
	mov [rax+4*9], edx
	mov edx, [rcx+4*6]
	mov [rax+4*10], edx
	mov edx, [rcx+4*7]
	mov [rax+4*11], edx
	ret



; Initialize cipher state with 128-bit key
; Input: r8 - state pointer, r9 - key pointer (128 bits)
; Output: state initialized
chacha20_init_128:
	mov rax, r8
	
	lea rcx, [rel chacha20_constants_128]
	mov edx, [rcx+4*0]
	mov [rax+4*0], edx
	mov edx, [rcx+4*1]
	mov [rax+4*1], edx
	mov edx, [rcx+4*2]
	mov [rax+4*2], edx
	mov edx, [rcx+4*3]
	mov [rax+4*3], edx
	
	mov rcx, r9
	mov edx, [rcx+4*0]
	mov [rax+4*4], edx
	mov edx, [rcx+4*1]
	mov [rax+4*5], edx
	mov edx, [rcx+4*2]
	mov [rax+4*6], edx
	mov edx, [rcx+4*3]
	mov [rax+4*7], edx
	mov edx, [rcx+4*0]
	mov [rax+4*8], edx
	mov edx, [rcx+4*1]
	mov [rax+4*9], edx
	mov edx, [rcx+4*2]
	mov [rax+4*10], edx
	mov edx, [rcx+4*3]
	mov [rax+4*11], edx
	ret



; Set initialization vector in state
; Input: r8 - state pointer, r9 - iv pointer (min 32 bits)
; Output: state updated
chacha20_set_iv:
	mov rax, r8
	mov rdx, r9
	mov ecx, [rdx+4*0]
	mov [rax+4*12], ecx
	mov ecx, [rdx+4*1]
	mov [rax+4*13], ecx
	xor rcx,rcx
	mov [rax+4*14], ecx
	mov [rax+4*15], ecx
	ret



; Set full 64-bit initialization vector in state
; Input: r8 - state pointer, r9 - iv pointer (64 bits)
; Output: state updated
chacha20_set_iv_full:
	mov rax, r8
	mov rdx, r9
	mov ecx, [rdx+4*0]
	mov [rax+4*12], ecx
	mov ecx, [rdx+4*1]
	mov [rax+4*13], ecx
	mov ecx, [rdx+4*2]
	mov [rax+4*14], ecx
	mov ecx, [rdx+4*3]
	mov [rax+4*15], ecx
	ret



; Encrypt plaintext using ChaCha20
; Input: r8 - state, r9 - plaintext, r10 - ciphertext, r11 - data size
; Output: ciphertext written to r10
chacha20_process:
	push rbp
	mov rbp, rsp
	sub rsp, 16*4
	sub rsp, 16*4
	sub rsp, 64
	mov rax, r11
	test rax, rax
	jz complete
	push rsi
	push rdi
	push rbx
	
	; Copy state to working buffer
	mov rax, r8
	mov rbx, rbp
	sub rbx, 16*4
	mov rcx, 15
.copy_state:
	mov edx, [rax+4*rcx]
	mov [rbx+4*rcx], edx
	dec rcx
	jge .copy_state
	
	; Process data in blocks
.process_blocks:
	; Handle partial blocks
	cmp r11, 64
	jge .full_block
		mov rbx, r9
		mov rcx, r11
		dec rcx
		mov rdx, rbp
		sub rdx, (16*4)+(16*4)+64
		.partial_copy:
		mov al, byte [rbx+rcx]
		mov [rdx+rcx], al
		dec rcx
		jge .partial_copy
		mov r9, rdx
		mov rax, r10
		mov r12, rax
		mov r10, rdx
	.full_block:
	
	; Prepare working state
	mov rax, rbp
	sub rax, 16*4
	mov rbx, rbp
	sub rbx, (16*4)+(16*4)
	mov rcx, 15
.prepare_state: 
	mov edx, [rax+4*rcx]
	mov [rbx+4*rcx], edx
	dec rcx
	jge .prepare_state
	
	; Generate keystream and encrypt
	mov rsi, rbp
	sub rsi, 16*4
	mov rdi, rbp
	sub rdi, (16*4)+(16*4)
	call chacha20_core
	mov rax, r9
	mov rcx, 15
.xor_loop: 
	mov edx, [rax+4*rcx]
	xor [rdi+4*rcx], edx
	dec rcx
	jge .xor_loop
	
	; Update counter
	sub rbp, 16*4
	inc qword [rbp+4*12]
	mov rax, [rbp+4*12]
	test rax, rax
	jnz .no_carry
		inc qword [rbp+4*14]
	.no_carry:
	add rbp, 16*4
	
	; Output result
	mov rax, rbp
	sub rax, 16*4+16*4
	mov rbx, r10
	mov rcx, 15
.output_loop: 
	mov edx, [rax+4*rcx]
	mov [rbx+4*rcx], edx
	dec rcx
	jge .output_loop
	
	; Final block handling
	mov rax, r11
	cmp rax, 64
	jg .not_final
		jge .exact_block
			; Copy from temp buffer
			mov rax, r10
			mov rbx, r12
			mov rcx, r11
			dec rcx
			.final_copy: 
			mov dl, [rax+rcx]
			mov [rbx+rcx], dl
			dec rcx
			jge .final_copy
		.exact_block:
		mov rdx, r8
		sub rbp, 16*4
		mov rax, [rbp+4*12]
		mov [rdx+4*14], rax
		mov rax, [rbp+4*14]
		mov [rdx+4*15], rax
		add rbp, 16*4
		jmp cleanup_stack
	.not_final:
	
	sub r11, 64
	add r10, 64
	add r9, 64
	jmp .process_blocks
	
cleanup_stack:
	pop rbx
	pop rdi
	pop rsi
complete:
	add rsp, 64
	add rsp, 16*4
	add rsp, 16*4
	pop rbp
	ret



; Decrypt ciphertext using ChaCha20
; Input: r8 - state, r9 - ciphertext, r10 - plaintext, r11 - data size
; Output: plaintext written to r10
chacha20_decrypt_data:
	call chacha20_process
	ret