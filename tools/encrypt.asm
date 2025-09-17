
; Constants for the expansion functions
section .data
	chacha20_sigma: db 0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33
	chacha20_tau db 0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B

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
    call chacha20_setupkey32
    mov r8,chacha20_state
    mov r9,chacha20_nonce
    call chacha20_setupiv

    ;encrypt
    mov r8,chacha20_state
    mov r9,rdi ;message
    mov r10,r14
    mov r11,r15
    call chacha20_encrypt
	mov rax,rdi
	leave
	ret


chacha20_QuarterRound:
	; z1
	add eax, ebx
	xor edx, eax
	rol edx, 16

	; z2
	add ecx, edx
	xor ebx, ecx
	rol ebx, 12

	; z3
	add eax, ebx
	xor edx, eax
	rol edx, 8

	; z0
	add ecx, edx
	xor ebx, ecx
	rol ebx, 7

	ret

; This function performs the doubleround function
; It assumes that rdi points to the start of an array of 16 input dwords
; This function modifies rax, rbx, rcx, rdx, rsi
; The results are stored in-place
chacha20_DoubleRound:
	; z0, z4, z8, z12
	mov eax, [rdi+4*0]
	mov ebx, [rdi+4*4]
	mov ecx, [rdi+4*8]
	mov edx, [rdi+4*12]
	call chacha20_QuarterRound
	mov [rdi+4*0], eax
	mov [rdi+4*4], ebx
	mov [rdi+4*8], ecx
	mov [rdi+4*12], edx
	
	; z1, z5, z9, z13
	mov eax, [rdi+4*1]
	mov ebx, [rdi+4*5]
	mov ecx, [rdi+4*9]
	mov edx, [rdi+4*13]
	call chacha20_QuarterRound
	mov [rdi+4*1], eax
	mov [rdi+4*5], ebx
	mov [rdi+4*9], ecx
	mov [rdi+4*13], edx
	
	; z2, z6, z10, z14
	mov eax, [rdi+4*2]
	mov ebx, [rdi+4*6]
	mov ecx, [rdi+4*10]
	mov edx, [rdi+4*14]
	call chacha20_QuarterRound
	mov [rdi+4*2], eax
	mov [rdi+4*6], ebx
	mov [rdi+4*10], ecx
	mov [rdi+4*14], edx
	
	; z3, z7, z11, z15
	mov eax, [rdi+4*3]
	mov ebx, [rdi+4*7]
	mov ecx, [rdi+4*11]
	mov edx, [rdi+4*15]
	call chacha20_QuarterRound
	mov [rdi+4*3], eax
	mov [rdi+4*7], ebx
	mov [rdi+4*11], ecx
	mov [rdi+4*15], edx

	; z0, z5, z10, z15
	mov eax, [rdi+4*0]
	mov ebx, [rdi+4*5]
	mov ecx, [rdi+4*10]
	mov edx, [rdi+4*15]
	call chacha20_QuarterRound
	mov [rdi+4*0], eax
	mov [rdi+4*5], ebx
	mov [rdi+4*10], ecx
	mov [rdi+4*15], edx

	; z1, z6, z11, z12
	mov eax, [rdi+4*1]
	mov ebx, [rdi+4*6]
	mov ecx, [rdi+4*11]
	mov edx, [rdi+4*12]
	call chacha20_QuarterRound
	mov [rdi+4*1], eax
	mov [rdi+4*6], ebx
	mov [rdi+4*11], ecx
	mov [rdi+4*12], edx

	; z2, z7, z8, z13
	mov eax, [rdi+4*2]
	mov ebx, [rdi+4*7]
	mov ecx, [rdi+4*8]
	mov edx, [rdi+4*13]
	call chacha20_QuarterRound
	mov [rdi+4*2], eax
	mov [rdi+4*7], ebx
	mov [rdi+4*8], ecx
	mov [rdi+4*13], edx

	; z3, z4, z9, z14
	mov eax, [rdi+4*3]
	mov ebx, [rdi+4*4]
	mov ecx, [rdi+4*9]
	mov edx, [rdi+4*14]
	call chacha20_QuarterRound
	mov [rdi+4*3], eax
	mov [rdi+4*4], ebx
	mov [rdi+4*9], ecx
	mov [rdi+4*14], edx

	ret

; This function performs the salsa20 hash function
; It assumes that esi points to the start of an array of 16 input dwords,
; that edi points to the start of an array of 16 output dwords and that the output
; dwords are initially a copy of the input dwords
; This function modifies eax, ebx, ecx, edx and uses the stack
; The results are stored in-place, the input dwords are not modified
chacha20_hash:
	push rbp
	
	; Run the double rounds on the output (the copy of inputs)
	push rsi
	mov rbp, 10
.roundLoop: 
	call chacha20_DoubleRound
	dec rbp
	jnz .roundLoop
	pop rsi
	
	; Add back inputs to outputs
	mov rcx, 15
.addLoop: 
	mov edx, [rsi+4*rcx]
	add [rdi+4*rcx], edx
	dec rcx
	jge .addLoop
	
	pop rbp
	ret



; This function performs a salsa20 expansion of a 32-byte key (256 bits)
; Assumes that r8 points to a 32-byte key, and r9 points to a 16-byte nounce
; Assumes that rsi points to the destination buffer
; This function modifies rdi
chacha20_expand32:
	mov rdi, chacha20_sigma
	
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
	call chacha20_hash
	ret



; This function performs a salsa20 expansion of a 16-byte key (256 bits)
; Assumes that r8 points to a 16-byte key, and r9 points to a 16-byte nounce
; Assumes that rsi points to the destination buffer
; This function modifies rdi and uses the stack
chacha20_expand16:
	add rsp, 64
	mov rdi, chacha20_tau
	
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
	call chacha20_hash
	ret



; Prepare the cipher's internal state to use the given key
; Assumes that r8 points to the state and r9 points to the key
; The key must have a size of 256 bits
; Returns nothing
chacha20_setupkey32:
	mov rax, r8
	
	mov rcx, chacha20_sigma
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



; Prepare the cipher's internal state to use the given key
; Assumes that r8 points to the state and r9 points to the key
; The key must have a size of 128 bits
; Returns nothing
chacha20_setupkey16:
	mov rax, r8
	
	mov rcx, chacha20_tau
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



; Prepare the cipher's internal state to use the given IV
; Assumes that r8 points to the state and r9 points to the iv
; The iv must have a size of at least 32 bits
; Returns nothing
chacha20_setupiv:
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



; Prepare the cipher's internal state to use the given IV fully
; Assumes that r8 points to the state and r9 points to the iv
; The iv must have a size of 64 bits
; Returns nothing
chacha20_setupivfull:
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



; Encrypts the plaintext m with the given internal state
; Assumes that r8 points to the state, r9 points to the msg, 
; r10 to the ciphertext, and r11 to the message size
; This function assumes that the state is valid, use setupkey and setupiv first
; Outputs the cyphertext to c
; Returns nothing
chacha20_encrypt:
	; NASM can't declare local arrays, so we'll play with rbp manually ...
	; I hate NASM. So much.
	;%local j[16]:dword, x[16]:dword, tmp[64]:byte, ctarget:ptr
	push rbp
	mov rbp, rsp
	sub rsp, 16*4 ; j
	sub rsp, 16*4 ; x
	sub rsp, 64 ; tmp
	mov rax, r11
	test rax, rax
	jz done
	push rsi
	push rdi
	push rbx
	
	; Prepare j
	mov rax, r8
	mov rbx, rbp
	sub rbx, 16*4
	mov rcx, 15
.jloop:
	mov edx, [rax+4*rcx]
	mov [rbx+4*rcx], edx
	dec rcx
	jge .jloop
	
	; Main loop
.mainLoop:
	; Use our tmp buffer if less than 64B is left
	cmp r11, 64
	jge .dontUseTmp
		mov rbx, r9
		mov rcx, r11
		dec rcx
		mov rdx, rbp
		sub rdx, (16*4)+(16*4)+64
		.tmploop:
		mov al, byte [rbx+rcx]
		mov [rdx+rcx], al
		dec rcx
		jge .tmploop
		mov r9, rdx
		mov rax, r10
		mov r12, rax
		mov r10, rdx
	.dontUseTmp:
	
	; Prepare x
	mov rax, rbp
	sub rax, 16*4
	mov rbx, rbp
	sub rbx, (16*4)+(16*4)
	mov rcx, 15
.xloop: 
	mov edx, [rax+4*rcx]
	mov [rbx+4*rcx], edx
	dec rcx
	jge .xloop
	
	; Compute hash & xor
	mov rsi, rbp
	sub rsi, 16*4
	mov rdi, rbp
	sub rdi, (16*4)+(16*4)
	call chacha20_hash
	mov rax, r9
	mov rcx, 15
.hashloop: 
	mov edx, [rax+4*rcx]
	xor [rdi+4*rcx], edx
	dec rcx
	jge .hashloop
	
	; Increment the nonce
	sub rbp, 16*4
	inc qword [rbp+4*12]
	mov rax, [rbp+4*12]
	test rax, rax
	jnz .noNoneOverflow
		inc qword [rbp+4*14]
	.noNoneOverflow:
	add rbp, 16*4
	
	; Write the ciphertext
	mov rax, rbp
	sub rax, 16*4+16*4
	mov rbx, r10
	mov rcx, 15
.cipherloop: 
	mov edx, [rax+4*rcx]
	mov [rbx+4*rcx], edx
	dec rcx
	jge .cipherloop
	
	; The last block is handled differently
	mov rax, r11
	cmp rax, 64
	jg .noLastBE
		jge .noLastB
			; We're using the tmp buffer, need to copy to ctarget
			mov rax, r10
			mov rbx, r12
			mov rcx, r11
			dec rcx
			.copyloop: 
			mov dl, [rax+rcx]
			mov [rbx+rcx], dl
			dec rcx
			jge .copyloop
		.noLastB:
		mov rdx, r8
		sub rbp, 16*4
		mov rax, [rbp+4*12]
		mov [rdx+4*14], rax
		mov rax, [rbp+4*14]
		mov [rdx+4*15], rax
		add rbp, 16*4
		jmp cleanup
	.noLastBE:
	
	sub r11, 64
	add r10, 64
	add r9, 64
	jmp .mainLoop
	
cleanup:
	pop rbx
	pop rdi
	pop rsi
done:
	add rsp, 64
	add rsp, 16*4
	add rsp, 16*4
	pop rbp
	ret



; Decrypts the cyphertext c with the given internal state
; Assumes that r8 points to the state, r9 points to the msg, 
; r10 to the ciphertext, and r11 to the message size
; Outputs the plaintext to m
; Returns nothing
chacha20_decrypt:
	call chacha20_encrypt
	ret
