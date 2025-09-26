extern printf
extern ExitProcess
extern scanf
section .data
    fmt db "value is 0x%x", 10, 0 
    numbers times 32 db 0
    sfmt db "%d", 0
    sfmtprint db "Enter value: ", 0

section .text
    global mains
    global gostGetNumberHash

mains:

    sub rsp, 40

    lea rcx, [rel sfmtprint]
    xor eax, eax          ; clear RAX for variadic
    call printf

    lea rcx, [rel sfmt]
    lea rdx, [rel numbers]
    call scanf

    mov rcx,[rel numbers]
    call gostGetNumberHash

    lea rcx, [rel fmt]
    mov rdx,rax
    xor eax, eax          ; clear RAX for variadic
    call printf

    xor ecx, ecx                ; ECX = exit code 0
    call ExitProcess            ; Exit cleanly

gostGetNumberHash:
    push rbp
    mov rbp,rsp

    mov rdi,rcx

    push rdi
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

    mov eax,r9d
    leave
    ret

; print_win.asm


