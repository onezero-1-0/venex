; Example raw x86 assembly module
bits 64

;rcx -> this is pointer to table structer 

; Entry point - this is where execution begins
module_entry:
    ; Your assembly code here
    push rbp
    mov rbp, rsp

    mov r11,[rcx]
    mov r12,[rcx+8]
    
    sub rsp,32
    lea rcx,[rel command]
    lea rdx,[rel output_buffer]
    mov r8,buffer_size
    call r11
    add rsp,32

    

    sub rsp,32
    lea rcx,[rel output_buffer]
    mov rdx,rax
    call r12
    add rsp,32
    
    mov rsp,rbp
    pop rbp
    ret

; Data section
command db "pwd", 0
output_buffer: times 1024 db 0
buffer_size equ $ - output_buffer
