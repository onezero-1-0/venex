extern _syscallExtracter
extern _stubExtracter


struc IO_STATUS_BLOCK
    .Status         resq 1        ; NTSTATUS (or pointer)
    .Information    resq 1
endstruc

struc OBJECT_ATTRIBUTES
    .Length                  resd 1      ; ULONG (4)
    ._pad0                   resd 1      ; padding for alignment
    .RootDirectory           resq 1      ; HANDLE (8)
    .ObjectName              resq 1      ; PUNICODE_STRING (8)
    .Attributes              resd 1      ; ULONG (4)
    ._pad1                   resd 1      ; padding
    .SecurityDescriptor      resq 1      ; PVOID (8)
    .SecurityQualityOfService resq 1     ; PVOID (8)
endstruc

struc UNICODE_STRING
    .Length           resw 1        ; NTSTATUS (or pointer)
    .MaximumLength    resw 1 
    ._pad0            resd 1      ; padding for alignment
    .Buffer           resq 1
endstruc

section .bss
    ; Reserve space for UNICODE_STRING structure
    objName resb UNICODE_STRING_size  ; 3 fields: Length (2), MaximumLength (2), Buffer (8)
    objAttr resb OBJECT_ATTRIBUTES_size
    hConsole resb 8          ; HANDLE (4 bytes) = NULL
    ioStatus resb IO_STATUS_BLOCK_size  

section .data
    ; Unicode string for CONOUT$
    consoleName dw '\', '?', '?', '\', 'C', 'O', 'N', 'O', 'U', 'T', '$', 0  ; L"\\??\\CONOUT$"
    msg db "Hello World",10,0
    msgLen equ $ - msg


section .text
global _start


_start:
    ; Initialize UNICODE_STRING structure manually
    mov word [rel objName + UNICODE_STRING.Length], 22          ; Length = 11 chars * 2 = 22 bytes
    mov word [rel objName + UNICODE_STRING.MaximumLength], 24      ; MaximumLength = 22 + 2 = 24 bytes (includes null terminator)
    lea rax,[rel consoleName]
    mov qword [rel objName + UNICODE_STRING.Buffer], rax ; Buffer pointer to the string

    mov dword [rel objAttr + OBJECT_ATTRIBUTES.Length], 48         ; Length = sizeof(OBJECT_ATTRIBUTES) = 24
    mov qword [rel objAttr + OBJECT_ATTRIBUTES.RootDirectory], 0      ; RootDirectory = NULL
    lea rax,[rel objName]
    mov qword [rel objAttr + OBJECT_ATTRIBUTES.ObjectName], rax ; ObjectName = &objName
    mov dword [rel objAttr + OBJECT_ATTRIBUTES.Attributes], 0x40  ; Attributes = OBJ_CASE_INSENSITIVE
    mov qword [rel objAttr + OBJECT_ATTRIBUTES.SecurityDescriptor], 0     ; SecurityDescriptor = NULL
    mov qword [rel objAttr + OBJECT_ATTRIBUTES.SecurityQualityOfService], 0     ; SecurityQualityOfService = NULL

    ; Initialize variables
    mov qword [rel hConsole], 0  ; hConsole = NULL
    
    ; Initialize IO_STATUS_BLOCK to zero (optional but good practice)
    mov qword [rel ioStatus + IO_STATUS_BLOCK.Status], 0    ; Status/Pointer = 0
    mov qword [rel ioStatus + IO_STATUS_BLOCK.Information], 0 ; Information = 0

    
    ;making createFile syscall
    sub rsp, 88
    lea rcx,[rel hConsole]
    mov	edx, 1179926
    lea r8,[rel objAttr]
    lea r9,[rel ioStatus]
    mov	DWORD 80[rsp], 0
	mov	QWORD 72[rsp], 0
	mov	DWORD 64[rsp], 32
	mov	DWORD 56[rsp], 3
	mov	DWORD 48[rsp], 3
	mov	DWORD 40[rsp], 128
	mov	QWORD 32[rsp], 0
    mov eax,0x18B9EFEE
    call _syscallExtracter
    call _stubExtracter
    add rsp, 88

    ; Initialize IO_STATUS_BLOCK to zero (optional but good practice)
    mov qword [rel ioStatus + IO_STATUS_BLOCK.Status], 0    ; Status/Pointer = 0
    mov qword [rel ioStatus + IO_STATUS_BLOCK.Information], 0 ; Information = 0

    ;making createFile syscall
    sub rsp,72
    mov rcx,[rel hConsole]
    xor	rdx, rdx
    xor r8,r8
    xor r9,r9
	mov	QWORD 64[rsp], 0
	mov	QWORD 56[rsp], 0
	mov	DWORD 48[rsp], msgLen
    lea rax,[rel msg]
	mov	QWORD 40[rsp], rax
    lea rax,[rel ioStatus]
	mov	QWORD 32[rsp], rax
    mov eax,0x01EE87BE
    call _syscallExtracter
    call _stubExtracter
    add rsp,72

    xor rcx, rcx        ; ProcessHandle = NULL (current process)
    xor rdx, rdx        ; ExitStatus = 0
    mov eax, 0x29       ; NtTerminateProcess syscall number (may vary)
    syscall

syscall_stub:
    mov     r10,rcx
    syscall
    ret