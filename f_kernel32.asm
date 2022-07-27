; Returns handle to kernel32.dll in memory and handle to GetProcAddress

; 32 bit applications only

global _f_kernel32

section .text

_f_kernel32:
    push ebp
    mov ebp, esp
    push edi
    push esi
    push ebx

    call KE32FIND

    mov eax, [ebp + 0x8]
    mov ebx, [ebp + 0xc]

    mov [eax], ecx
    mov [ebx], edx

    pop ebx
    pop esi
    pop edi

    mov ebp, esp
    pop ebp
    ret

KE32BASE:
    mov eax, [fs:0x30]
    mov eax, [eax + 0xc]
    mov eax, [eax + 0x14]   
    mov eax, [eax]
    mov eax, [eax]
    mov eax, [eax + 0x10]
    ret

KE32EXPORTS:							; (IN UNCHANGED) eax kernel32 base, (OUT) ecx no. of functions, (OUT) ebx ordinal table, (OUT) esi name pointer table, (OUT) edx address table
    
    xor ebx, ebx
    mov ebx, [eax + 0x3c]
    add ebx, eax
    mov edx, [ebx]
    
    mov ebx, [ebx + 0x78]
    add ebx, eax
    
    mov ecx, [ebx + 0x14]
    mov edx, [ebx + 0x1c]
    mov esi, [ebx + 0x20]
    mov ebx, [ebx + 0x24]
    
    add edx, eax
    add esi, eax
    add ebx, eax
    
    ret

KE32FIND:
    
    push ebp
    mov ebp, esp
    
    push edi
    push esi

    call KE32BASE
    test eax, eax
    je .error
    
    push 0x00007373
    push 0x65726464
    push 0x41636f72
    push 0x50746547
    
    mov edi, esp
    
    call PROCADDR
    
    add esp, 0x10
    
    pop esi
    pop edi
    
.error:
    mov esp, ebp
    pop ebp
    ret
    
PROCADDR: 								; eax = dll to get function from, edi = function name
    push ebp
    mov ebp, esp
    
    call KE32EXPORTS
    
    push edx
    push ebx
    push ecx
    
    xor ebx, ebx
    push esi
    push edi
.LOADNEXT:
    mov esi, [esi + ebx * 4]
    add esi, eax
    mov ecx, 15
    repe cmpsb
    je .PROCFIND
    mov esi, [ebp - 0x10]
    mov edi, [ebp - 0x14]
    inc ebx
    cmp ebx, [ebp - 0xc]
    jg .NOTFOUND
    jmp .LOADNEXT
.PROCFIND:								; name address table starts at 0x4
    add esp, 0xc
    pop ecx
    push eax
    xor eax, eax
    mov ax, word [ecx + ebx * 2]
    mov edx, [edx + eax * 4]
    pop ecx
    add edx, ecx
.NOTFOUND:	
    mov esp, ebp
    pop ebp
    ret
    
    
    