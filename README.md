# Hook API
Assembly blocks for hooking windows API functions.


## iat_hook.asm
It finds the import address table index of API functions by parsing the `_IMAGE_IMPORT_DESCRIPTOR` structure entries inside the import table of the PE file. It first calculates the ROR(13) hash of the (module name + function name) and compares with the hash passed to block. If the hash matches it replaces IAT entry with the passed address. Sometimes the memory space that is containing the import address table is not writable by the running thread. In such cases this block uses `VirtualProtect` function for changing the virtual address space permissions that is containing the IAT entry we want.  

![Description](https://github.com/EgeBalci/hook_api/raw/master/flow.png)

<strong>IMPORTANT !!</strong> 
- The function that is called with hook_api must be imported by the PE file or it will crash.

### Example

Following code hooks the `DeleteFileA` windows API function using the hook_api block. After hooking the function it will always return nonzero value. When a process executes this code it will not able to delete any file.  

```
[BITS 32]
    pushad                  ; Save all registers to stack
    pushfd                  ; Save all flags to stack
    cld                     ; Clear direction flags
    call start              ; call start
    %include "iat_api.asm"  ; iat_api.asm goes here
start:                      ; ...
    pop ebp                 ; Pop out the address of iat_api.asm to EBP
    call fin                ; Push the address of hooked code to stack
hooked_code:                ; ...
    mov eax,0xFF            ; Move non-zero value to EAX
    ret                     ; Return
fin:                        ; ...
    push 0x13DD2ED7         ; hash( "KERNEL32.dll", "DeleteFileA" )
    call ebp                ; Call the iat_api block
    popfd                   ; Pop back saved flags
    popad                   ; Pop back saved registers
    ret                     ; Return to caller

```

Following code hooks the `TerminateProcess` windows API function using the hook_api block. After hooking the function it will always return nonzero value. When a process executes this code it will not able to terminate any other process with `TerminateProcess` API function.  

```
[BITS 64]

    cld                     ; Clear direction flags
    push r10                ; Save R10 register
    %include "iat_api.asm"  ; iat_api.asm goes here
start:                      ; ...
    pop rbp                 ; Pop out the address of iat_api.asm to RBP
    call get_return_true    ; Call get_return_true
return_true:                ; ...
    mov rax,0x01            ; Move non zero value to RAX
    ret                     ; Return
get_return_true:            ; ...
    mov r10d,0x5ECADC87     ; hash( "KERNEL32.dll", "TerminateProcess" )
    call rbp                ; Call the iat_api block
    pop rax                 ; Clear stack
    pop r10                 ; Restore R10
    ret                     ; Return to caller

```

## inline_hook.asm
It finds the address of the target API functions by parsing the `PEB->Ldr->InMemoryOrderModuleList`. After finding the address it replaces the beginng of the function with the given `patch` binary. This binary can be used as a prologue for redirecting the target API function to elsewhere or returning any arbitrary value.

### Example

Following code hooks the `AdjustTokenPrivileges` windows API function using the inline_hook.asm block. After hooking the function it will always return nonzero value. When a process executes this code it will not be able to escalate privileges.  

Content of `patch` binary
```
    db 0x32,0xc0  ; xor eax,eax
    db 0xc3       ; ret 
```

x86 Hook code:
```
[BITS 32]


	cld                             ; Clear direction flags
	call get_hook_api               ; Get the address of inline_hook_api.asm to stack
	%include "inline_hook.asm"      ; inline_hook.asm goes here
get_hook_api:                       ; ...
	pop ebp                         ; Pop out the address of inline_hook_api.asm to EBP
	push 0x330A1F75                 ; hash("NTDLL.dll", "AdjustTokenPrivileges")
	call ebp                        ; hook("RtlSetDaclSecurityDescriptor")
```

x64 Hook code:
```
[BITS 64]
	
	cld                             ; Clear direction flags
	call get_hook_api               ; Get the address of inline_hook_api.asm to stack
	%include "inline_hook.asm"      ; inline_hook.asm goes here
get_hook_api:                       ; ...
	pop rbp                         ; Pop out the address of inline_hook_api.asm to EBP
	mov r10d,0x330A1F75             ; hash("ADVAPI32.dll", "AdjustTokenPrivileges")
	call rbp                        ; hook("RtlSetDaclSecurityDescriptor")
	
```