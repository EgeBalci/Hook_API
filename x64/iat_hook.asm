;-----------------------------------------------------------------------------;
; Author: Ege Balcı (ege.balci[at]invictuseurope[dot]com)
; Compatible: Windows 7, 2003
; Architecture: x64
; Size: 454 bytes
;-----------------------------------------------------------------------------;

[BITS 64]

; Windows x64 calling convention:
; http://msdn.microsoft.com/en-us/library/9b372w95.aspx

; Input: The hash of the API to hook in r10d and the first stack parameter is the address to be replaced with. 
; Output: Block do not give any output.
; Clobbers: RAX, R10
; Un-Clobbered: RBX, RDX, RSI, RDI, RBP, R11, R12, R13, R14, R15. 
; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.
; Note: This function is unable to call forwarded exports.
; Note: Caller needs to clean the stack parameter after block finishes.


%define ROTATION 13		; Rotation value for ROR hash

api_call:
  	push rdx                ; Save RDX
  	push rcx                ; Save RCX
  	push rsi                ; Save RSI
	push rdi				; Save RDI
  	xor rdx,rdx            	; Zero RDX
  	mov rdx,[gs:rdx+96]    	; Get a pointer to the PEB
  	mov rdx,[rdx+24]       	; Get PEB->Ldr
  	mov rdx,[rdx+32]       	; Get the first module from the InMemoryOrder module list
  	mov rdx,[rdx+32]	   	; Get this modules base address
  	push rdx				; Save the image base to stack (will use this alot)
  	add dx,word [rdx+60]    ; "PE" Header
  	mov edx,dword [rdx+144]	; Import table RVA
 	add rdx,[rsp]			; Address of Import Table
	push rdx				; Save the &IT to stack (will use this alot)i
  	mov rsi,[rsp+8]			; Move the image base to RSI
	sub rsp,16				; Allocate space for import descriptor counter & hash
	sub rdx,20				; Prepare import descriptor pointer for processing
next_desc:
	add rdx,20				; Get the next import descriptor
	cmp dword [rdx],0		; Check if import descriptor is valid
	jz not_found			; If import name array RVA is zero finish parsing
	mov rsi,[rsp+16]		; Move import table address to RSI
	mov si,[rdx+12]			; Get pointer to module name string RVA
	xor rdi,rdi				; Clear RDI which will store the hash of the module name
	xor rax,rax				; Clear RAX for calculating the hash
loop_modname:
	lodsb					; Read in the next byte of the name
	cmp al,'a'				; Some versions of windows use lower case module names
	jl not_lowercase		;
	sub al,32				; If so normalize to uppercase 
not_lowercase:
  	ror edi, ROTATION       ; Rotate right our hash value
  	add edi, eax            ; Add the next byte of the name
	ror edi,ROTATION		; In order to calculate the same hash values as Stephen Fewer's hash API we need to rotate one more and add a null byte.
	test al,al				; Check if we read all
	jnz loop_modname		; 
  	; We now have the module hash computed
	mov [rsp+8],rdx			; Save the current position in the module listfor later
	mov [rsp],edi			; Save the current module hash for later
  	; Proceed to itterate the export address table, 
  	mov ecx,dword [rdx]     ; Get RVA of import names table
  	add rcx,[rsp+24]  		; Add the image base and get the address of import names table
	sub rcx,8				; Go 4 bytes back
get_next_func:             	;
	add ecx,8				; 4 byte forward
	cmp dword [rcx],0		; Check if end of INT
	jz next_desc			; If no INT present, process the next import descriptor
	mov esi,dword [rcx]		; Get the RVA of func name hint
	cmp esi,0x80000000		; Check if the high order bit is set
	jns get_next_func		; If not, there is no function name string :(
	add rsi,[rsp+24]		; Add the image base and get the address of function name hint
	add dword esi,2			; Move 2 bytes forward to asci function name
	; now ecx returns to its regularly scheduled counter duties
	; Computing the module hash + function hash
	xor rdi,rdi
	xor rax,rax
	; And compare it to the one we want
loop_funcname:
	lodsb                   ; Read in the next byte of the ASCII function name
  	ror edi,ROTATION        ; Rotate right our hash value
  	add edi,eax             ; Add the next byte of the name
  	cmp al,ah               ; Compare AL (the next byte from the name) to AH (null)
  	jne loop_funcname       ; If we have not reached the null terminator, continue
  	add edi,[rsp]          	; Add the current module hash to the function hash
  	cmp edi,r10d      		; Compare the hash to the one we are searchnig for 
  	jnz get_next_func       ; Go compute the next function hash if we have not found it
  ; If found, fix up stack, call the function and then value else compute the next one...
	mov eax,dword [rdx+16]	; Get the RVA of current descriptor's IAT
	mov edx,dword [rdx]		; Get the import names table RVA of current import descriptor
	add rdx,[rsp+24]		; Get the address of import names table of current import descriptor
	sub rcx,rdx				; Find the function array index ?
	add rax,[rsp+24]		; Add the image base to current descriptors IAT RVA
	add rax,rcx				; Add the function index
	; Now clean the stack
  	; We now fix up the stack and perform the call to the drsired function...
	push rax				; Save the function address to stack
	cld						; Clear direction flags
	call unprotect			; Get the address of block_api to stack
_api_call:
	push r9                  ; Save the 4th parameter
	push r8                  ; Save the 3rd parameter
	push rdx                 ; Save the 2nd parameter
	push rcx                 ; Save the 1st parameter
	push rsi                 ; Save RSI
	xor rdx, rdx             ; Zero rdx
	mov rdx, [gs:rdx+96]     ; Get a pointer to the PEB
	mov rdx, [rdx+24]        ; Get PEB->Ldr
	mov rdx, [rdx+32]        ; Get the first module from the InMemoryOrder module list
_next_mod:                  ;
	mov rsi, [rdx+80]        ; Get pointer to modules name (unicode string)
	movzx rcx, word [rdx+74] ; Set rcx to the length we want to check 
	xor r9, r9               ; Clear r9 which will store the hash of the module name
_loop_modname:              ;
	xor rax, rax             ; Clear rax
	lodsb                    ; Read in the next byte of the name
	cmp al, 'a'              ; Some versions of Windows use lower case module names
	jl _not_lowercase         ;
	sub al, 0x20             ; If so normalise to uppercase
_not_lowercase:             ;
	ror r9d, ROTATION              ; Rotate right our hash value
	add r9d, eax             ; Add the next byte of the name
	loop _loop_modname        ; Loop untill we have read enough
	; We now have the module hash computed
	push rdx                 ; Save the current position in the module list for later
	push r9                  ; Save the current module hash for later
	; Proceed to itterate the export address table, 
	mov rdx, [rdx+32]        ; Get this modules base address
	mov eax, dword [rdx+60]  ; Get PE header
	add rax, rdx             ; Add the modules base address
	cmp word [rax+24], 0x020B ; is this module actually a PE64 executable? 
	; this test case covers when running on wow64 but in a native x64 context via nativex64.asm and 
	; their may be a PE32 module present in the PEB's module list, (typicaly the main module).
	; as we are using the win64 PEB ([gs:96]) we wont see the wow64 modules present in the win32 PEB ([fs:48])
	jne _get_next_mod1         ; if not, proceed to the next module
	mov eax, dword [rax+136] ; Get export tables RVA
	test rax, rax            ; Test if no export address table is present
	jz _get_next_mod1         ; If no EAT present, process the next module
	add rax, rdx             ; Add the modules base address
	push rax                 ; Save the current modules EAT
	mov ecx, dword [rax+24]  ; Get the number of function names  
	mov r8d, dword [rax+32]  ; Get the rva of the function names
	add r8, rdx              ; Add the modules base address
	; Computing the module hash + function hash
_get_next_func:             ;
	jrcxz _get_next_mod       ; When we reach the start of the EAT (we search backwards), process the next module
	dec rcx                  ; Decrement the function name counter
	mov esi, dword [r8+rcx*4]; Get rva of next module name
	add rsi, rdx             ; Add the modules base address
	xor r9, r9               ; Clear r9 which will store the hash of the function name
	; And compare it to the one we want
_loop_funcname:             ;
	xor rax, rax             ; Clear rax
	lodsb                    ; Read in the next byte of the ASCII function name
	ror r9d, ROTATION              ; Rotate right our hash value
	add r9d, eax             ; Add the next byte of the name
	cmp al, ah               ; Compare AL (the next byte from the name) to AH (null)
	jne _loop_funcname        ; If we have not reached the null terminator, continue
	add r9, [rsp+8]          ; Add the current module hash to the function hash
	cmp r9d, r10d            ; Compare the hash to the one we are searchnig for 
	jnz _get_next_func        ; Go compute the next function hash if we have not found it
	; If found, fix up stack, call the function and then value else compute the next one...
	pop rax                  ; Restore the current modules EAT
	mov r8d, dword [rax+36]  ; Get the ordinal table rva      
	add r8, rdx              ; Add the modules base address
	mov cx, [r8+2*rcx]       ; Get the desired functions ordinal
	mov r8d, dword [rax+28]  ; Get the function addresses table rva  
	add r8, rdx              ; Add the modules base address
	mov eax, dword [r8+4*rcx]; Get the desired functions RVA
	add rax, rdx             ; Add the modules base address to get the functions actual VA
	; We now fix up the stack and perform the call to the drsired function...
_finish:
	pop r8                   ; Clear off the current modules hash
	pop r8                   ; Clear off the current position in the module list
	pop rsi                  ; Restore RSI
	pop rcx                  ; Restore the 1st parameter
	pop rdx                  ; Restore the 2nd parameter
	pop r8                   ; Restore the 3rd parameter
	pop r9                   ; Restore the 4th parameter
	pop r10                  ; pop off the return address
	sub rsp, 32              ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
							; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
	push r10                 ; push back the return address
	jmp rax                  ; Jump into the required function
	; We now automagically return to the correct caller...
_get_next_mod:              ;
	pop rax                  ; Pop off the current (now the previous) modules EAT
_get_next_mod1:             ;
	pop r9                   ; Pop off the current (now the previous) modules hash
	pop rdx                  ; Restore our position in the module list
	mov rdx, [rdx]           ; Get the next module
	jmp _next_mod             ; Process this module
unprotect:	
	pop rbp					; Pop the address of block_api to RBP
	mov rcx,[rsp]			; lpAddress (IAT entry address)
	mov rdx,8				; dwSize
	mov r8,0x04				; flNewProtect (PAGE_READWRITE)i
	push rax				; Allocate space for lpflOldProtect
	mov r9,rsp				; lpflOldProtecti
	mov r10d,0xC38AE110		; hash( "KERNEL32.dll", "VirtualProtect" )
	call rbp				; VirtualProtect(&IAT,8,PAGE_READWRITE,&STACK)
	add rsp,40				; Clean out the stack
	pop rax					; Move the IAT entry address to RAX 
finish:
	add rsp,32			     ; Clear off the module hash, module list index, &IT, image base
  	pop rdi					 ; Restore RDI
	pop rsi                  ; Restore RSI
  	pop rcx                  ; Restore RCX
  	pop rdx                  ; Restore RDX	
  	mov r10,[rsp+8]          ; Move the new IAT entry to R10
	mov [rax],r10			 ; Change the IAT entry with the new function address
  	ret						 ; Finito !
  ; We now automagically return to the correct caller...
not_found:
	add rsp,32			     ; Clear off the module hash, module list index, &IT, image base
	pop rdi					 ; Restore RDI
	pop rsi					 ; Restore RSI
	pop rcx					 ; Restore RCX
	pop rdx					 ; Restore RDX
	ret						 ; Return to caller
