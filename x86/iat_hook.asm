;-----------------------------------------------------------------------------;
; Author: Ege Balcı <ege.balci[at]invictuseurope[dot]com>
; Compatible: Windows 10/8.1/8/7/2008/Vista/2003/XP/2000/NT4
; Version: 1.0 (25 January 2018)
; Size: 172 bytes
;-----------------------------------------------------------------------------;

; This block hooks the API functions by locating the addresses of API functions from import address table with given ror(13) hash value.
; Design is inpired from Stephen Fewer's hash api.

[BITS 32]

; Input: The hash of the API to call and all its parameters must be pushed onto stack.
; Output: The return value from the API call will be in EAX.
; Clobbers: EAX, ECX and EDX (ala the normal stdcall calling convention)
; Un-Clobbered: EBX, ESI, EDI, ESP and EBP can be expected to remain un-clobbered.
; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.
; Note: This function is unable to call forwarded exports.

%define ROTATION 0x0D		; Rotation value for ROR hash

set_essentials:
  	pushad                 	; We preserve all the registers for the caller, bar EAX and ECX.
  	xor eax,eax           	; Zero EAX (upper 3 bytes will remain zero until function is found)
  	mov edx,[fs:eax+0x30] 	; Get a pointer to the PEB
	mov edx,[edx+0x0C]		; Get PEB->Ldr	
	mov edx,[edx+0x14]		; Get the first module from the InMemoryOrder module list
	mov edx,[edx+0x10]		; Get this modules base address
	push edx				; Save the image base to stack (will use this alot)
  	add edx,[edx+0x3C]     	; "PE" Header
	mov edx,[edx+0x80]		; Import table RVA
	add edx,[esp]			; Address of Import Table
	push edx				; Save the &IT to stack (will use this alot)
	mov esi,[esp+0x04]		; Move image base to ESI
	sub esp,0x08			; Allocate space for import desriptor & hash
	sub edx,0x14			; Prepare the import descriptor pointer for processing
next_desc:
	add edx,0x14			; Get the next import descriptor
	cmp dword [edx],0x00	; Check if import descriptor valid
	jz not_found			; If import name array RVA is zero finish parsing
	mov si,[edx+0x0C]     	; Get pointer to module name string RVA
	xor edi, edi           	; Clear EDI which will store the hash of the module name
loop_modname:            	;
	lodsb                  	; Read in the next byte of the name
	cmp al, 'a'            	; Some versions of Windows use lower case module names
	jl not_lowercase       	;
	sub al, 0x20           	; If so normalise to uppercase
not_lowercase:           	;
  	ror edi,ROTATION        ; Rotate right our hash value
 	add edi,eax           	; Add the next byte of the name
	ror edi,ROTATION		; In order to calculate the same hash values as Stephen Fewer's hash API we need to rotate one more and add a null byte.
  	test al,al				; Check if we read all
	jnz loop_modname
	; We now have the module hash computed
	mov [esp+4],edx         ; Save the current position in the module list for later
	mov [esp],edi           ; Save the current module hash for later
  	; Proceed to iterate the export address table,
	mov ecx,[edx]      		; Get the RVA of import names table 
	add ecx,[esp+0x0C]      ; Add image base and get address of import names table
	sub ecx,0x04			; Go 4 byte back	
get_next_func:
  	; use ecx as our EAT pointer here so we can take advantage of jecxz.
  	add ecx,0x04			; 4 byte forward
	cmp dword [ecx],0x00	; Check if end of INT
  	jz next_desc    		; If no INT present, process the next import descriptor
  	mov esi,[ecx]           ; Get the RVA of func name hint
  	cmp esi,0x80000000      ; Check if the high order bit is set
	jns get_next_func		; If not there is no function name string :(
	add esi,[esp+0x0C]		; Add the image base and get the address of function hint
	add dword esi,0x02		; Move 2 bytes forward to asci function name
  	; now ecx returns to its regularly scheduled counter duties
  	; Computing the module hash + function hash
  	xor edi,edi           	; Clear EDI which will store the hash of the function name
  	; And compare it to the one we want
loop_funcname:           	;
  	lodsb                  	; Read in the next byte of the ASCII function name
  	ror edi,ROTATION        ; Rotate right our hash value
  	add edi,eax           	; Add the next byte of the name
  	cmp al,ah             	; Compare AL (the next byte from the name) to AH (null)
  	jne loop_funcname      	; If we have not reached the null terminator, continue
  	add edi,[esp]       	; Add the current module hash to the function hash
  	cmp edi,[esp+0x34]      ; Compare the hash to the one we are searching for
  	jnz get_next_func      	; Go compute the next function hash if we have not found it

  	; If found, fix up stack, replace the function address and then value else compute the next one...
	mov eax,[edx+0x10]		; Get the RVA of current descriptor's IAT 
	mov edx,[edx]			; Get the import names table RVA of current import descriptor
	add edx,[esp+0x0C]		; Get the address of import names table of current import descriptor
	sub ecx,edx				; Find the function array index ?
	add eax,[esp+0x0C]		; Add the image base to current descriptors IAT RVA
	add eax,ecx				; Add the function index
	; Now we clean the stack		
	push eax				; Save the function address to stack
	cld						; Clear direction flags
	call unprotect			; Get the address of block_api to stack
_api_call:
	pushad                 ; We preserve all the registers for the caller, bar EAX and ECX.
	mov ebp, esp           ; Create a new stack frame
	xor eax, eax           ; Zero EAX (upper 3 bytes will remain zero until function is found)
	mov edx, [fs:eax+48]   ; Get a pointer to the PEB
	mov edx, [edx+12]      ; Get PEB->Ldr
	mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
	_next_mod:                ;
	mov esi, [edx+40]      ; Get pointer to modules name (unicode string)
	movzx ecx, word [edx+38] ; Set ECX to the length we want to check
	xor edi, edi           ; Clear EDI which will store the hash of the module name
_loop_modname:            ;
	lodsb                  ; Read in the next byte of the name
	cmp al, 'a'            ; Some versions of Windows use lower case module names
	jl _not_lowercase       ;
	sub al, 0x20           ; If so normalise to uppercase
_not_lowercase:           ;
	ror edi, 13            ; Rotate right our hash value
	add edi, eax           ; Add the next byte of the name
	loop _loop_modname      ; Loop until we have read enough

	; We now have the module hash computed
	push edx               ; Save the current position in the module list for later
	push edi               ; Save the current module hash for later
	; Proceed to iterate the export address table,
	mov edx, [edx+16]      ; Get this modules base address
	mov ecx, [edx+60]      ; Get PE header

	; use ecx as our EAT pointer here so we can take advantage of jecxz.
	mov ecx, [ecx+edx+120] ; Get the EAT from the PE header
	jecxz _get_next_mod1    ; If no EAT present, process the next module
	add ecx, edx           ; Add the modules base address
	push ecx               ; Save the current modules EAT
	mov ebx, [ecx+32]      ; Get the rva of the function names
	add ebx, edx           ; Add the modules base address
	mov ecx, [ecx+24]      ; Get the number of function names
	; now ecx returns to its regularly scheduled counter duties

	; Computing the module hash + function hash
_get_next_func:           ;
	jecxz _get_next_mod     ; When we reach the start of the EAT (we search backwards), process the next module
	dec ecx                ; Decrement the function name counter
	mov esi, [ebx+ecx*4]   ; Get rva of next module name
	add esi, edx           ; Add the modules base address
	xor edi, edi           ; Clear EDI which will store the hash of the function name
	; And compare it to the one we want
_loop_funcname:           ;
	lodsb                  ; Read in the next byte of the ASCII function name
	ror edi, 13            ; Rotate right our hash value
	add edi, eax           ; Add the next byte of the name
	cmp al, ah             ; Compare AL (the next byte from the name) to AH (null)
	jne _loop_funcname      ; If we have not reached the null terminator, continue
	add edi, [ebp-8]       ; Add the current module hash to the function hash
	cmp edi, [ebp+36]      ; Compare the hash to the one we are searching for
	jnz _get_next_func      ; Go compute the next function hash if we have not found it

	; If found, fix up stack, call the function and then value else compute the next one...
	pop eax                ; Restore the current modules EAT
	mov ebx, [eax+36]      ; Get the ordinal table rva
	add ebx, edx           ; Add the modules base address
	mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
	mov ebx, [eax+28]      ; Get the function addresses table rva
	add ebx, edx           ; Add the modules base address
	mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
	add eax, edx           ; Add the modules base address to get the functions actual VA
	; We now fix up the stack and perform the call to the desired function...
_finish:
	mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address for the upcoming popad
	pop ebx                ; Clear off the current modules hash
	pop ebx                ; Clear off the current position in the module list
	popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
	pop ecx                ; Pop off the origional return address our caller will have pushed
	pop edx                ; Pop off the hash value our caller will have pushed
	push ecx               ; Push back the correct return value
	jmp eax                ; Jump into the required function
	; We now automagically return to the correct caller...

_get_next_mod:            ;
	pop edi                ; Pop off the current (now the previous) modules EAT
_get_next_mod1:           ;
	pop edi                ; Pop off the current (now the previous) modules hash
	pop edx                ; Restore our position in the module list
	mov edx, [edx]         ; Get the next module
	jmp _short next_mod     ; Process this module
unprotect:
	pop ebp					; Pop the address of block_api to EBP
	push eax				; Allocate space for lpflOldProtect
	push esp				; lpflOldProtect
	push 0x00000004			; flNewProtect (PAGE_READWRITE)
	push 0x00000008			; dwSize
	push eax				; lpAddress (IAT entry address)
	push 0xC38AE110			; hash( "KERNEL32.dll", "VirtualProtect" )
	call ebp				; VirtualProtect(&IAT,8,PAGE_READWRITE,&STACK)
	pop eax					; Deallocate lpflOldProtect
	pop eax					; Pop back the function address to be hooked
finish:
	mov esi,[esp+0x38]		; Get the hooker fucntion address ;D	
	mov [eax],esi			; Replace the IAT entry with hooker
	add esp,0x10			; Deallocate saved module hash, import descriptor address, import table address
  	popad                  	; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
  	pop ecx                	; Pop off the origional return address our caller will have pushed
  	pop edx                	; Pop off the hash value our caller will have pushed
	pop edx					; Pop off the hooker function address
  	push ecx               	; Push back the correct return value
	ret						; Return
not_found:
	add esp,0x08			; Fix the stack
	popad					; Restore all registers
	ret						; Return
	; (API is not found)
