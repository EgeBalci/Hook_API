# Hook API
Assembly block for hooking windows API functions.


It finds the import address table index of API functions by parsing the `_IMAGE_IMPORT_DESCRIPTOR` structure entries inside the import table of the PE file. It first calculates the ROR(13) hash of the (module name + function name) and compares with the hash passed to block. If the hash matches it replaces IAT entry with the passed address. Sometimes the memory space that is containing the import address table is not writable by the running thread. In such cases this block uses `VirtualProtect` function for changing the virtual address space permissions that is containing the IAT entry we want.  

![Description](https://github.com/EgeBalci/hook_api/raw/master/flow.png)

<strong>IMPORTANT !!</strong> 
- The function that is called with hook_api must be imported by the PE file or it will crash.

## Example

Following code hooks the `DeleteFileA` windows API function using the hook_api block. After hooking the function it will always return nonzero value. When a process executes this code it will not able to delete any file.  

[![Example](https://github.com/EgeBalci/Hook_API/raw/master/Example.png)]()

Following code hooks the `TerminateProcess` windows API function using the hook_api block. After hooking the function it will always return nonzero value. When a process executes this code it will not able to terminate any other process with `TerminateProcess` API function.  

[![Example64](https://github.com/EgeBalci/Hook_API/raw/master/Example64.png)]()