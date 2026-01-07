#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>

// (Optional) declare the pointer globally
void* my_payload_mem; 
void* my_payload_dest;

int main() {
    // call the function here, when the program is running.
    my_payload_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // Check for success
    if (my_payload_mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("Memory allocated at: %p\n", my_payload_mem);

    // canned shellcode maybe write my own
    unsigned char shellcode[] = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05";

    // copy the shellcode to the allocated memory
    my_payload_dest = memcpy(my_payload_mem, shellcode, sizeof(shellcode));

    printf("Shellcode copied succesfully to the allocated memory with memory destination at: %p\n", my_payload_dest);

    // create a funciton pointer
    void (*func_ptr)();

    // cast the void pointer to the function pointer
    *(void**)(&func_ptr) = my_payload_dest;

    // call the function pointer
    func_ptr();
    
    return 0;
}

// 1. Define a variable to hold the address
// 2. Call mmap
// Arg 1 (addr): NULL (Let the OS choose the address)
// Arg 2 (len):  The size in bytes (e.g., 4096)
// Arg 3 (prot): PROT_READ | PROT_WRITE | PROT_EXEC (The permissions)
// Arg 4 (flags): MAP_PRIVATE | MAP_ANONYMOUS (Not a file, private memory)
// Arg 5 (fd):   -1 (We aren't using a file)
// Arg 6 (offset): 0 (No offset needed)
// "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"