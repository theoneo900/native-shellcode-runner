# native-shellcode-runner

Stealthy Shellcode runner written in C, simulating OS operations to avoid getting detected by defense mechanisms. The project is a poc for educational purposes, any malicious use of this code is your own responsibility and I strongly advise against it / Dont use it for malicious purposes. 

There are two C code files:

- shellcoderunner.c
    A shell code runner that the shellcode is hardcoded in the script uses xor to decrypt the shellcode, allocates memory, writes the shellcode there, switches permissions from rw to re and then using function pointer casting calls the function pointer and runs the shellcode.

- fileoperations.c 
    The same as above but instead of hardcoding the shellcode i use a payload.bin file to read the payload from and in that bin file the last byte is the key to xor it with (not that xor is hard to bruteforce but i wanted to practise)
