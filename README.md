# native-shellcode-runner

Stealthy Shellcode runner written in C, simulating OS operations to avoid getting detected by defense mechanisms. The project is a poc for educational purposes, any malicious use of this code is your own responsibility and I strongly advise against it / Dont use it for malicious purposes. 

There are two C code files:

- shellcoderunner.c
    A shell code runner that the shellcode is hardcoded in the script uses xor to decrypt the shellcode, allocates memory, writes the shellcode there, switches permissions from rw to re and then using function pointer casting calls the function pointer and runs the shellcode.

- fileoperations.c 
    The same as above but instead of hardcoding the shellcode i use a payload.bin file to read the payload from and in that bin file the last byte is the key to xor it with (not that xor is hard to bruteforce but i wanted to practise)


To Do:

* Path 1: The "Ghost" (Stealth & Anti-Forensics)Focus: Making your loader invisible to security tools and analysts (like yourself using GDB).Network Loading ("Fileless"):The Upgrade: Instead of fopen, use C Sockets to download the encrypted bytes from a Python server directly into RAM.Why: It leaves no trace on the hard drive.Concept:Anti-Debugging:The Upgrade: Add code that detects if GDB is watching. A simple trick is ptrace(PTRACE_TRACEME, 0, 1, 0). If it fails, a debugger is already attached $\rightarrow$ exit().Why: It forces you to learn how Linux tracks processes.String Obfuscation:The Upgrade: Right now, if you run strings your_loader, you see "payload.bin". You should XOR-encrypt your file names and error messages at compile time and decrypt them only when needed.

* Path 2: The "Parasite" (Process Injection)Focus: Instead of running the shellcode inside your own process, inject it into a legitimate process (like chrome or notepad).The Upgrade: Use the ptrace system call to pause another running process, write your shellcode into its memory, and force its instruction pointer (RIP) to jump to your code.The Potential: This is how advanced tools survive. Even if your loader closes, the shellcode lives on inside the victim process.

* Path 3: The "Cryptographer" (Advanced Encoding)Focus: Moving beyond simple XOR to robust encryption.The Upgrade: Implement AES-128 or RC4 decryption in C.The Challenge: You cannot easily use libraries like openssl (because they make your binary huge and suspicious). You have to find a "tiny AES" implementation in C (usually 1 header file) and compile it directly into your loader.Why: XOR is easy to break statistically. AES is military-grade.
