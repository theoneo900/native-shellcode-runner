#include <stdio.h>
#include "modules/anti_debug.h"

int main() {
    printf("[*] Loader starting...\n");

    // Phase 1 check
    if (check_debugger()) {
        printf("[!] Debugger detected! Self-destructing.\n");
        return 1;
    }

    printf("[+] Environment seems clean. Proceeding...\n");
    
    // Future: network_load();
    // Future: decrypt();
    // Future: execute();

    return 0;
}