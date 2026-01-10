#include <sys/ptrace.h>
#include <stdio.h>
#include "anti_debug.h"

int check_debugger() {
    // TRICK 1: Ptrace Traceme
    // A process can only be ptraced by ONE thing at a time.
    // If GDB is attached, this call will FAIL (-1).
    // If we are free, this call succeeds (0).
    
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return 1; // Debugger found!
    }
    
    return 0; // Clean
}