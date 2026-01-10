# Compiler to use
CC = gcc

# Flags:
# -Wall: Show all warnings (good coding)
# -fvisibility=hidden: Hide symbols by default (Stealth!)
# -static: Bundle everything into one binary (No dependencies)
CFLAGS = -Wall -fvisibility=hidden

# The Target Binary Name
TARGET = loader

# Source files (Wildcard picks up all .c files in root and modules)
SRCS = main.c $(wildcard modules/*.c)

# Build Rule
all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)
	@echo "[*] Compiling finished."
	@echo "[*] Stripping symbols for stealth..."
	strip --strip-all $(TARGET)
	@echo "[+] Build Complete: ./$(TARGET)"

clean:
	rm -f $(TARGET)