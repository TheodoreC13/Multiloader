CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Werror -Wpedantic -Wshadow -Wconversion -pthread
MINGW_CC = x86_64-w64-mingw32-gcc
ELF32_CC = gcc -m32
SRC = Multiloader.c 
OBJ = $(SRC:.c=.o)
OUT = loader

HELLO_SRC = hello.c
HELLO_ELF32 = hello_elf32
HELLO_PE = hello_win.exe

.PHONY: all clean

all: $(OUT) $(HELLO_ELF32) $(HELLO_PE)

$(OUT): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(HELLO_ELF32): $(HELLO_SRC)
	$(ELF32_CC) -o $@ $<
$(HELLO_PE): $(HELLO_SRC)
	$(MINGW_CC) -o $@ $<
clean:
	rm -f $(OUT) $(OBJ) $(HELLO_ELF32) $(HELLO_PE)
