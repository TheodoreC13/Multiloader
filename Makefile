CC = gcc
Cflags = -std=c99 -Wall -Wextra -Werror -Wpendantic -Wshadow -Wconversion
SRC = Multiloader.c
OUT = loader

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC)
clean:
	rm -f $(OUT)
