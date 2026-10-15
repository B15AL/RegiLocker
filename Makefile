CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong -fPIE -pie -O2 -D_FORTIFY_SOURCE=2 -Iinclude
LDFLAGS = -lcrypto

SRC = src/main.c src/network.c src/storage.c src/encrypt/crypt.c
OBJ = $(SRC:.c=.o)
TARGET = secure_vault_daemon

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o src/encrypt/*.o $(TARGET)

.PHONY: all clean
