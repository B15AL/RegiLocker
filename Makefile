CC      ?= gcc
CFLAGS  ?= -std=gnu11 -O2 -Wall -Wextra -Wshadow -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now
SRC     := src/main.c src/network.c src/storage.c src/vault.c src/crypt.c

all: vaultd

vaultd: $(SRC) $(wildcard src/*.h)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

key:
	@test -e vault.key && echo "vault.key already exists, not overwriting" || \
	  (umask 077; head -c 32 /dev/urandom > vault.key; echo "created vault.key")

dirs:
	mkdir -p vault_storage vault_jail

test: tests/test_crypt.c src/crypt.c
	$(CC) $(CFLAGS) tests/test_crypt.c src/crypt.c -o tests/test_crypt $(LDFLAGS)
	./tests/test_crypt > /dev/null && echo "crypt self-test: OK"
	python3 tests/integration.py

clean:
	rm -f vaultd tests/test_crypt *.o src/*.o

.PHONY: all key dirs test clean
