# Encrypted File Vault Daemon

Small C daemon that stores files encrypted (ChaCha20-Poly1305) and serves them over TCP.

## Build / run

    make            # builds ./vaultd
    make key        # creates vault.key (32 random bytes, mode 0600)
    make dirs       # creates vault_storage/ and vault_jail/
    make test       # crypto self-test + end-to-end tests
    ./vaultd        # 127.0.0.1:8080

Options: `-b addr -p port -s storage_dir -k keyfile -j jail_dir -u uid -g gid`

As root it chroots into the (empty) jail dir and drops to uid/gid 65534.
As a normal user it skips that step and says so. Back up `vault.key`: without it the data is unrecoverable.

## Protocol (one request per connection)

    PUT <name> <len>\n<len bytes>   ->  OK\n
    GET <name>\n                    ->  OK <len>\n<bytes>
    DEL <name>\n                    ->  OK\n
    errors                          ->  ERR <reason>\n

Quick try:

    printf 'PUT hello.txt 5\nhello' | nc 127.0.0.1 8080
    printf 'GET hello.txt\n'        | nc 127.0.0.1 8080

Names: 1-64 chars of `A-Z a-z 0-9 . _ -`, not starting with `.`. Max file size 1 MiB.

## Layout

    src/main.c      startup, signals, chroot + privilege drop, accept loop
    src/network.c   TCP listener + protocol parsing, timeouts
    src/vault.c     key loading, encrypt/decrypt, on-disk format
    src/storage.c   safe file I/O (openat on a pre-opened dir fd, atomic writes)
    src/crypt.c     ChaCha20, Poly1305, AEAD (RFC 8439)
    tests/          crypto self-test, integration.py

On-disk format: `"VLT1" | nonce(12) | ciphertext | tag(16)`. The name is authenticated, so blobs can't be swapped between names.

## Known limits

- One client at a time; plain TCP with no authentication. Keep it on localhost or behind a tunnel/firewall.
- Single master key for all files; no key rotation.
