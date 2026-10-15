#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pwd.h>
#include <errno.h>

#define PORT 8080
#define JAIL_DIR "./vault_jail"

/**
 * Drops privileges and jails the process for defense-in-depth.
 */
void secure_daemon_init() {
    // 1. Change root to an empty jail directory (defense against file system escapes)
    // Note: Ensure JAIL_DIR and ./vault_storage exist prior to running.
    if (chroot(JAIL_DIR) != 0) {
        perror("chroot failed");
        // Depending on strictness, exit or handle error
    }
    
    if (chdir("/") != 0) {
        perror("chdir to jail root failed");
        exit(EXIT_FAILURE);
    }

    // 2. Drop privileges from root to a non-root user (e.g., UID 1000)
    if (setuid(1000) != 0) {
        perror("Failed to drop privileges (setuid)");
        exit(EXIT_FAILURE);
    }
    
    // Verify privilege drop
    if (getuid() == 0) {
        fprintf(stderr, "CRITICAL: Failed to drop root privileges!\n");
        exit(EXIT_FAILURE);
    }
}

int main(void) {
    printf("[*] Starting Secure Encrypted File Vault Daemon...\n");

    // Server socket setup (bind typically requires root if port < 1024, or standard unprivileged port like 8080)
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    // Drop privileges after binding if using a privileged port, or call early
    secure_daemon_init();
    printf("[*] Daemon secured, chrooted, and running as UID: %d\n", getuid());

    // Main Event Loop
    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }

        // Handle client connection using your network/storage/crypto pipeline here
        // e.g., read request, sanitize, decrypt/encrypt, save/retrieve, respond, close.
        
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
