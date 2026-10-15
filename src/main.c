#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "network.h"
#include "storage.h"
#include "vault.h"

static volatile sig_atomic_t running = 1;
static void on_signal(int sig) { (void)sig; running = 0; }

/* Jail + drop privileges. Only possible as root; everything needed from the
 * filesystem (storage dir fd, key, listening socket) is opened BEFORE this. */
static void secure_daemon_init(const char *jail, uid_t uid, gid_t gid) {
    if (geteuid() != 0) {
        fprintf(stderr, "[!] Not running as root: skipping chroot/setuid (fine for development)\n");
        return;
    }
    if (chroot(jail) != 0 || chdir("/") != 0) { perror("chroot"); exit(EXIT_FAILURE); }

    /* Order matters: supplementary groups, then gid, then uid. */
    if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0) {
        perror("drop privileges"); exit(EXIT_FAILURE);
    }
    if (setuid(0) == 0) {                       /* must NOT be able to regain root */
        fprintf(stderr, "CRITICAL: privilege drop failed\n"); exit(EXIT_FAILURE);
    }
}

static void usage(const char *p) {
    fprintf(stderr,
        "usage: %s [-b addr] [-p port] [-s storage_dir] [-k keyfile] [-j jail_dir] [-u uid] [-g gid]\n"
        "  defaults: -b 127.0.0.1 -p 8080 -s ./vault_storage -k ./vault.key -j ./vault_jail -u 65534 -g 65534\n", p);
}

int main(int argc, char **argv) {
    const char *addr = "127.0.0.1", *store = "./vault_storage", *keyf = "./vault.key", *jail = "./vault_jail";
    int port = 8080, opt;
    uid_t uid = 65534; gid_t gid = 65534;

    while ((opt = getopt(argc, argv, "b:p:s:k:j:u:g:h")) != -1) {
        switch (opt) {
        case 'b': addr = optarg; break;
        case 'p': port = atoi(optarg); break;
        case 's': store = optarg; break;
        case 'k': keyf = optarg; break;
        case 'j': jail = optarg; break;
        case 'u': uid = (uid_t)atoi(optarg); break;
        case 'g': gid = (gid_t)atoi(optarg); break;
        default:  usage(argv[0]); return 2;
        }
    }
    if (port < 1 || port > 65535) { usage(argv[0]); return 2; }

    printf("[*] Starting Secure Encrypted File Vault Daemon...\n");
    umask(077);                                             /* files we create are owner-only */
    signal(SIGPIPE, SIG_IGN);
    struct rlimit nocore = {0, 0};
    setrlimit(RLIMIT_CORE, &nocore);                        /* a core dump would contain the key */

    struct sigaction sa = {0};
    sa.sa_handler = on_signal;                              /* no SA_RESTART: accept() returns on signal */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (storage_init(store) != 0) { perror("storage dir"); return 1; }
    if (vault_load_key(keyf) != 0) {
        fprintf(stderr, "key file '%s': %s (need exactly 32 bytes, mode 0600; try: make key)\n", keyf, strerror(errno));
        return 1;
    }
    int server_fd = network_listen(addr, port);
    if (server_fd < 0) { perror("listen"); return 1; }

    secure_daemon_init(jail, uid, gid);
    printf("[*] Listening on %s:%d as uid %d\n", addr, port, (int)getuid());

    while (running) {
        int client = accept(server_fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        network_handle_client(client);
        close(client);
    }

    close(server_fd);
    printf("[*] Shut down cleanly\n");
    return 0;
}
