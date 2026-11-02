/* Test-only Darwin resolver stalls. Never linked into Layerline. */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void entered(const char *name) {
    int fd = open(RESOLVER_TEST_LOG, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) _exit(91);
    char line[512];
    int size = snprintf(line, sizeof(line), "%d %d %s\n", getpid(), getppid(), name);
    if (size <= 0 || size >= (int)sizeof(line) || write(fd, line, size) != size) _exit(92);
    close(fd);
}

static int test_getaddrinfo(const char *name, const char *service,
                            const struct addrinfo *hints, struct addrinfo **result) {
    if (!name || !strstr(name, ".resolver.test")) return getaddrinfo(name, service, hints, result);
    entered(name);
    if (!strcmp(name, "exit.resolver.test")) _exit(42);
    if (!strcmp(name, "unknown.resolver.test")) return EAI_NONAME;
    long ms = !strcmp(name, "slow.resolver.test") ? 4000 :
              !strcmp(name, "combined.resolver.test") ? 140 :
              !strcmp(name, "cancel.resolver.test") ? 20000 : 0;
    struct timespec delay = {ms / 1000, ms % 1000 * 1000000};
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
    return getaddrinfo("127.0.0.1", service, hints, result);
}

static int test_posix_spawn(pid_t *pid, const char *path,
                             const posix_spawn_file_actions_t *actions,
                             const posix_spawnattr_t *attributes,
                             char *const argv[], char *const env[]) {
    if (argv && argv[0] && argv[1] && !strcmp(argv[1], "--layerline-resolver-v1")) {
        /* Production deliberately gives helpers an empty environment. Inject
           only inside this fixture, so the child can really block in libc. */
        char *test_env[] = {"DYLD_INSERT_LIBRARIES=" RESOLVER_TEST_DYLIB, NULL};
        return posix_spawn(pid, path, actions, attributes, argv, test_env);
    }
    return posix_spawn(pid, path, actions, attributes, argv, env);
}

#define INTERPOSE(replacement, original) \
    __attribute__((used)) static const struct { const void *new; const void *old; } \
    interpose_##original __attribute__((section("__DATA,__interpose"))) = \
        {(const void *)&replacement, (const void *)&original}

INTERPOSE(test_getaddrinfo, getaddrinfo);
INTERPOSE(test_posix_spawn, posix_spawn);
