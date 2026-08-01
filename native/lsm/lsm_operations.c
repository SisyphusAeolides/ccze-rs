#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int open_status(pid_t pid, FILE **file)
{
    char path[64];
    int length = snprintf(path, sizeof(path), "/proc/%d/status", pid);

    if (length < 0 || (size_t)length >= sizeof(path)) {
        return -ENAMETOOLONG;
    }
    *file = fopen(path, "r");
    return *file == NULL ? -errno : 0;
}

int32_t ccze_lsm_has_capability(pid_t pid, uint32_t capability)
{
    FILE *file;
    char line[4096];
    uint64_t capabilities;
    int result;

    if (capability >= 64) {
        return -EINVAL;
    }
    result = open_status(pid, &file);
    if (result < 0) {
        return result;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if ((strncmp(line, "CapEff:", 7) == 0 || strncmp(line, "CapPrm:", 7) == 0) &&
            sscanf(line + 7, "%" SCNx64, &capabilities) == 1) {
            fclose(file);
            return (capabilities & (UINT64_C(1) << capability)) != 0;
        }
    }
    fclose(file);
    return 0;
}

int32_t ccze_lsm_get_capabilities(pid_t pid, char *buffer, size_t buffer_size)
{
    static const char *const names[] = {
        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
        "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
        "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
        "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
        "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
        "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
        "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
        "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE"
    };
    FILE *file;
    char line[4096];
    uint64_t capabilities;
    size_t capability;
    size_t written = 0;
    int result;

    if (buffer == NULL || buffer_size == 0) {
        return -EINVAL;
    }
    buffer[0] = '\0';
    result = open_status(pid, &file);
    if (result < 0) {
        return result;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (strncmp(line, "CapEff:", 7) != 0 ||
            sscanf(line + 7, "%" SCNx64, &capabilities) != 1) {
            continue;
        }
        for (capability = 0; capability < sizeof(names) / sizeof(names[0]); capability++) {
            size_t name_length;

            if ((capabilities & (UINT64_C(1) << capability)) == 0) {
                continue;
            }
            name_length = strlen(names[capability]);
            if (written + name_length + 2 >= buffer_size) {
                fclose(file);
                return -ENOSPC;
            }
            memcpy(buffer + written, names[capability], name_length);
            written += name_length;
            buffer[written++] = ',';
            buffer[written++] = ' ';
        }
        if (written >= 2) {
            written -= 2;
        }
        buffer[written] = '\0';
        fclose(file);
        return (int32_t)written;
    }
    fclose(file);
    return 0;
}

int32_t ccze_lsm_drop_capability(pid_t pid, uint32_t capability)
{
    (void)pid;
    (void)capability;
    return -EPERM;
}

int32_t ccze_lsm_check_support(void)
{
    FILE *file;
    char release[256];
    char path[512];
    char line[4096];

    if (access("/sys/kernel/security/lsm", R_OK) == 0) {
        return 1;
    }
    file = fopen("/proc/sys/kernel/osrelease", "r");
    if (file == NULL || fgets(release, sizeof(release), file) == NULL) {
        if (file != NULL) {
            fclose(file);
        }
        return 0;
    }
    fclose(file);
    release[strcspn(release, "\r\n")] = '\0';
    if (snprintf(path, sizeof(path), "/boot/config-%s", release) >= (int)sizeof(path)) {
        return 0;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strncmp(line, "CONFIG_LSM=", 11) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}
