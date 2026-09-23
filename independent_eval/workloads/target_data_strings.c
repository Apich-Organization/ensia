#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Static string buffers for testing StringEncryption & AntiDump
static const char *g_banner = "=== ENSIA SECURE SECURITY GATEWAY v2.4 ===";
static const char *g_prompt = "Enter authentication token: ";
static const char *g_secret_salt = "SALT_K9x_#88419!mZ";
static const char *g_success = "AUTHENTICATION_GRANTED_LEVEL_9";
static const char *g_failure = "ACCESS_DENIED_VIOLATION_LOGGED";

// Returns pointer to static string for anti-dump inspection
const char *get_secret_salt(void) {
    return g_secret_salt;
}

int check_token(const char *input) {
    char combined[128];
    snprintf(combined, sizeof(combined), "%s%s", input, g_secret_salt);

    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; combined[i]; i++) {
        hash ^= (uint8_t)combined[i];
        hash *= 0x01000193;
    }

    if (hash == 0x7c8e2b10) {
        printf("%s\n", g_success);
        return 0;
    } else {
        printf("%s\n", g_failure);
        return 1;
    }
}

int main(int argc, char **argv) {
    printf("%s\n", g_banner);
    const char *tok = (argc > 1) ? argv[1] : "default_token_val";
    return check_token(tok);
}
