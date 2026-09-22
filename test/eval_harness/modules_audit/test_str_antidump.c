#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *saved_internal_ptr = NULL;

__attribute__((noinline))
void use_internal_string(int flag) {
    const char *sensitive_token = "ANTIDUMP_SECRET_TOKEN_492817";
    saved_internal_ptr = sensitive_token;
    if (flag) {
        printf("Internal string in use: %s\n", sensitive_token);
    }
}

__attribute__((noinline))
const char* get_returned_string(void) {
    const char *ret_token = "PERSISTENT_RETURNED_STRING_998877";
    return ret_token;
}

int main(int argc, char **argv) {
    // Call 1
    use_internal_string(1);
    
    // Check if the memory pointed to by saved_internal_ptr is wiped!
    printf("After use_internal_string exit, internal buffer points to: '");
    for (int i = 0; i < 28; i++) {
        char c = saved_internal_ptr[i];
        if (c >= 32 && c <= 126) putchar(c);
        else printf("\\x%02X", (unsigned char)c);
    }
    printf("'\n");

    // Call 2: verify function can be safely re-entered and re-decrypts correctly
    use_internal_string(1);

    // Call 3: verify returned string is NOT wiped and still valid
    const char *ret = get_returned_string();
    printf("Returned string: %s\n", ret);

    return 0;
}
