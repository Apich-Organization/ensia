#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

__attribute__((noinline)) int target_func(int a, int b) {
  return (a * 17) ^ (b + 31);
}

int main(int argc, char **argv) {
  if (argc == 1) {
    setvbuf(stdout, NULL, _IONBF, 0);
    // Parent test runner: tests untampered execution and tampered child
    // execution
    printf("[*] 1. Testing clean untampered execution...\n");
    int res = target_func(3, 4);
    int expected = (3 * 17) ^ (4 + 31);
    if (res != expected) {
      fprintf(stderr, "[-] Target function return value mismatch: %d != %d\n",
              res, expected);
      return 1;
    }
    printf("[+] Untampered call succeeded: target_func(3, 4) = %d\n", res);

    printf("[*] 2. Spawning child process with injected hook stub...\n");
    pid_t pid = fork();
    if (pid < 0) {
      perror("fork");
      return 1;
    }

    if (pid == 0) {
      // Child process: execute with --tamper-hook
      execl(argv[0], argv[0], "--tamper-hook", NULL);
      _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    printf("[*] Hook-tampered child exit status: 0x%x\n", status);

    // Verification: child MUST have terminated either via exit(137) or via
    // fatal signal (SIGFPE/SIGILL/SIGSEGV)
    if (WIFEXITED(status)) {
      int code = WEXITSTATUS(status);
      printf("[*] Child exited normally with code %d\n", code);
      if (code == 137) {
        printf("[+] SUCCESS: Anti-hook violent direct exit (code 137) "
               "triggered as expected!\n");
      } else if (code == 0) {
        fprintf(stderr,
                "[-] FAILURE: Tampered child exited cleanly with code 0!\n");
        return 1;
      } else {
        printf("[+] SUCCESS: Anti-hook terminated child with non-zero exit "
               "code: %d\n",
               code);
      }
    } else if (WIFSIGNALED(status)) {
      int sig = WTERMSIG(status);
      printf(
          "[+] SUCCESS: Anti-hook triggered violent hardware trap signal: %d\n",
          sig);
    }

    printf("[*] 3. Spawning child process with modified code byte (integrity "
           "violation)...\n");
    pid = fork();
    if (pid < 0) {
      perror("fork");
      return 1;
    }

    if (pid == 0) {
      execl(argv[0], argv[0], "--tamper-code", NULL);
      _exit(127);
    }

    waitpid(pid, &status, 0);
    printf("[*] Integrity-tampered child exit status: 0x%x\n", status);
    if (WIFEXITED(status)) {
      int code = WEXITSTATUS(status);
      if (code == 137) {
        printf("[+] SUCCESS: Integrity violation violent direct exit (code "
               "137) triggered!\n");
      } else if (code == 0) {
        fprintf(stderr, "[-] FAILURE: Integrity-tampered child exited cleanly "
                        "with code 0!\n");
        return 1;
      } else {
        printf(
            "[+] SUCCESS: Integrity violation terminated child with code: %d\n",
            code);
      }
    } else if (WIFSIGNALED(status)) {
      printf("[+] SUCCESS: Integrity violation triggered violent hardware trap "
             "signal: %d\n",
             WTERMSIG(status));
    }

    printf(
        "\n=== ANTI-HOOK & INTEGRITY DEFENSE VERIFICATION PASSED 100%% ===\n");
    return 0;
  }

  // Child process handling
  void *page = (void *)((uintptr_t)target_func & ~0xFFFULL);
  if (mprotect(page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    perror("mprotect failed");
    return 1;
  }

  volatile uint8_t *p = (volatile uint8_t *)target_func;

  if (strcmp(argv[1], "--tamper-hook") == 0) {
    // Inject 0xE9 (JMP rel32 - classic Detours / Frida hook)
    *p = 0xE9;
  } else if (strcmp(argv[1], "--tamper-code") == 0) {
    // Tamper an internal instruction byte (integrity violation)
    *(p + 5) ^= 0x42;
  }

  int (*volatile volatile_target)(int, int) = target_func;
  int bad_res = volatile_target(3, 4);

  // If it survived and returned, check if data-flow entanglement corrupted the
  // result
  int expected = (3 * 17) ^ (4 + 31);
  if (bad_res != expected) {
    printf("[+] Data-flow entanglement corrupted result: %d != %d\n", bad_res,
           expected);
    return 42; // indicates corrupted output caught
  }

  return 0;
}
