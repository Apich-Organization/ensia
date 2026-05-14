#include <stdio.h>
#include <stdlib.h>

int core_logic(int input) {
    int result = 0;
    if (input % 2 == 0) {
        result = input * 3;
    } else {
        result = input + 7;
    }

    for (int i = 0; i < 5; i++) {
        result ^= (i + input);
        if (result > 100) {
            result -= 10;
        } else {
            result += 5;
        }
    }

    return result;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <number>\n", argv[0]);
        return 1;
    }

    int val = atoi(argv[1]);
    int output = core_logic(val);

    printf("Input: %d, Result: %d\n", val, output);
    return 0;
}
