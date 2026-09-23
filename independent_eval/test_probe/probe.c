#include <stdio.h>
int calc(int a, int b) {
    int c = a + b;
    int d = c ^ 0x12345678;
    return d * 3;
}
int main() {
    printf("Result: %d\n", calc(10, 20));
    return 0;
}
