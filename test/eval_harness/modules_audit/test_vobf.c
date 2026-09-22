#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
int vobf_int_calc(int a, int b) {
    int c = a + b;
    int d = c ^ 0x55AA55AA;
    int e = d * 13;
    int f = (e >> 3) & 0x00FFFFFF;
    int g = (f << 2) | (f >> 30);
    int h = (g > 1000) ? (g - 500) : (g + 500);
    return h;
}

__attribute__((noinline))
float vobf_float_calc(float x, float y) {
    float a = x + y;
    float b = a * 2.5f;
    float c = b - 1.25f;
    return c;
}

int main(int argc, char **argv) {
    int seed = (argc > 1) ? atoi(argv[1]) : 12345;
    int ri = vobf_int_calc(seed, 67890);
    float rf = vobf_float_calc((float)seed * 0.1f, 4.5f);
    printf("VOBF Results: int=%08X, float=%.2f\n", ri, rf);
    return 0;
}
