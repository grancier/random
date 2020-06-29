#include <sys/types.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include "chacha.h"

void genrand(uint8_t *buff)
{
    __uint128_t store[32];

    int i,j,k;
    u_int32_t val;

    for (i = 0; i < 32; i++) {
        store[i] = 0;
        arc4random(&val);
        for (j = 0; j < 3; j++) {
            store[i] ^= val;
            store[i] <<= 32;
            arc4random(&val);
        }
        store[i] ^= val;
    }

    for (i = 0; i < 32; i++) {
        for(k = 0; k < 16; k++) {
            buff[(i * 16) + k] = store[i] >> (k * 8);
        }
    }
}

int main() {
    uint8_t *buff = (uint8_t *)malloc(512 * sizeof(uint8_t));
    int i,j,k;

    int candidate_pool[70] = { 
                               1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 
                              14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                              27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                              40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                              53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
                              66, 67, 68, 69, 70
                            };

    genrand(buff);
    k = 0;
    for (i = 0; i < 5; i++) {
        printf("%i ", candidate_pool[buff[k] % 70]);
        candidate_pool[buff[k++] % 70] = 0;
        while (candidate_pool[buff[k] % 70] == 0) {
            k++;  
        }
    }
    
    printf("\n");
    

    free(buff);
    return 0;
}