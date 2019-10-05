#include "parameter.h"
#include "pke.h"
#include "poly.h"
#include <stdio.h>
#include <time.h>

#define NTESTS 10000

int main() {
    unsigned char pk[PKE_PUBLICKEYBYTES];
    unsigned char sk[PKE_SECRETKEYBYTES];
    unsigned long long pklen;
    unsigned long long sklen;
    unsigned char m[128];
    unsigned char c[2048];
    
    clock_t start, finish;
    double total_time;
    start = clock();
    for (int i = 0; i < NTESTS; i++) {
        pke_keygen(pk, &pklen, sk, &sklen);
    }
    finish = clock();
    total_time = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("keygen %f us\n", (total_time * 1000000 / NTESTS));
    
    pke_keygen(pk, &pklen, sk, &sklen);
    start = clock();
    for (int i = 0; i < NTESTS; i++) {
        pke_enc(pk, PKE_PUBLICKEYBYTES, m, PKE_MESS_BYTES, c, PKE_CIP_BYTES);
    }
    finish = clock();
    total_time = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("enc %f us\n", (total_time * 1000000 / NTESTS));
    return 0;
}

// I love zeze
