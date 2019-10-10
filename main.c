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
    unsigned char m[128] = "Here's a test message of length 128 bytes. If you can see these words, the encryption and decryption algorithms are successful.";
    unsigned char c[2048];
    unsigned long long mlen = PKE_MESS_BYTES;
    unsigned long long clen = PKE_CIP_BYTES;

    // clock_t start, finish;
    // double total_time;


    // start = clock();
    // for (int i = 0; i < NTESTS; i++) {
    //     pke_keygen(pk, &pklen, sk, &sklen);
    // }
    // finish = clock();
    // total_time = (double)(finish - start) / CLOCKS_PER_SEC;
    // printf("keygen %f us\n", (total_time * 1000000 / NTESTS));
    
    // pke_keygen(pk, &pklen, sk, &sklen);
    // start = clock();
    // for (int i = 0; i < NTESTS; i++) {
    //     pke_enc(pk, PKE_PUBLICKEYBYTES, m, PKE_MESS_BYTES, c, &clen);
    // }
    // finish = clock();
    // total_time = (double)(finish - start) / CLOCKS_PER_SEC;
    // printf("enc %f us\n", (total_time * 1000000 / NTESTS));

    // pke_keygen(pk, &pklen, sk, &sklen);
    // pke_enc(pk, PKE_PUBLICKEYBYTES, m, PKE_MESS_BYTES, c, &clen);
    // start = clock();
    // for (int i = 0; i < NTESTS; i++) {
    //     pke_dec(sk, PKE_SECRETKEYBYTES, c, clen, m, &mlen);
    // }
    // finish = clock();
    // total_time = (double)(finish - start) / CLOCKS_PER_SEC;
    // printf("dec %f us\n", (total_time * 1000000 / NTESTS));

    pke_keygen(pk, &pklen, sk, &sklen);
    pke_enc(pk, pklen, m, PKE_MESS_BYTES, c, &clen);
    pke_dec(sk, sklen, c, clen, m, &mlen);
    printf("%s\n", m);

    return 0;
}

