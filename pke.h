//
//  pke.h
//  c
//

//

#ifndef pke_h
#define pke_h
#include <stdio.h>

unsigned long long pke_get_pk_byts();

unsigned long long pke_get_sk_byts();

unsigned long long pke_get_ct_byts();

int pke_keygen(unsigned char *pk, unsigned long long *pklen, unsigned char *sk,
               unsigned long long *sklen);

int pke_enc(unsigned char *pk, unsigned long long pklen, unsigned char *m,
            unsigned long long mlen, unsigned char *c,
            unsigned long long *clen);

int pke_dec(unsigned char *sk, unsigned long long sklen, unsigned char *c,
            unsigned long long clen, unsigned char *m,
            unsigned long long *mlen);

int pke_enc_with_param_fixed(unsigned char *pk, unsigned long long pklen,
                             unsigned char *m, unsigned long long mlen,
                             unsigned char *rand, unsigned long long randbyts,
                             unsigned char *c, unsigned long long *clen);

int pke_dec_with_param_fixed(unsigned char *sk, unsigned long long sklen,
                             unsigned char *c, unsigned long long clen,
                             unsigned char *m, unsigned long long *mlen);

#endif /* pke_h */
