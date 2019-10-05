//
//  pke.c
//  c
//

//
#include "pke.h"
#include "fips202.h"
#include "parameter.h"
#include "poly.h"
#include "rng.h"
#include <openssl/rand.h>
#include <stdint.h>
#include <string.h>

unsigned long long pke_get_pk_byts() { return PKE_PUBLICKEYBYTES; }

unsigned long long pke_get_sk_byts() { return PKE_SECRETKEYBYTES; }

unsigned long long pke_get_ct_byts() { return PKE_CIP_BYTES; }

// int16_t Remain(uint16_t a) {
//     int16_t b;

//     b = a - Q + (((a > (Q - 1) / 2) - 1) & Q);

//     b += ((Q - 1) / 2) - (((b < -(Q - 1) / 4) - 1) & ((Q - 1) / 2));
    
//     b -= ((Q + 1) / 2) - (((b > (Q - 1) / 4) - 1) & ((Q + 1) / 2));

//     return b;
// }

/*-------------------key generation--------------------
 sprime, e_0 are sampled from the central binomial distribution
 a is sampled with the seed
 s=2sprime+1
 b=as+2e_0
 pk=b|seed
 sk=s
-----------------------------------------------------*/

int pke_keygen(unsigned char *pk, unsigned long long *pointer_pklen,
               unsigned char *sk, unsigned long long *pointer_sklen) {
    uint16_t sprime[N], s[N], e_0[N], bhat[N], s_ahat[N], a[N];
    unsigned char seed[PKE_SEED_BYTES], seed1[PKE_SEED_BYTES], seed2[N];
    int i;
    // RAND_bytes(seed1, SEED_BYTES);
    // shake256(seed, 2*SEED_BYTES,seed1, SEED_BYTES);

    /*for(i=0;i<SEED_BYTES;i++)
    { seed1[i]=seed[i];
      seed2[i]=seed[i+SEED_BYTES];

    }
    */
    //  FILE *fpt;
    // fpt = fopen("随机数.txt","a");
    RAND_bytes(seed1, PKE_SEED_BYTES);

    //  fprintf(fpt,"\n");
    // fprintf(fpt,"随机数=[");
    // for(i=0;i<PKE_SEED_BYTES;i++)
    // fprintf(fpt,"%x",seed1[i]);
    // fprintf(fpt,"]");
    //  fclose(fpt);

    shake256(seed, PKE_SEED_BYTES, seed1, PKE_SEED_BYTES);
    poly_gen_a(a, seed);

    // printf("a in key generation is \n");
    // for(i=0;i<N;i++)
    // printf("%d,",a[i]);
    // printf("\n");

    /*中心二项分布采样k=2*/
    RAND_bytes(seed2, N);
    shake256(seed2, N, seed2, N);
    for (i = 0; i < N; i++) {
        sprime[i] = ((seed2[i / 8] >> (i % 8)) & 1) -
                    ((seed2[i / 8 + N / 8] >> (i % 8)) & 1) +
                    ((seed2[i / 8 + N / 4] >> (i % 8)) & 1) -
                    ((seed2[i / 8 + 3 * N / 8] >> (i % 8)) & 1) + Q;
        s[i] = (2 * sprime[i]) % Q;
        e_0[i] = ((seed2[i / 8 + N / 2] >> (i % 8)) & 1) -
                 ((seed2[i / 8 + 5 * N / 8] >> (i % 8)) & 1) +
                 ((seed2[i / 8 + 3 * N / 4] >> (i % 8)) & 1) -
                 ((seed2[i / 8 + 7 * N / 8] >> (i % 8)) & 1) * 2 % Q;
    }
    s[0] = (s[0] + 1) % Q;

    // printf("a in key generation is \n");
    // for(i=0;i<N;i++)
    // printf("%d,",a[i]);
    // printf("\n");

    // cbd(sprime,seed2,0);
    // cbd(e_0,seed2,1);

    for (i = 0; i < N; i++) {
        if (sprime[i] > 2)
            sprime[i] = sprime[i] - Q + 2;
        else
            sprime[i] = sprime[i] + 2;
    }

    poly_tobyte_s(sk, sprime);

    poly_ntt(s);
    poly_pointwise(s_ahat, a, s);
    poly_ntt(e_0);
    poly_add(bhat, s_ahat, e_0); // in ntt domain

    poly_tobyte(pk, bhat);
    for (i = 0; i < PKE_SEED_BYTES; i++)
        pk[PKE_POLY_BYTES + i] = seed[i];

    // poly_tobyte(sk,s);

    // FILE *fpt;
    // fopen_s(&fpt, "info.dat", "wb+");
    // int64_t nounce[N];

    // uint32_t arr[7] = {
    //     PKE_PUBLICKEYBYTES, PKE_SECRETKEYBYTES, PKE_MESS_BYTES, PKE_MESS_BYTES,
    //     PKE_CIP_BYTES,      PKE_CIP_BYTES,      RAND_BTS};

    // fwrite(arr, sizeof(arr), 1, fpt);
    // fwrite(pk, PKE_PUBLICKEYBYTES, 1, fpt);
    // fwrite(sk, PKE_SECRETKEYBYTES, 1, fpt);
    // fclose(fpt);

    return 0; // success
}

/*----------------------encryption------------------------------------
 r,e,e_r are sampled from central binomial distribution
 c_0=ar+2e;
 c=br+2e_r;
 mm=(mm+alpha)%2
 c_1=(c_0+mm)%Q

 ---------------------------------------------------------------------*/

int pke_enc(unsigned char *pk, unsigned long long pklen, unsigned char *m,
            unsigned long long mlen, unsigned char *c,
            unsigned long long *pointer_clen) {
    uint16_t r[N], e[N], e_r[N], c_0[N], c_1[N], c_2[N], c_3[N];
    uint16_t ar[N], a[N], br[N], mm[N], bb[N], alpha[N];
    int16_t c_4[N], tmp;
    unsigned char seed[PKE_SEED_BYTES], b[PKE_POLY_BYTES]; 
    unsigned char seed1[3 * N / 2], rand[RAND_BTS];
    int i;
    for (i = 0; i < PKE_SEED_BYTES; i++)
        seed[i] = pk[PKE_POLY_BYTES + i];

    poly_gen_a(a, seed);
    // unsigned char seed1[SEED_BYTES];
    // RAND_bytes(seed1, SEED_BYTES);
    // shake256(seed1, SEED_BYTES,seed1, SEED_BYTES);

    RAND_bytes(seed1, 3 * N / 2);
    shake256(seed1, 3 * N / 2, seed1, 3 * N / 2);
    for (i = 0; i < N; i++) {
        r[i] = ((seed1[i / 8] >> (i % 8)) & 1) -
               ((seed1[i / 8 + N / 8] >> (i % 8)) & 1) +
               ((seed1[i / 8 + N / 4] >> (i % 8)) & 1) -
               ((seed1[i / 8 + 3 * N / 8] >> (i % 8)) & 1) + Q;
        e[i] = ((seed1[i / 8 + N / 2] >> (i % 8)) & 1) -
               ((seed1[i / 8 + 5 * N / 8] >> (i % 8)) & 1) +
               ((seed1[i / 8 + 3 * N / 4] >> (i % 8)) & 1) -
               ((seed1[i / 8 + 7 * N / 8] >> (i % 8)) & 1) * 2 % Q;
        e_r[i] = ((seed1[i / 8 + N] >> (i % 8)) & 1) -
                 ((seed1[i / 8 + 9 * N / 8] >> (i % 8)) & 1) +
                 ((seed1[i / 8 + 5 * N / 4] >> (i % 8)) & 1) -
                 ((seed1[i / 8 + 11 * N / 8] >> (i % 8)) & 1) * 2 % Q;
    }
    // cbd(r,seed1,0);
    // cbd(e,seed1,1);
    // cbd(e_r,seed1,2);

    poly_tobyte(rand, e);
    poly_tobyte(rand + PKE_POLY_BYTES, r);
    poly_tobyte(rand + 2 * PKE_POLY_BYTES, e_r);

    // FILE *fpt;
    // fopen_s(&fpt, "info.dat", "ab");

    poly_ntt(r);
    poly_pointwise(ar, a, r);
    poly_ntt(e);
    poly_add(c_0, ar, e);

    for (i = 0; i < PKE_POLY_BYTES; i++)
        b[i] = pk[i];

    byte_topoly(b, bb);
    // pol_naivemul(br,bb,r);
    // poly_add(c_1,br,e_r);

    // poly_ntt(bb);

    poly_pointwise(br, bb, r);
    poly_ntt(e_r);
    poly_add(c_1, br, e_r);
    poly_invntt(c_0);
    poly_invntt(c_1);

    for (i = 0; i < N; i++)
        mm[i] = (m[i / 8] >> (i % 8)) & 1;

    for (i = 0; i < N; i++) {

        tmp = c_1[i] - Q + (((c_1[i] > (Q - 1) / 2) - 1) & Q);
        tmp += ((Q - 1) / 2) - (((tmp < -(Q - 1) / 4) - 1) & ((Q - 1) / 2));
        tmp -= ((Q + 1) / 2) - (((tmp > (Q - 1) / 4) - 1) & ((Q + 1) / 2));
        alpha[i] = tmp & 1;

        mm[i] = (mm[i] + alpha[i]) % 2;

        c_2[i] = (c_0[i] + mm[i]) % Q;

        c_4[i] = c_1[i] - Q + (((c_1[i] > (Q - 1) / 2) - 1) & Q);

        c_3[i] = (c_4[i] < -(Q - 1) / 4 || c_4[i] > (Q - 1) / 4);
    }

    poly_tobyte(c, c_2);
    for (i = 0; i < N / 8; i++) {
        c[PKE_POLY_BYTES + i] = 0;
        c[PKE_POLY_BYTES + i] |= c_3[8 * i + 0];
        c[PKE_POLY_BYTES + i] |= c_3[8 * i + 1] * 2;
        c[PKE_POLY_BYTES + i] |= c_3[8 * i + 2] * 4;
        c[PKE_POLY_BYTES + i] |= c_3[8 * i + 3] * 8;
        c[PKE_POLY_BYTES + i] |= c_3[8 * i + 4] * 16;
        c[PKE_POLY_BYTES + i] |= c_3[8 * i + 5] * 32;
        c[PKE_POLY_BYTES + i] |= c_3[8 * i + 6] * 64;
        c[PKE_POLY_BYTES + i] |= c_3[8 * i + 7] * 128;
    }

    // for(i=0;i<mlen;i++)
    // printf("%u ",m[i]);

    // printf("\n");

    // fwrite(m, N / 8, 1, fpt);
    // fwrite(m, N / 8, 1, fpt);
    // fwrite(c, PKE_CIP_BYTES, 1, fpt);
    // fwrite(c, PKE_CIP_BYTES, 1, fpt);
    // fwrite(rand, RAND_BTS, 1, fpt);
    // fprintf(fpt, "%c", 1);
    // fclose(fpt);

    return 0;
}

int pke_dec(unsigned char *sk, unsigned long long sklen,
            unsigned char *c, unsigned long long clen, 
            unsigned char *m, unsigned long long *pointer_mlen)

{
    uint16_t mprime[N], c_1[N], s[N], cs[N], mm[N], cprime[N], sprime[N];
    int16_t mmprime[N], ccs[N];

    int i;
    unsigned char c_2[PKE_POLY_BYTES], c_3[N / 8];
    *pointer_mlen = N / 8;

    // byte_topoly(sk,s);
    byte_topoly_s(sk, sprime);
    s[0] = (2 * (sprime[0] + Q - 2) + 1) % Q;
    for (i = 1; i < N; i++)
        s[i] = 2 * (sprime[i] + Q - 2) % Q;

    poly_ntt(s);

    for (i = 0; i < PKE_POLY_BYTES; i++)
        c_2[i] = c[i];

    for (i = 0; i < N / 8; i++)
        c_3[i] = c[i + PKE_POLY_BYTES];

    for (i = 0; i < N; i++)
        cprime[i] = (c_3[i / 8] >> (i % 8)) & 1;
    // printf("cprime[0] is %lld \n,"cprime[0]);

    byte_topoly(c_2, c_1);

    poly_ntt(c_1);
    poly_pointwise(cs, c_1, s);
    poly_invntt(cs);

    // poly_ntt(cprime);
    // poly_add(mprime,cs,cprime);
    // poly_invntt(mprime);
    /* for(i=0;i<N;i++)
     if(mprime[i]>(Q-1)/2)
         mprime[i]=((mmprime[i]-Q)%2+2)%2;
     else
         mprime[i]=mprime[i]%2;*/

    // pol_naivemul(cs ,c_1,s);
    // poly_sub(mprime,cs,cprime);

    /* for(i=0;i<N;i++)
     {
         mm[i]=(m[i/8]>>(i%8))&1;

     }
     */

    for (i = 0; i < N; i++) {
        if (cs[i] > (Q - 1) / 2)
            ccs[i] = cs[i] - Q;
        else
            ccs[i] = cs[i];

        mmprime[i] = (ccs[i] + (Q - 1) / 2 * cprime[i]); //(-(Q-1)/2,Q)之间

        if (mmprime[i] >= (Q - 1) / 2)

            mprime[i] = ((mmprime[i] - Q) % 2 + 2) % 2;

        else if (mmprime[i] >= -(Q - 1) / 2 && mmprime[i] < 0)

            mprime[i] = ((mmprime[i]) % 2 + 2) % 2;

        else
            mprime[i] = mmprime[i] % 2;
    }

    // printf("\n");

    // for(i=0;i<N/8;i++)
    // printf("%u ",m[i]);
    // for(i=0;i<N;i++)
    // if(mprime[i]!=mm[i]) {
    // printf("%d ",i);
    //}
    // return -1;//解密错误}
    // printf("\n");

    memset(m, 0, sizeof(m));

    for (i = 0; i < N / 8; i++) {
        m[i] = mprime[8 * i + 0];
        m[i] = m[i] + mprime[8 * i + 1] * 2;
        m[i] = m[i] + mprime[8 * i + 2] * 4;
        m[i] = m[i] + mprime[8 * i + 3] * 8;
        m[i] = m[i] + mprime[8 * i + 4] * 16;
        m[i] = m[i] + mprime[8 * i + 5] * 32;
        m[i] = m[i] + mprime[8 * i + 6] * 64;
        m[i] = m[i] + mprime[8 * i + 7] * 128;
        // printf("%u ",m[i]);
    }

    return 0;
}

int pke_enc_with_param_fixed(unsigned char *pk, unsigned long long pklen,
                             unsigned char *m, unsigned long long mlen,
                             unsigned char *rand, unsigned long long randbyts,
                             unsigned char *c, unsigned long long *pointer_clen)

{
    uint16_t r[N], e[N], e_r[N], c_0[N], c_1[N], c_2[N], c_3[N], ar[N], a[N],
        br[N], mm[N], bb[N], alpha[N];
    int16_t c_4[N];
    unsigned char seed[PKE_SEED_BYTES], b[PKE_POLY_BYTES], rb[PKE_POLY_BYTES],
        eb[PKE_POLY_BYTES], erb[PKE_POLY_BYTES];
    unsigned char seed1[3 * N / 2];
    int i;
    for (i = 0; i < PKE_SEED_BYTES; i++)
        seed[i] = pk[PKE_POLY_BYTES + i];

    poly_gen_a(a, seed);
    // unsigned char seed1[SEED_BYTES];
    // RAND_bytes(seed1, SEED_BYTES);
    // shake256(seed1, SEED_BYTES,seed1, SEED_BYTES);

    /*RAND_bytes(seed1,3*N/2);
    shake256(seed1,3*N/2,seed1,3*N/2);
    for(i=0;i<N;i++)
    {
    r[i]=((seed1[i/8]>>(i%8))&1)-((seed1[i/8+N/8]>>(i%8))&1)+((seed1[i/8+N/4]>>(i%8))&1)-((seed1[i/8+3*N/8]>>(i%8))&1)+Q;
        e[i]=((seed1[i/8+N/2]>>(i%8))&1)-((seed1[i/8+5*N/8]>>(i%8))&1)+((seed1[i/8+3*N/4]>>(i%8))&1)-((seed1[i/8+7*N/8]>>(i%8))&1)+Q;
        e_r[i]=((seed1[i/8+N]>>(i%8))&1)-((seed1[i/8+9*N/8]>>(i%8))&1)+((seed1[i/8+5*N/4]>>(i%8))&1)-((seed1[i/8+11*N/8]>>(i%8))&1)+Q;

    }*/

    for (i = 0; i < PKE_POLY_BYTES; i++) {
        rb[i] = rand[i];
        eb[i] = rand[i + PKE_POLY_BYTES];
        erb[i] = rand[i + 2 * PKE_POLY_BYTES];
    }

    // cbd(r,seed1,0);
    // cbd(e,seed1,1);
    // cbd(e_r,seed1,2);
    /* for(i=0;i<N;i++)
     {
         e[i]=2*e[i]%Q;
         e_r[i]=2*e_r[i]%Q;
     }
     */

    byte_topoly(eb, e);
    byte_topoly(rb, r);
    byte_topoly(erb, e_r);

    poly_ntt(r);
    poly_pointwise(ar, a, r);
    poly_ntt(e);
    poly_add(c_0, ar, e);

    for (i = 0; i < PKE_POLY_BYTES; i++)
        b[i] = pk[i];

    byte_topoly(b, bb);
    // pol_naivemul(br,bb,r);
    // poly_add(c_1,br,e_r);

    // poly_ntt(bb);

    poly_pointwise(br, bb, r);
    poly_ntt(e_r);
    poly_add(c_1, br, e_r);
    poly_invntt(c_0);
    poly_invntt(c_1);

    for (i = 0; i < N; i++)
        mm[i] = (m[i / 8] >> (i % 8)) & 1;

    for (i = 0; i < N; i++) {

        alpha[i] = (Remain(c_1[i]) % 2 + 2) % 2;
        mm[i] = (mm[i] + alpha[i]) % 2;
        c_2[i] = (c_0[i] + mm[i]) % Q;

        if (c_1[i] > (Q - 1) / 2)
            c_4[i] = c_1[i] - Q;
        else
            c_4[i] = c_1[i];

        if (c_4[i] < -(Q - 1) / 4 || c_4[i] > (Q - 1) / 4)

            c_3[i] = 1;

        else
            c_3[i] = 0;
    }

    poly_tobyte(c, c_2);
    for (i = 0; i < N / 8; i++) {
        c[PKE_POLY_BYTES + i] = c_3[8 * i + 0];
        c[PKE_POLY_BYTES + i] = c[PKE_POLY_BYTES + i] + c_3[8 * i + 1] * 2;
        c[PKE_POLY_BYTES + i] = c[PKE_POLY_BYTES + i] + c_3[8 * i + 2] * 4;
        c[PKE_POLY_BYTES + i] = c[PKE_POLY_BYTES + i] + c_3[8 * i + 3] * 8;
        c[PKE_POLY_BYTES + i] = c[PKE_POLY_BYTES + i] + c_3[8 * i + 4] * 16;
        c[PKE_POLY_BYTES + i] = c[PKE_POLY_BYTES + i] + c_3[8 * i + 5] * 32;
        c[PKE_POLY_BYTES + i] = c[PKE_POLY_BYTES + i] + c_3[8 * i + 6] * 64;
        c[PKE_POLY_BYTES + i] = c[PKE_POLY_BYTES + i] + c_3[8 * i + 7] * 128;
    }

    for (i = 0; i < N / 8; i++)
        printf("%u ", m[i]);

    printf("\n");
    return 0;
}

int
pke_dec_with_param_fixed(unsigned char *sk, unsigned long long sklen,
                         unsigned char *c, unsigned long long clen,
                         unsigned char *m, unsigned long long *pointer_mlen)

{
    uint16_t mprime[N], c_1[N], s[N], cs[N], mm[N], cprime[N], sprime[N];
    int16_t mmprime[N], ccs[N];

    int i;
    unsigned char c_2[PKE_POLY_BYTES], c_3[N / 8];
    *pointer_mlen = N / 8;

    // byte_topoly(sk,s);
    byte_topoly_s(sk, sprime);
    s[0] = (2 * (sprime[0] + Q - 2) + 1) % Q;
    for (i = 1; i < N; i++)
        s[i] = 2 * (sprime[i] + Q - 2) % Q;

    poly_ntt(s);

    for (i = 0; i < PKE_POLY_BYTES; i++)
        c_2[i] = c[i];

    for (i = 0; i < N / 8; i++)
        c_3[i] = c[i + PKE_POLY_BYTES];

    for (i = 0; i < N; i++)
        cprime[i] = (c_3[i / 8] >> (i % 8)) & 1;
    // printf("cprime[0] is %lld \n,"cprime[0]);

    byte_topoly(c_2, c_1);

    poly_ntt(c_1);
    poly_pointwise(cs, c_1, s);
    poly_invntt(cs);

    // poly_ntt(cprime);
    // poly_add(mprime,cs,cprime);
    // poly_invntt(mprime);
    /* for(i=0;i<N;i++)
     if(mprime[i]>(Q-1)/2)
         mprime[i]=((mmprime[i]-Q)%2+2)%2;
     else
         mprime[i]=mprime[i]%2;*/

    // pol_naivemul(cs ,c_1,s);
    // poly_sub(mprime,cs,cprime);

    /* for(i=0;i<N;i++)
     {
         mm[i]=(m[i/8]>>(i%8))&1;

     }
     */

    for (i = 0; i < N; i++) {
        if (cs[i] > (Q - 1) / 2)
            ccs[i] = cs[i] - Q;
        else
            ccs[i] = cs[i];

        mmprime[i] = (ccs[i] + (Q - 1) / 2 * cprime[i]); //(-(Q-1)/2,Q)之间

        if (mmprime[i] >= (Q - 1) / 2)

            mprime[i] = ((mmprime[i] - Q) % 2 + 2) % 2;

        else if (mmprime[i] >= -(Q - 1) / 2 && mmprime[i] < 0)

            mprime[i] = ((mmprime[i]) % 2 + 2) % 2;

        else
            mprime[i] = mmprime[i] % 2;
    }

    // printf("\n");

    // for(i=0;i<N/8;i++)
    // printf("%u ",m[i]);
    // for(i=0;i<N;i++)
    // if(mprime[i]!=mm[i]) {
    // printf("%d ",i);
    //}
    // return -1;//解密错误}
    // printf("\n");

    memset(m, 0, sizeof(m));

    for (i = 0; i < N / 8; i++) {
        m[i] = mprime[8 * i + 0];
        m[i] = m[i] + mprime[8 * i + 1] * 2;
        m[i] = m[i] + mprime[8 * i + 2] * 4;
        m[i] = m[i] + mprime[8 * i + 3] * 8;
        m[i] = m[i] + mprime[8 * i + 4] * 16;
        m[i] = m[i] + mprime[8 * i + 5] * 32;
        m[i] = m[i] + mprime[8 * i + 6] * 64;
        m[i] = m[i] + mprime[8 * i + 7] * 128;
        // printf("%u ",m[i]);
    }

    return 0;
}
