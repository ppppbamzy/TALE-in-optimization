//
//  parameter.h

#ifndef parameter_h
#define parameter_h

#define N 1024
#define Q 18433
#define k 2 // central binomial

#define PKE_SECRETKEYBYTES 3 * N / 8 // 15*N/8
#define PKE_PUBLICKEYBYTES 15 * N / 8 + 32
#define PKE_SEED_BYTES 32         // the size of seed
#define PKE_POLY_BYTES 15 * N / 8 //  2^14< q=18433 <2^15
#define PKE_MESS_BYTES N / 8
#define PKE_CIP_BYTES (15 * N + N) / 8
#define RAND_BTS 3 * 15 * N / 8
#define PKE_ALGNAME TALE

#endif /* parameter_h */
