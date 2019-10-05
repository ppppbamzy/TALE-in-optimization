//
//  poly.h

#ifndef poly_h
#define poly_h

#include "parameter.h"
#include <stdint.h>

void poly_add(uint16_t *c, const uint16_t *a, const uint16_t *b);
void poly_pointwise(uint16_t *c, const uint16_t *a, const uint16_t *b);
void poly_bitrev(uint16_t *a);
void poly_tobyte(unsigned char *a, uint16_t *r);
void byte_topoly(unsigned char *a, uint16_t *r);
void byte_topoly_s(unsigned char *a, uint16_t *r);
void poly_tobyte_s(unsigned char *a, uint16_t *r);
void poly_ntt(uint16_t *r);
void poly_invntt(uint16_t *r);
void poly_gen_a(uint16_t *a, const unsigned char *seed);

#endif /* poly_h */
