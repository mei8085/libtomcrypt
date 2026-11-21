/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

static int s_ecc_cmp_hex_bn(const char *left_hex, void *right_bn, void *tmp_bn)
{
   if (ltc_mp_read_radix(tmp_bn, left_hex, 16) != CRYPT_OK) return 0;
   if (ltc_mp_cmp(tmp_bn, right_bn) != LTC_MP_EQ)           return 0;
   return 1;
}

/* Match the domain parameters in 'dp' against the built-in named curves.
 *
 * returns  1 and sets '*cu' if all domain parameters (prime, order, A, B,
 *            base point and cofactor) are equal to a named curve
 * returns  0 if no named curve is defined over the same field (custom curve)
 * returns -1 if a named curve uses the same field prime but some other
 *            domain parameter differs (partial match, inconsistent input)
 */
static int s_ecc_find_named_curve(const ltc_ecc_dp *dp, const ltc_ecc_curve **cu)
{
   void *bn;
   const ltc_ecc_curve *curve;
   int ret = 0;

   *cu = NULL;
   if (ltc_mp_init(&bn) != CRYPT_OK) return 0;
   for (curve = ltc_ecc_curves; curve->prime != NULL; curve++) {
      if (s_ecc_cmp_hex_bn(curve->prime, dp->prime,  bn) != 1) continue;
      /* same field: either all domain parameters match or the input is inconsistent */
      if (s_ecc_cmp_hex_bn(curve->order, dp->order,  bn) != 1) { ret = -1; break; }
      if (s_ecc_cmp_hex_bn(curve->A,     dp->A,      bn) != 1) { ret = -1; break; }
      if (s_ecc_cmp_hex_bn(curve->B,     dp->B,      bn) != 1) { ret = -1; break; }
      if (s_ecc_cmp_hex_bn(curve->Gx,    dp->base.x, bn) != 1) { ret = -1; break; }
      if (s_ecc_cmp_hex_bn(curve->Gy,    dp->base.y, bn) != 1) { ret = -1; break; }
      if (dp->cofactor != curve->cofactor)                     { ret = -1; break; }
      *cu = curve;
      ret = 1;
      break;
   }
   ltc_mp_clear(bn);
   return ret;
}

static void s_ecc_oid_lookup(ecc_key *key)
{
   const ltc_ecc_curve *curve;

   key->dp.oidlen = 0;
   if (s_ecc_find_named_curve(&key->dp, &curve) == 1 && curve->OID != NULL) {
      key->dp.oidlen = 16; /* size of key->dp.oid */
      pk_oid_str_to_num(curve->OID, key->dp.oid, &key->dp.oidlen);
   }
}

/* Fully validate the domain parameters of a custom (non named) curve:
 * the field prime, the curve coefficients, the base point, the subgroup
 * order and the cofactor.
 */
static int s_ecc_verify_domain_params(const ltc_ecc_dp *dp)
{
   ecc_point *tg = NULL;
   void *t1 = NULL, *t2 = NULL, *t3 = NULL;
   int err, isprime, inf;

   /* the field prime must be an odd prime */
   if (ltc_mp_cmp_d(dp->prime, 3) == LTC_MP_LT) return CRYPT_INVALID_PACKET;
   if (ltc_mp_isodd(dp->prime) != LTC_MP_YES)   return CRYPT_INVALID_PACKET;
   if (ltc_mp.isprime != NULL) {
      if ((err = ltc_mp_prime_is_prime(dp->prime, LTC_MILLER_RABIN_REPS, &isprime)) != CRYPT_OK) return err;
      if (isprime != LTC_MP_YES) return CRYPT_INVALID_PACKET;
   }

   /* the curve coefficients must be field elements: 0 <= A,B < prime */
   if (ltc_mp_cmp(dp->A, dp->prime) != LTC_MP_LT) return CRYPT_INVALID_PACKET;
   if (ltc_mp_cmp(dp->B, dp->prime) != LTC_MP_LT) return CRYPT_INVALID_PACKET;

   /* the base point coordinates must be field elements: 0 <= Gx,Gy < prime */
   if (ltc_mp_cmp(dp->base.x, dp->prime) != LTC_MP_LT) return CRYPT_INVALID_PACKET;
   if (ltc_mp_cmp(dp->base.y, dp->prime) != LTC_MP_LT) return CRYPT_INVALID_PACKET;

   /* the base point must lie on the curve */
   if ((err = ltc_ecc_is_point(dp, dp->base.x, dp->base.y)) != CRYPT_OK) return err;

   /* the subgroup order must be larger than one */
   if (ltc_mp_cmp_d(dp->order, 1) != LTC_MP_GT) return CRYPT_INVALID_PACKET;

   if ((err = ltc_mp_init_multi(&t1, &t2, &t3, LTC_NULL)) != CRYPT_OK) return err;

   /* the base point must have the claimed order: order*G == point at infinity */
   tg = ltc_ecc_new_point();
   if (tg == NULL) {
      err = CRYPT_MEM;
      goto cleanup;
   }
   if ((err = ltc_ecc_mulmod(dp->order, &dp->base, tg, dp->A, dp->prime, 0)) != CRYPT_OK) goto cleanup;
   if ((err = ltc_ecc_is_point_at_infinity(tg, dp->prime, &inf)) != CRYPT_OK)             goto cleanup;
   if (inf != 1) {
      err = CRYPT_INVALID_PACKET;
      goto cleanup;
   }

   /* if a cofactor is given it must be consistent with the Hasse bound:
    *   |(p + 1) - cofactor*order| <= 2*sqrt(p)   <=>   ((p + 1) - cofactor*order)^2 <= 4*p
    */
   if (dp->cofactor > 0) {
      if ((err = ltc_mp_mul_d(dp->order, dp->cofactor, t1)) != CRYPT_OK) goto cleanup; /* t1 = h*n       */
      if ((err = ltc_mp_add_d(dp->prime, 1, t2)) != CRYPT_OK)            goto cleanup; /* t2 = p+1       */
      if ((err = ltc_mp_sub(t2, t1, t3)) != CRYPT_OK)                    goto cleanup; /* t3 = p+1 - h*n */
      if ((err = ltc_mp_sqr(t3, t3)) != CRYPT_OK)                        goto cleanup; /* t3 = t3^2      */
      if ((err = ltc_mp_mul_d(dp->prime, 4, t1)) != CRYPT_OK)            goto cleanup; /* t1 = 4*p       */
      if (ltc_mp_cmp(t3, t1) == LTC_MP_GT) {
         err = CRYPT_INVALID_PACKET;
         goto cleanup;
      }
   }

   err = CRYPT_OK;
cleanup:
   if (tg != NULL) ltc_ecc_del_point(tg);
   ltc_mp_deinit_multi(t1, t2, t3, LTC_NULL);
   return err;
}

/* Read a curve coefficient (a or b) from its DER OCTET STRING and check that
 * it is canonically encoded: either the minimal big-endian encoding or the
 * fixed field-width encoding (SEC 1) is accepted, any other (padded or
 * over-long) encoding is rejected.  The value must be a field element.
 */
int ecc_read_curve_coef(void *coef, const unsigned char *in, unsigned long inlen, void *prime)
{
   unsigned long field_size, min_size;
   int err;

   field_size = ltc_mp_unsigned_bin_size(prime);
   if (inlen == 0 || inlen > field_size) return CRYPT_INVALID_PACKET;
   if ((err = ltc_mp_read_unsigned_bin(coef, in, inlen)) != CRYPT_OK) return err;
   min_size = ltc_mp_unsigned_bin_size(coef);
   if (min_size == 0) min_size = 1; /* zero is encoded as a single 0x00 byte */
   if (inlen != field_size && inlen != min_size) return CRYPT_INVALID_PACKET;
   if (ltc_mp_cmp(coef, prime) != LTC_MP_LT) return CRYPT_INVALID_PACKET;
   return CRYPT_OK;
}

int ecc_copy_curve(const ecc_key *srckey, ecc_key *key)
{
   unsigned long i;
   int err;

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(srckey != NULL);

   if ((err = ltc_mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = ltc_mp_copy(srckey->dp.prime,  key->dp.prime )) != CRYPT_OK) { goto error; }
   if ((err = ltc_mp_copy(srckey->dp.order,  key->dp.order )) != CRYPT_OK) { goto error; }
   if ((err = ltc_mp_copy(srckey->dp.A,      key->dp.A     )) != CRYPT_OK) { goto error; }
   if ((err = ltc_mp_copy(srckey->dp.B,      key->dp.B     )) != CRYPT_OK) { goto error; }
   if ((err = ltc_ecc_copy_point(&srckey->dp.base, &key->dp.base)) != CRYPT_OK) { goto error; }
   /* cofactor & size */
   key->dp.cofactor = srckey->dp.cofactor;
   key->dp.size     = srckey->dp.size;
   /* OID */
   if (srckey->dp.oidlen > 0) {
     key->dp.oidlen = srckey->dp.oidlen;
     for (i = 0; i < key->dp.oidlen; i++) key->dp.oid[i] = srckey->dp.oid[i];
   }
   else {
     s_ecc_oid_lookup(key); /* try to find OID in ltc_ecc_curves */
   }
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

int ecc_set_curve_from_mpis(void *a, void *b, void *prime, void *order, void *gx, void *gy, unsigned long cofactor, ecc_key *key)
{
   const ltc_ecc_curve *curve;
   int err, match;

   LTC_ARGCHK(key   != NULL);
   LTC_ARGCHK(a     != NULL);
   LTC_ARGCHK(b     != NULL);
   LTC_ARGCHK(prime != NULL);
   LTC_ARGCHK(order != NULL);
   LTC_ARGCHK(gx    != NULL);
   LTC_ARGCHK(gy    != NULL);

   if ((err = ltc_mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = ltc_mp_copy(prime, key->dp.prime )) != CRYPT_OK) { goto error; }
   if ((err = ltc_mp_copy(order, key->dp.order )) != CRYPT_OK) { goto error; }
   if ((err = ltc_mp_copy(a,     key->dp.A     )) != CRYPT_OK) { goto error; }
   if ((err = ltc_mp_copy(b,     key->dp.B     )) != CRYPT_OK) { goto error; }
   if ((err = ltc_mp_copy(gx,    key->dp.base.x)) != CRYPT_OK) { goto error; }
   if ((err = ltc_mp_copy(gy,    key->dp.base.y)) != CRYPT_OK) { goto error; }
   if ((err = ltc_mp_set(key->dp.base.z, 1)) != CRYPT_OK)      { goto error; }
   /* cofactor & size */
   key->dp.cofactor = cofactor;
   key->dp.size = ltc_mp_unsigned_bin_size(prime);
   key->dp.oidlen = 0;

   /* match the domain parameters against the built-in named curves */
   match = s_ecc_find_named_curve(&key->dp, &curve);
   if (match < 0) {
      /* the parameters only partially match a named curve, refuse to
       * guess the caller's intent: inconsistent input is rejected */
      err = CRYPT_INVALID_PACKET;
      goto error;
   }
   if (match == 1) {
      /* parameters equivalent to a named curve: normalize to its canonical
       * definition so that named-curve and explicit-parameter encodings of
       * the same curve result in the same key */
      if (curve->OID != NULL) {
         key->dp.oidlen = 16; /* size of key->dp.oid */
         if ((err = pk_oid_str_to_num(curve->OID, key->dp.oid, &key->dp.oidlen)) != CRYPT_OK) { goto error; }
      }
   }
   else {
      /* custom curve: fully validate prime, order, base point and cofactor */
      if ((err = s_ecc_verify_domain_params(&key->dp)) != CRYPT_OK) { goto error; }
   }
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

#endif
