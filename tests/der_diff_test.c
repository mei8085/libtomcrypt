/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#if !defined(LTC_DER) || !defined(LTC_MRSA) || !defined(LTC_MECC) || !defined(LTC_SHA256)
LTC_NOP_TEST(der_diff_test)
#else

/*
 * Differential DER test: acceptance sets of the DER decoder entry points and
 * re-encoding / canonicalization consistency.
 *
 * Seeds are structures that the library itself consumes:
 *
 *  - (sig)  ECDSA-Sig-Value ::= SEQUENCE { INTEGER r, INTEGER s }, the format
 *           parsed by ecc_verify_hash_x962() for ANSI X9.62 signatures.  It is
 *           the RFC 6979 P-256/SHA-256 signature over "sample" (r and s from
 *           the RFC 6979 test vectors), so the consumer must report a valid
 *           signature for the untouched seed.
 *  - (spki) X.509 SubjectPublicKeyInfo wrapping an RSAPublicKey as parsed by
 *           rsa_import().
 *  - (ec)   RFC 5915 ECPrivateKey on a named curve as parsed by
 *           ecc_import_openssl().
 *
 * From every seed a deterministic corpus is derived: single bit flips, every
 * truncation, appended trailing data, random byte overwrites and structural
 * rewrites (non-minimal length encodings and redundant leading zeroes on
 * INTEGER values) built from an independent parse tree.
 *
 * For each corpus entry these decoders are compared:
 *   flexi, relaxed SEQUENCE, strict SEQUENCE, all-strict SEQUENCE and the
 *   library consumer implementing the structure.  An independent DER parser
 *   (below, not using libtomcrypt) supplies the structural verdict, so a
 *   decoder bug cannot mask itself.
 *
 * Requirements (all empirically stable for this revision):
 *
 *  R1  all-strict accepted  => strict accepted => relaxed accepted
 *  R2  strict accepted      => its re-encoding is accepted by all-strict
 *  R3  strict accepted      => re-decoding the re-encoding reproduces it
 *                              byte for byte (decoding reaches a fixpoint)
 *  R4  relaxed accepted     => its re-encoding is accepted by all-strict and
 *                              re-decoding it relaxed reproduces it exactly
 *  R5  the flexi decoder never consumes more bytes than were supplied
 *  R6  appending bytes to a seed is rejected by the schema decoders, while
 *      the flexi decoder consumes exactly the seed
 *  R7  every proper prefix of a seed is rejected by the schema decoders
 *  R8  a non-minimal length on the outermost element is rejected by
 *      all-strict, accepted by relaxed, and re-encodes to the seed; the same
 *      rewrite on a nested element is rejected by every schema decoder (they
 *      advance by canonical lengths and cannot resynchronize)
 *  R9  a redundant leading zero on a nested INTEGER is rejected by every
 *      schema decoder (the outermost element here is always a SEQUENCE)
 *  R10 every input accepted by the schema consumers is accepted by the
 *      relaxed schema decoder as well
 *  R11 the signature consumer reports a valid signature only for the exact
 *      seed vector - unauthenticated data is never treated as a signature
 *
 * Determinism / resources: mutations come from a fixed-seed xorshift64
 * generator, buffers are bounded by DD_MAX_* and the tree walk is bounded in
 * nodes and depth, so runtime and memory are bounded and machine independent.
 */

#define DD_MAX_BUF    1024
#define DD_MAX_BITS   (DD_MAX_BUF * 8)
#define DD_MAX_NODES  64
#define DD_MAX_DEPTH  16
/* deterministic corpus size bounds (see der_diff_test()) */
#define DD_MIN_CASES  3000
#define DD_MAX_CASES  6000

/* oracle verdicts */
#define DD_CANON      0   /* structurally valid, minimal (DER) encoding */
#define DD_NONCANON   1   /* structurally valid, non-minimal encoding  */
#define DD_INVALID   (-1) /* not exactly one well-formed TLV           */

/* structural rewrite modes */
#define DD_M_LONGLEN  1   /* encode one length non-minimally */
#define DD_M_REDZERO  2   /* prepend 0x00 to one INTEGER value */

typedef struct {
   unsigned long off;    /* identifier offset */
   unsigned long idl;    /* identifier length */
   unsigned long coff;   /* content offset */
   unsigned long clen;   /* content length */
   unsigned long ends;   /* offset just past this element */
   unsigned long tag;    /* tag number */
   unsigned char id;     /* identifier octet */
} dd_node;

typedef struct {
   dd_node n[DD_MAX_NODES];
   int nn;
   int bad_struct;
   int bad_len;
   int bad_val;
   unsigned long first_end;
} dd_parse;

/* ------------------------------------------------------------------ */
/* independent DER parser                                             */
/* ------------------------------------------------------------------ */

static int dd_parse_rec(unsigned char *b, unsigned long limit, unsigned long off,
                        int depth, dd_parse *p)
{
   unsigned long pos, idl, len, lenlen, i, tag;
   dd_node *nd;

   if (depth > DD_MAX_DEPTH || p->nn >= DD_MAX_NODES || off >= limit) {
      p->bad_struct = 1;
      return -1;
   }

   nd  = &p->n[p->nn];
   pos = off;
   nd->off = pos;
   nd->id  = b[pos];
   tag     = b[pos] & 0x1f;
   idl     = 1;

   /* high tag number form: up to four subsequent octets, no leading 0x80 */
   if (tag == 0x1f) {
      unsigned long t = 0;
      int k = 0, lead = 1;
      for (;;) {
         unsigned char c;
         if (pos + idl >= limit || k >= 4) { p->bad_struct = 1; return -1; }
         c = b[pos + idl];
         if (lead && (c & 0x7f) == 0) { p->bad_struct = 1; return -1; }
         lead = 0;
         t = (t << 7) | (c & 0x7f);
         k++;
         idl++;
         if (!(c & 0x80)) break;
      }
      if (t < 0x1f) { p->bad_struct = 1; return -1; }
      tag = t;
   }

   if (pos + idl >= limit) { p->bad_struct = 1; return -1; }

   if (b[pos + idl] < 128) {
      len    = b[pos + idl];
      lenlen = 1;
   } else {
      unsigned long k = b[pos + idl] & 0x7f;
      if (k == 0 || k > sizeof(unsigned long))  { p->bad_struct = 1; return -1; }
      if (pos + idl + 1 + k > limit)            { p->bad_struct = 1; return -1; }
      lenlen = 1 + k;
      len = 0;
      for (i = 0; i < k; i++) len = (len << 8) | b[pos + idl + 1 + i];
      if ((k > 1 && b[pos + idl + 1] == 0) || (k == 1 && len < 128)) p->bad_len = 1;
   }

   nd->tag  = tag;
   nd->idl  = idl;
   nd->coff = pos + idl + lenlen;
   nd->clen = len;
   if (nd->coff + len > limit) { p->bad_struct = 1; return -1; }
   nd->ends = nd->coff + len;
   if (p->nn == 0) p->first_end = nd->ends;

   /* value checks for universal (class 0) types */
   if ((nd->id & 0xc0) == 0) {
      int cons = (b[pos] & 0x20) != 0;
      if (cons && (tag == 1 || tag == 2 || tag == 3 || tag == 5 || tag == 6)) {
         p->bad_struct = 1;
         return -1;
      }
      if (!cons) {
         if (tag == 1) {              /* BOOLEAN */
            if (len != 1) { p->bad_val = 1; return -1; }
            if (b[nd->coff] != 0x00 && b[nd->coff] != 0xff) p->bad_val = 1;
         } else if (tag == 2) {       /* INTEGER */
            if (len == 0) { p->bad_struct = 1; return -1; }
            if (len > 1 && ((b[nd->coff] == 0x00 && b[nd->coff + 1] < 0x80) ||
                            (b[nd->coff] == 0xff && b[nd->coff + 1] >= 0x80))) p->bad_val = 1;
         } else if (tag == 3) {       /* BIT STRING */
            unsigned long unused;
            if (len == 0) { p->bad_struct = 1; return -1; }
            unused = b[nd->coff];
            if (unused > 7 || (len == 1 && unused != 0) ||
                (unused != 0 && (b[nd->coff + len - 1] & ((1uL << unused) - 1uL)) != 0)) p->bad_val = 1;
         } else if (tag == 6) {       /* OBJECT IDENTIFIER */
            unsigned long j = 0;
            if (len == 0) { p->bad_struct = 1; return -1; }
            while (j < len) {
               if (b[nd->coff + j] == 0x80) { p->bad_struct = 1; return -1; }
               while (j < len && (b[nd->coff + j] & 0x80)) j++;
               j++;
            }
         }
      }
   }

   if (p->bad_struct || p->bad_val) return -1;

   p->nn++;

   if (b[pos] & 0x20) {
      unsigned long c = nd->coff;
      while (c < nd->ends) {
         if (dd_parse_rec(b, nd->ends, c, depth + 1, p)) return -1;
         c = p->n[p->nn - 1].ends;
      }
      if (c != nd->ends) { p->bad_struct = 1; return -1; }
   }
   return 0;
}

/* Parse exactly one TLV covering the whole input; returns DD_CANON,
 * DD_NONCANON or DD_INVALID (including trailing data). */
static int dd_oracle(const unsigned char *b, unsigned long n)
{
   dd_parse p;

   p.nn         = 0;
   p.bad_struct = 0;
   p.bad_len    = 0;
   p.bad_val    = 0;
   p.first_end  = 0;

   if (n == 0 || dd_parse_rec((unsigned char *)b, n, 0, 0, &p)) return DD_INVALID;
   if (p.first_end != n) return DD_INVALID;
   return p.bad_len ? DD_NONCANON : DD_CANON;
}

/* ------------------------------------------------------------------ */
/* independent structural re-writer                                   */
/* ------------------------------------------------------------------ */

static int dd_put(unsigned char *out, unsigned long cap, unsigned long *o,
                  const unsigned char *p, unsigned long n)
{
   if (*o + n > cap) return -1;
   XMEMCPY(out + *o, p, n);
   *o += n;
   return 0;
}

static int dd_put_len(unsigned char *out, unsigned long cap, unsigned long *o,
                      unsigned long len, int nonminimal)
{
   unsigned char b[5];
   unsigned long n = 0, t = len;
   int k = 0;

   if (!nonminimal && len < 128) {
      b[n++] = (unsigned char)len;
      return dd_put(out, cap, o, b, n);
   }
   while (t) { k++; t >>= 8; }
   if (k == 0) k = 1;
   if (nonminimal) {
      b[n++] = (unsigned char)(0x80 | (k + 1));
      b[n++] = 0x00;
   } else {
      b[n++] = (unsigned char)(0x80 | k);
   }
   while (k) { b[n++] = (unsigned char)((len >> (8 * (k - 1))) & 0xff); k--; }
   return dd_put(out, cap, o, b, n);
}

/* Rebuild the subtree rooted at node idx.  mode/target rewrite a single node:
 * DD_M_LONGLEN encodes that node's length non-minimally, DD_M_REDZERO
 * prepends a zero octet to the content of that node. */
static int dd_emit(const unsigned char *b, const dd_parse *p, int idx,
                   int mode, int target, unsigned char *out, unsigned long cap,
                   unsigned long *o, int *next)
{
   const dd_node *nd = &p->n[idx];
   unsigned char tmp[DD_MAX_BUF];
   unsigned long tl = 0;
   int k = idx + 1;   /* index of the next node in pre-order */

   if (b[nd->off] & 0x20) {
      unsigned long c = nd->coff;
      while (c < nd->ends) {
         int nx;
         if (k >= p->nn) return -1;
         if (dd_emit(b, p, k, mode, target, tmp, sizeof(tmp), &tl, &nx)) return -1;
         k = nx;
         c = p->n[nx - 1].ends;
      }
   } else {
      if (mode == DD_M_REDZERO && idx == target) {
         tmp[tl++] = 0x00;
      }
      if (dd_put(tmp, sizeof(tmp), &tl, b + nd->coff, nd->clen)) return -1;
   }

   /* identifier octets are copied verbatim so that only the selected
    * structural property differs from the seed */
   if (dd_put(out, cap, o, b + nd->off, nd->idl)) return -1;
   if (dd_put_len(out, cap, o, tl, mode == DD_M_LONGLEN && idx == target)) return -1;
   if (dd_put(out, cap, o, tmp, tl)) return -1;

   *next = k;
   return 0;
}

static int dd_rewrite(const unsigned char *b, unsigned long n,
                      int mode, int target, unsigned char *out, unsigned long *outlen)
{
   dd_parse p;
   int next = 0;
   unsigned long o = 0;

   p.nn         = 0;
   p.bad_struct = 0;
   p.bad_len    = 0;
   p.bad_val    = 0;
   p.first_end  = 0;

   if (n == 0 || dd_parse_rec((unsigned char *)b, n, 0, 0, &p)) return -1;
   if (p.first_end != n) return -1;
   if (dd_emit(b, &p, 0, mode, target, out, DD_MAX_BUF, &o, &next)) return -1;
   *outlen = o;
   return 0;
}

/* ------------------------------------------------------------------ */
/* schema decoders: decode then re-encode, mirroring the consumers    */
/* ------------------------------------------------------------------ */

static unsigned long dd_oid[16];
static unsigned char dd_bits[DD_MAX_BITS];
static unsigned char dd_oct[DD_MAX_BUF];
static void *dd_mp1, *dd_mp2;

static int dd_dec_sig(const unsigned char *in, unsigned long inlen, unsigned int flags,
                      unsigned char *out, unsigned long *outlen)
{
   ltc_asn1_list seq[2];
   unsigned long olen = *outlen;
   int err;

   ltc_mp_set_int(dd_mp1, 0);
   ltc_mp_set_int(dd_mp2, 0);
   LTC_SET_ASN1(seq, 0, LTC_ASN1_INTEGER, dd_mp1, 1);
   LTC_SET_ASN1(seq, 1, LTC_ASN1_INTEGER, dd_mp2, 1);

   if ((err = der_decode_sequence_ex(in, inlen, seq, 2, flags)) != CRYPT_OK) return -1;
   err = der_encode_sequence_multi(out, &olen,
                                   LTC_ASN1_INTEGER, 1UL, dd_mp1,
                                   LTC_ASN1_INTEGER, 1UL, dd_mp2,
                                   LTC_ASN1_EOL,     0UL, NULL);
   if (err != CRYPT_OK) return -1;
   *outlen = olen;
   return 0;
}

static int dd_dec_spki(const unsigned char *in, unsigned long inlen, unsigned int flags,
                       unsigned char *out, unsigned long *outlen)
{
   ltc_asn1_list alg[2], top[2];
   unsigned long olen = *outlen;
   int err;

   LTC_SET_ASN1(alg, 0, LTC_ASN1_OBJECT_IDENTIFIER, dd_oid,  LTC_ARRAY_SIZE(dd_oid));
   LTC_SET_ASN1(alg, 1, LTC_ASN1_NULL,              NULL,    0);
   LTC_SET_ASN1(top, 0, LTC_ASN1_SEQUENCE,          alg,     2);
   LTC_SET_ASN1(top, 1, LTC_ASN1_BIT_STRING,        dd_bits, DD_MAX_BITS);

   if ((err = der_decode_sequence_ex(in, inlen, top, 2, flags)) != CRYPT_OK) return -1;
   err = der_encode_sequence(top, 2, out, &olen);
   if (err != CRYPT_OK) return -1;
   *outlen = olen;
   return 0;
}

static int dd_dec_ec(const unsigned char *in, unsigned long inlen, unsigned int flags,
                     unsigned char *out, unsigned long *outlen)
{
   ltc_asn1_list priv[4], custom[2];
   unsigned long ver = 0, olen = *outlen;
   int err;

   LTC_SET_ASN1(custom, 0, LTC_ASN1_OBJECT_IDENTIFIER, dd_oid,  LTC_ARRAY_SIZE(dd_oid));
   LTC_SET_ASN1(custom, 1, LTC_ASN1_RAW_BIT_STRING,    dd_bits, DD_MAX_BITS);
   LTC_SET_ASN1(priv, 0, LTC_ASN1_SHORT_INTEGER,       &ver,    1);
   LTC_SET_ASN1(priv, 1, LTC_ASN1_OCTET_STRING,        dd_oct,  DD_MAX_BUF);
   LTC_SET_ASN1_CUSTOM_CONSTRUCTED(priv, 2, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0, custom);
   LTC_SET_ASN1_CUSTOM_CONSTRUCTED(priv, 3, LTC_ASN1_CL_CONTEXT_SPECIFIC, 1, custom + 1);

   if ((err = der_decode_sequence_ex(in, inlen, priv, 4, flags)) != CRYPT_OK) return -1;
   err = der_encode_sequence(priv, 4, out, &olen);
   if (err != CRYPT_OK) return -1;
   *outlen = olen;
   return 0;
}

/* ------------------------------------------------------------------ */
/* consumers                                                          */
/* ------------------------------------------------------------------ */

static ecc_key dd_sig_key;
static unsigned char dd_sig_hash[32];
static unsigned long dd_sig_hashlen;

static int dd_cons_sig(const unsigned char *in, unsigned long inlen, int *stat)
{
   *stat = 0;
   return ecc_verify_hash_x962(in, inlen, dd_sig_hash, dd_sig_hashlen, stat, &dd_sig_key);
}

static int dd_cons_spki(const unsigned char *in, unsigned long inlen, int *stat)
{
   rsa_key key;
   int err;

   *stat = 0;
   if ((err = rsa_import(in, inlen, &key)) != CRYPT_OK) return err;
   rsa_free(&key);
   *stat = 1;
   return CRYPT_OK;
}

static int dd_cons_ec(const unsigned char *in, unsigned long inlen, int *stat)
{
   ecc_key key;
   int err;

   *stat = 0;
   if ((err = ecc_import_openssl(in, inlen, &key)) != CRYPT_OK) return err;
   ecc_free(&key);
   *stat = 1;
   return CRYPT_OK;
}

/* ------------------------------------------------------------------ */
/* seeds                                                              */
/* ------------------------------------------------------------------ */

/* RFC 6979 P-256 / SHA-256 signature of "sample".  The r component has the
 * high bit set and therefore carries a 0x00 leading octet. */
static const unsigned char dd_seed_sig[] = {
   0x30,0x46,0x02,0x21,0x00,0xef,0xd4,0x8b,0x2a,0xac,0xb6,0xa8,0xfd,0x11,0x40,0xdd,
   0x9c,0xd4,0x5e,0x81,0xd6,0x9d,0x2c,0x87,0x7b,0x56,0xaa,0xf9,0x91,0xc3,0x4d,0x0e,
   0xa8,0x4e,0xaf,0x37,0x16,0x02,0x21,0x00,0xf7,0xcb,0x1c,0x94,0x2d,0x65,0x7c,0x41,
   0xd4,0x36,0xc7,0xa1,0xb6,0xe2,0x9f,0x65,0xf3,0xe9,0x00,0xdb,0xb9,0xaf,0xf4,0x06,
   0x4d,0xc4,0xab,0x2f,0x84,0x3a,0xcd,0xa8
};

/* X.509 SubjectPublicKeyInfo carrying an RSA public key */
static const unsigned char dd_seed_spki[] = {
   0x30,0x81,0x9f,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,
   0x05,0x00,0x03,0x81,0x8d,0x00,0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xcf,0x9a,0xde,
   0x64,0x8a,0xda,0xc8,0x33,0x20,0xa9,0xd7,0x83,0x31,0x19,0x54,0xb2,0x9a,0x85,0xa7,
   0xa1,0xb7,0x75,0x33,0xb6,0xa9,0xac,0x84,0x24,0xb3,0xde,0xdb,0x7d,0x85,0x2d,0x96,
   0x65,0xe5,0x3f,0x72,0x95,0x24,0x9f,0x28,0x68,0xca,0x4f,0xdb,0x44,0x1c,0x3e,0x60,
   0x12,0x8a,0xdd,0x26,0xa5,0xeb,0xff,0x0b,0x5e,0xd4,0x88,0x38,0x49,0x2a,0x6e,0x5b,
   0xbf,0x12,0x37,0x47,0xbd,0x05,0x6b,0xbc,0xdb,0xf3,0xee,0xe4,0x11,0x8e,0x41,0x68,
   0x7c,0x61,0x13,0xd7,0x42,0xc8,0x80,0xbe,0x36,0x8f,0xdc,0x08,0x8b,0x4f,0xac,0xa4,
   0xe2,0x76,0x0c,0xc9,0x63,0x6c,0x49,0x58,0x93,0xed,0xcc,0xaa,0xdc,0x25,0x3b,0x0a,
   0x60,0x3f,0x8b,0x54,0x3a,0xc3,0x4d,0x31,0xe7,0x94,0xa4,0x44,0xfd,0x02,0x03,0x01,
   0x00,0x01
};

/* RFC 5915 ECPrivateKey on the named curve P-256 */
static const unsigned char dd_seed_ec[] = {
   0x30,0x77,0x02,0x01,0x01,0x04,0x20,0xc9,0xaf,0xa9,0xd8,0x45,0xba,0x75,0x16,0x6b,
   0x5c,0x21,0x57,0x67,0xb1,0xd6,0x93,0x4e,0x50,0xc3,0xdb,0x36,0xe8,0x9b,0x12,0x7b,
   0x8a,0x62,0x2b,0x12,0x0f,0x67,0x21,0xa0,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,
   0x03,0x01,0x07,0xa1,0x44,0x03,0x42,0x00,0x04,0x60,0xfe,0xd4,0xba,0x25,0x5a,0x9d,
   0x31,0xc9,0x61,0xeb,0x74,0xc6,0x35,0x6d,0x68,0xc0,0x49,0xb8,0x92,0x3b,0x61,0xfa,
   0x6c,0xe6,0x69,0x62,0x2e,0x60,0xf2,0x9f,0xb6,0x79,0x03,0xfe,0x10,0x08,0xb8,0xbc,
   0x99,0xa4,0x1a,0xe9,0xe9,0x56,0x28,0xbc,0x64,0xf2,0xf1,0xb2,0x0c,0x2d,0x7e,0x9f,
   0x51,0x77,0xa3,0xc2,0x94,0xd4,0x46,0x22,0x99
};

typedef struct {
   const char *name;
   const unsigned char *seed;
   unsigned long seedlen;
   int (*dec)(const unsigned char *, unsigned long, unsigned int, unsigned char *, unsigned long *);
   int (*consumer)(const unsigned char *, unsigned long, int *);
   int authenticating;
} dd_schema;

/* ------------------------------------------------------------------ */
/* differential driver                                                */
/* ------------------------------------------------------------------ */

static unsigned long dd_rng;
static unsigned long dd_cases;
static unsigned long dd_failures;

static unsigned long dd_rand(void)
{
   dd_rng ^= dd_rng << 13;
   dd_rng ^= dd_rng >> 7;
   dd_rng ^= dd_rng << 17;
   return dd_rng;
}

static void dd_dump(const unsigned char *in, unsigned long inlen)
{
   unsigned long i;

   for (i = 0; i < inlen && i < 48; i++) fprintf(stderr, "%02x", in[i]);
   if (inlen > 48) fprintf(stderr, "...");
}

static void dd_fail(const dd_schema *s, const char *rule, const char *what,
                    const unsigned char *in, unsigned long inlen)
{
   dd_failures++;
   fprintf(stderr, "FAIL[%s] %s: %s (len=%lu)\n   ", rule, s->name, what, inlen);
   dd_dump(in, inlen);
   fprintf(stderr, "\n");
}

/* Fetch / compare helpers; a decoder "accepts" when it returns 0. */
typedef struct {
   int flexi_ok;
   unsigned long flexi_len;
   int relaxed_ok;
   int strict_ok;
   int allstrict_ok;
   int consumer_ok;
   int consumer_stat;
   unsigned long relaxed_len;
   unsigned long strict_len;
   unsigned long allstrict_len;
} dd_verdict;

static void dd_eval(const dd_schema *s, const unsigned char *in, unsigned long inlen,
                    dd_verdict *v, unsigned char *rok, unsigned char *sok, unsigned char *aok)
{
   unsigned long slen;
   ltc_asn1_list *list = NULL;

   v->flexi_len = inlen;
   v->flexi_ok  = der_decode_sequence_flexi(in, &v->flexi_len, &list) == CRYPT_OK;
   if (v->flexi_ok) der_sequence_free(list);

   slen = DD_MAX_BUF;
   v->relaxed_ok = s->dec(in, inlen, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_RELAXED,
                          rok, &slen) == 0;
   v->relaxed_len = slen;

   slen = DD_MAX_BUF;
   v->strict_ok = s->dec(in, inlen, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_STRICT,
                         sok, &slen) == 0;
   v->strict_len = slen;

   slen = DD_MAX_BUF;
   v->allstrict_ok = s->dec(in, inlen, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_ALL_STRICT,
                            aok, &slen) == 0;
   v->allstrict_len = slen;

   /* The consumers reject an empty input through LTC_ARGCHK, which aborts in
    * ARGTYPE==0 builds; an empty buffer carries no structure so skip it. */
   v->consumer_stat = 0;
   v->consumer_ok = inlen != 0 &&
                    s->consumer(in, inlen, &v->consumer_stat) == CRYPT_OK;
}

static void dd_check(const dd_schema *s, const char *what,
                     const unsigned char *in, unsigned long inlen)
{
   dd_verdict v;
   unsigned char rok[DD_MAX_BUF], sok[DD_MAX_BUF], aok[DD_MAX_BUF];
   unsigned char tmp[DD_MAX_BUF];
   unsigned long tlen;

   dd_cases++;
   dd_eval(s, in, inlen, &v, rok, sok, aok);

   /* R1: the accepted sets are nested, all-strict <= strict <= relaxed */
   if (v.strict_ok && !v.relaxed_ok)
      dd_fail(s, "R1", "strict accepts what relaxed rejects", in, inlen);
   if (v.allstrict_ok && !v.strict_ok)
      dd_fail(s, "R1", "all-strict accepts what strict rejects", in, inlen);

   /* R2: strict re-encoding is accepted by the strictest decoder */
   if (v.strict_ok) {
      tlen = DD_MAX_BUF;
      if (s->dec(sok, v.strict_len, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_ALL_STRICT,
                 tmp, &tlen) != 0)
         dd_fail(s, "R2", "re-encoding of strict result rejected by all-strict", in, inlen);
   }

   /* R3: strict decode reaches a fixpoint */
   if (v.strict_ok) {
      tlen = DD_MAX_BUF;
      if (s->dec(sok, v.strict_len, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_STRICT,
                 tmp, &tlen) != 0 ||
          tlen != v.strict_len || XMEMCMP(tmp, sok, tlen) != 0)
         dd_fail(s, "R3", "strict decode not a fixpoint", in, inlen);
   }

   /* R4: relaxed re-encoding is canonical and relaxed-idempotent */
   if (v.relaxed_ok) {
      tlen = DD_MAX_BUF;
      if (s->dec(rok, v.relaxed_len, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_ALL_STRICT,
                 tmp, &tlen) != 0)
         dd_fail(s, "R4", "re-encoding of relaxed result rejected by all-strict", in, inlen);
      tlen = DD_MAX_BUF;
      if (s->dec(rok, v.relaxed_len, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_RELAXED,
                 tmp, &tlen) != 0 ||
          tlen != v.relaxed_len || XMEMCMP(tmp, rok, tlen) != 0)
         dd_fail(s, "R4", "relaxed decode not a fixpoint", in, inlen);
   }

   /* R5: the flexi decoder never over-consumes */
   if (v.flexi_ok && v.flexi_len > inlen)
      dd_fail(s, "R5", "flexi decoder consumed more than the input", in, inlen);

   /* R10: consumer acceptance implies relaxed acceptance */
   if (v.consumer_ok && !v.relaxed_ok)
      dd_fail(s, "R10", "consumer accepts what relaxed decoder rejects", in, inlen);

   /* R11: only the exact seed may authenticate */
   if (s->authenticating && v.consumer_ok && v.consumer_stat == 1 &&
       !(inlen == s->seedlen && XMEMCMP(in, s->seed, inlen) == 0))
      dd_fail(s, "R11", "unauthenticated data verified as a signature", in, inlen);

   LTC_UNUSED_PARAM(what);
}

/* Wrap rewrites of the seed with their dedicated known-answer checks. */
static void dd_structural(const dd_schema *s, int mode, int target, const char *rule)
{
   unsigned char buf[DD_MAX_BUF], out[DD_MAX_BUF];
   unsigned long blen;
   unsigned char rok[DD_MAX_BUF];
   unsigned long rlen;
   int err;

   if (dd_rewrite(s->seed, s->seedlen, mode, target, buf, &blen)) return;

   /* The relaxed decoder re-encodes canonically, so the rewritten input must
    * decode to the original seed bytes.  Only the length of the outermost
    * element may be non-minimal: the decoders walk nested elements by their
    * canonical length, so an inner non-minimal length cannot be resynchronized
    * and both decoders reject such input. */
   rlen = DD_MAX_BUF;
   err = s->dec(buf, blen, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_RELAXED, rok, &rlen);
   if (target == 0) {
      /* R8/R9 known answer: accepted, normalized to the seed, rejected when
       * the strictest decoder is asked for a minimal encoding. */
      if (err != 0)
         dd_fail(s, rule, "relaxed decoder rejects a structurally valid variant", buf, blen);
      if (err == 0 && (rlen != s->seedlen || XMEMCMP(rok, s->seed, rlen) != 0))
         dd_fail(s, rule, "re-encoding does not normalize to the seed", buf, blen);
      rlen = DD_MAX_BUF;
      if (s->dec(buf, blen, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_ALL_STRICT, out, &rlen) == 0)
         dd_fail(s, rule, "all-strict decoder accepts a non-canonical encoding", buf, blen);
   } else {
      /* an inner rewrite is simply outside the accepted set */
      if (err == 0)
         dd_fail(s, rule, "relaxed decoder accepts a non-resynchronizable inner length", buf, blen);
   }

   /* and the variant must still be exercised by the general differential */
   dd_check(s, rule, buf, blen);
}

static void dd_corpus(const dd_schema *s)
{
   unsigned char buf[DD_MAX_BUF + 16];
   unsigned long i;
   unsigned int bit;
   int idx;

   /* the seed itself must be canonical and accepted everywhere */
   if (dd_oracle(s->seed, s->seedlen) != DD_CANON) {
      dd_fail(s, "seed", "seed is not canonical DER", s->seed, s->seedlen);
   }
   dd_check(s, "seed", s->seed, s->seedlen);

   /* R7: proper prefixes are rejected and exercised */
   for (i = 0; i < s->seedlen; i++) {
      unsigned char r[DD_MAX_BUF], a[DD_MAX_BUF];
      unsigned long l;
      l = DD_MAX_BUF;
      if (s->dec(s->seed, i, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_RELAXED, r, &l) == 0)
         dd_fail(s, "R7", "relaxed decoder accepts a truncated prefix", s->seed, i);
      l = DD_MAX_BUF;
      if (s->dec(s->seed, i, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_STRICT, r, &l) == 0)
         dd_fail(s, "R7", "strict decoder accepts a truncated prefix", s->seed, i);
      l = DD_MAX_BUF;
      if (s->dec(s->seed, i, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_ALL_STRICT, a, &l) == 0)
         dd_fail(s, "R7", "all-strict decoder accepts a truncated prefix", s->seed, i);
      dd_check(s, "prefix", s->seed, i);
   }

   /* R6: trailing bytes are rejected; flexi consumes exactly the seed */
   for (i = 1; i <= 8; i++) {
      unsigned char r[DD_MAX_BUF], a[DD_MAX_BUF];
      unsigned long l;
      ltc_asn1_list *list = NULL;
      unsigned long flen = s->seedlen + 1;
      int ferr;

      XMEMCPY(buf, s->seed, s->seedlen);
      buf[s->seedlen] = (unsigned char)(i == 1 ? 0 : dd_rand());

      l = DD_MAX_BUF;
      if (s->dec(buf, s->seedlen + 1, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_RELAXED, r, &l) == 0)
         dd_fail(s, "R6", "relaxed decoder accepts trailing data", buf, s->seedlen + 1);
      l = DD_MAX_BUF;
      if (s->dec(buf, s->seedlen + 1, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_STRICT, r, &l) == 0)
         dd_fail(s, "R6", "strict decoder accepts trailing data", buf, s->seedlen + 1);
      l = DD_MAX_BUF;
      if (s->dec(buf, s->seedlen + 1, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_ALL_STRICT, a, &l) == 0)
         dd_fail(s, "R6", "all-strict decoder accepts trailing data", buf, s->seedlen + 1);

      ferr = der_decode_sequence_flexi(buf, &flen, &list);
      if (ferr == CRYPT_OK && flen != s->seedlen)
         dd_fail(s, "R6", "flexi decoder does not stop at the seed boundary", buf, s->seedlen + 1);
      if (ferr == CRYPT_OK) der_sequence_free(list);

      dd_check(s, "trailing", buf, s->seedlen + 1);
   }

   /* single bit flips */
   for (i = 0; i < s->seedlen; i++) {
      for (bit = 0; bit < 8; bit++) {
         XMEMCPY(buf, s->seed, s->seedlen);
         buf[i] ^= (unsigned char)(1u << bit);
         dd_check(s, "bitflip", buf, s->seedlen);
      }
   }

   /* random overwrites, bounded and deterministic */
   for (i = 0; i < 64; i++) {
      unsigned long pos = dd_rand() % s->seedlen;
      int k;
      XMEMCPY(buf, s->seed, s->seedlen);
      for (k = 0; k < 3; k++) {
         pos = (pos + 7) % s->seedlen;
         buf[pos] = (unsigned char)dd_rand();
      }
      dd_check(s, "random", buf, s->seedlen);
   }

   /* R8/R9 structural rewrites for every node in the parse tree.  The
    * outermost length is the only one a decoder can resynchronize (see
    * dd_structural); inner lengths and redundant INTEGER zeroes still make
    * useful negative cases and are fed through the general differential. */
   {
      dd_parse p;
      p.nn = 0; p.bad_struct = 0; p.bad_len = 0; p.bad_val = 0; p.first_end = 0;
      if (dd_parse_rec((unsigned char *)s->seed, s->seedlen, 0, 0, &p) == 0) {
         for (idx = 0; idx < p.nn; idx++) {
            dd_structural(s, DD_M_LONGLEN, idx, "R8");
            /* a redundant leading zero only makes sense on an INTEGER */
            if ((p.n[idx].id & 0xc0) == 0 && !(p.n[idx].id & 0x20) && p.n[idx].tag == 2) {
               dd_structural(s, DD_M_REDZERO, idx, "R9");
            }
         }
      }
   }
}

int der_diff_test(void)
{
   static const dd_schema schemas[] = {
      { "sig",  dd_seed_sig,  sizeof(dd_seed_sig),  dd_dec_sig,  dd_cons_sig,  1 },
      { "spki", dd_seed_spki, sizeof(dd_seed_spki), dd_dec_spki, dd_cons_spki, 0 },
      { "ec",   dd_seed_ec,   sizeof(dd_seed_ec),   dd_dec_ec,   dd_cons_ec,   0 },
   };
   static const unsigned char sig_priv[] = {
      0xc9,0xaf,0xa9,0xd8,0x45,0xba,0x75,0x16,0x6b,0x5c,0x21,0x57,0x67,0xb1,0xd6,0x93,
      0x4e,0x50,0xc3,0xdb,0x36,0xe8,0x9b,0x12,0x7b,0x8a,0x62,0x2b,0x12,0x0f,0x67,0x21
   };
   const ltc_ecc_curve *curve;
   int hash_idx;
   unsigned long i;
   int err;

   if (ltc_mp.name == NULL) return CRYPT_NOP;

   /* The authenticating seed needs SHA-256 and P-256; without them there is
    * no vector to verify and the whole differential is skipped. */
   if ((hash_idx = find_hash("sha256")) < 0) return CRYPT_NOP;
   if (ecc_find_curve("P-256", &curve) != CRYPT_OK)        return CRYPT_NOP;

   if ((err = ltc_mp_init_multi(&dd_mp1, &dd_mp2, LTC_NULL)) != CRYPT_OK) return err;

   /* consumer key: the private key matching the seed signature */
   if ((err = ecc_set_curve(curve, &dd_sig_key)) != CRYPT_OK) goto out;
   if ((err = ecc_set_key(sig_priv, sizeof(sig_priv), PK_PRIVATE, &dd_sig_key)) != CRYPT_OK)
      goto out;

   dd_sig_hashlen = sizeof(dd_sig_hash);
   if ((err = hash_memory(hash_idx, (const unsigned char *)"sample", 6,
                          dd_sig_hash, &dd_sig_hashlen)) != CRYPT_OK)
      goto out;

   /* the seed must be a valid signature so that R11 is meaningful */
   {
      int stat = 0;
      err = dd_cons_sig(dd_seed_sig, sizeof(dd_seed_sig), &stat);
      if (err != CRYPT_OK || stat != 1) {
         ecc_free(&dd_sig_key);
         err = CRYPT_FAIL_TESTVECTOR;
         goto out;
      }
   }

   dd_rng = CONST64(0x9e3779b97f4a7c15);
   dd_cases = 0;
   dd_failures = 0;

   for (i = 0; i < LTC_ARRAY_SIZE(schemas); i++) {
      dd_corpus(&schemas[i]);
   }

   /* The corpus is deterministic; refuse to pass silently if it shrank to
    * nothing (e.g. a seed could not be parsed) or if the budget was exceeded. */
   if (dd_cases < DD_MIN_CASES || dd_cases > DD_MAX_CASES) {
      fprintf(stderr, "der_diff: corpus size %lu outside [%lu, %lu]\n",
              dd_cases, (unsigned long)DD_MIN_CASES, (unsigned long)DD_MAX_CASES);
      ecc_free(&dd_sig_key);
      err = CRYPT_FAIL_TESTVECTOR;
      goto out;
   }

   ecc_free(&dd_sig_key);
   err = CRYPT_OK;

out:
   ltc_mp_deinit_multi(dd_mp1, dd_mp2, LTC_NULL);
   if (err != CRYPT_OK) return err;
   if (dd_failures != 0) {
      fprintf(stderr, "der_diff: %lu failures in %lu cases\n", dd_failures, dd_cases);
      return CRYPT_FAIL_TESTVECTOR;
   }
   return CRYPT_OK;
}

#endif
