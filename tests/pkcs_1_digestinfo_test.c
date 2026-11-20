/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#if defined(LTC_MRSA)

/**
  @file pkcs_1_digestinfo_test.c

  Regression tests for the ASN.1 DigestInfo handling of PKCS #1 v1.5
  signatures in rsa_verify_hash_v2().

  A PKCS #1 v1.5 signature is accepted when the EMSA-PKCS1-v1_5 encoding

     00 || 01 || PS (0xff ...) || 00 || DigestInfo

  carries a DigestInfo (RFC 8017, section 9.2) whose AlgorithmIdentifier
  names the hash the caller expects and whose OCTET STRING holds exactly the
  digest the caller supplies.

  The tests below feed deliberately malformed DigestInfo encodings, signed
  with the repository's test key, to the verifier.  For every input class the
  expected outcome is pinned down explicitly: either the verifier must reject
  the signature (returning CRYPT_OK but stat == 0) or the input is accepted
  by an existing compatibility convention and must keep resulting in stat == 1.

  Each case asserts both the return code and the `stat` result, and a positive
  control (the canonical encoding) runs through the same code path, so a
  verifier that rejects everything cannot make the test pass.

  The key is the 1024-bit key stored in tests/test.key, embedded as DER in
  ltc_rsa_private_test_key[].  No key is generated at runtime, which keeps the
  test reproducible and independent of the PRNG.
*/

#define DI_BUFSIZE 256

enum di_len_form {
   DI_LEN_CANON,
   DI_LEN_LONG1,      /* 0x81 <len> */
   DI_LEN_LONG2_ZERO  /* 0x82 0x00 <len> */
};

enum di_null_form {
   DI_NULL_ABSENT,     /* AlgorithmIdentifier without a parameters field */
   DI_NULL_CANON,      /* 05 00 */
   DI_NULL_BAD_LEN,    /* 05 01 00, a non-DER NULL */
   DI_NULL_AS_INTEGER  /* 02 01 00, parameters that are not NULL */
};

typedef struct {
   const unsigned char *oid;
   unsigned long        oidlen;
   enum di_len_form     oid_len_form;
   enum di_null_form    null_form;
   int                  extra_null;
   enum di_len_form     alg_len_form;
   const unsigned char *digest;
   unsigned long        digestlen;
   enum di_len_form     oct_len_form;
   int                  include_octet;
   enum di_len_form     outer_len_form;
   int                  outer_len_extra;
   int                  inner_trailing;
   int                  outer_trailing;
   int                  truncate;
   int                  omit_outer;
   unsigned char        outer_tag;
   unsigned char        alg_tag;
   unsigned char        oct_tag;
} di_shape;

typedef struct {
   const char          *name;
   di_shape             shape;
   const unsigned char *hash;
   unsigned long        hashlen;
   int                  hash_idx;
   int                  expected_err;
   int                  expected_stat;
} di_case;

static unsigned long s_put_len(unsigned char *out, unsigned long len, enum di_len_form form)
{
   switch (form) {
      case DI_LEN_LONG1:
         out[0] = 0x81;
         out[1] = (unsigned char)len;
         return 2;
      case DI_LEN_LONG2_ZERO:
         out[0] = 0x82;
         out[1] = 0x00;
         out[2] = (unsigned char)len;
         return 3;
      case DI_LEN_CANON:
      default:
         out[0] = (unsigned char)len;
         return 1;
   }
}

/* Build a DigestInfo according to shape.  All lengths fit into one octet for
 * the sizes used here, so the target buffer cannot overflow. */
static unsigned long s_build_digestinfo(unsigned char *out, const di_shape *shape)
{
   unsigned char content[DI_BUFSIZE], inner[DI_BUFSIZE];
   unsigned long clen = 0, ilen = 0, x, n;
   long declared;

   /* AlgorithmIdentifier content: OID plus optional parameters */
   content[clen++] = 0x06;
   n = s_put_len(content + clen, shape->oidlen, shape->oid_len_form);
   clen += n;
   XMEMCPY(content + clen, shape->oid, shape->oidlen);
   clen += shape->oidlen;
   switch (shape->null_form) {
      case DI_NULL_CANON:
         content[clen++] = 0x05;
         content[clen++] = 0x00;
         break;
      case DI_NULL_BAD_LEN:
         content[clen++] = 0x05;
         content[clen++] = 0x01;
         content[clen++] = 0x00;
         break;
      case DI_NULL_AS_INTEGER:
         content[clen++] = 0x02;
         content[clen++] = 0x01;
         content[clen++] = 0x00;
         break;
      case DI_NULL_ABSENT:
      default:
         break;
   }
   if (shape->extra_null) {
      content[clen++] = 0x05;
      content[clen++] = 0x00;
   }

   /* AlgorithmIdentifier SEQUENCE */
   inner[ilen++] = shape->alg_tag;
   n = s_put_len(inner + ilen, clen, shape->alg_len_form);
   ilen += n;
   XMEMCPY(inner + ilen, content, clen);
   ilen += clen;

   /* digest OCTET STRING */
   if (shape->include_octet) {
      inner[ilen++] = shape->oct_tag;
      n = s_put_len(inner + ilen, shape->digestlen, shape->oct_len_form);
      ilen += n;
      XMEMCPY(inner + ilen, shape->digest, shape->digestlen);
      ilen += shape->digestlen;
   }
   if (shape->inner_trailing) {
      inner[ilen++] = 0x05;
      inner[ilen++] = 0x00;
   }

   /* outer DigestInfo SEQUENCE */
   if (shape->omit_outer) {
      XMEMCPY(out, inner, ilen);
      return ilen;
   }
   declared = (long)ilen + shape->outer_len_extra;
   out[0] = shape->outer_tag;
   n = s_put_len(out + 1, (unsigned long)declared, shape->outer_len_form);
   XMEMCPY(out + 1 + n, inner, ilen);
   x = 1 + n + ilen;
   if (shape->outer_trailing) {
      out[x++] = 0x00;
   }
   if (shape->truncate) {
      x--;
   }
   return x;
}

static di_shape s_base_shape(const unsigned char *oid, unsigned long oidlen,
                             const unsigned char *digest, unsigned long digestlen)
{
   di_shape shape;

   XMEMSET(&shape, 0, sizeof(shape));
   shape.oid = oid;
   shape.oidlen = oidlen;
   shape.oid_len_form = DI_LEN_CANON;
   shape.null_form = DI_NULL_CANON;
   shape.alg_len_form = DI_LEN_CANON;
   shape.digest = digest;
   shape.digestlen = digestlen;
   shape.oct_len_form = DI_LEN_CANON;
   shape.include_octet = 1;
   shape.outer_len_form = DI_LEN_CANON;
   shape.outer_tag = 0x30;
   shape.alg_tag = 0x30;
   shape.oct_tag = 0x04;
   return shape;
}

static di_case s_make_case(const char *name, const di_shape *shape,
                           const unsigned char *hash, unsigned long hashlen,
                           int hash_idx, int expected_err, int expected_stat)
{
   di_case c;

   c.name = name;
   c.shape = *shape;
   c.hash = hash;
   c.hashlen = hashlen;
   c.hash_idx = hash_idx;
   c.expected_err = expected_err;
   c.expected_stat = expected_stat;
   return c;
}

/* Sign the raw bytes with PKCS #1 v1.5 block type 1 but without ASN.1
 * encoding, i.e. the signature is exactly over the bytes we generated. */
static int s_sign_raw_emsa(const unsigned char *data, unsigned long datalen,
                           unsigned char *sig, unsigned long *siglen,
                           const rsa_key *key)
{
   ltc_rsa_op_parameters params;

   XMEMSET(&params, 0, sizeof(params));
   params.params.hash_idx = -1;
   params.params.mgf1_hash_idx = -1;
   params.padding = LTC_PKCS_1_V1_5_NA1;
   return rsa_sign_hash_v2(data, datalen, sig, siglen, &params, key);
}

static int s_verify_v1_5(const unsigned char *sig, unsigned long siglen,
                         const unsigned char *hash, unsigned long hashlen,
                         int hash_idx, int *stat, const rsa_key *key)
{
   ltc_rsa_op_parameters params;

   XMEMSET(&params, 0, sizeof(params));
   params.params.hash_idx = hash_idx;
   params.padding = LTC_PKCS_1_V1_5;
   return rsa_verify_hash_v2(sig, siglen, hash, hashlen, &params, stat, key);
}

static int s_run_digestinfo_case(const di_case *c, const rsa_key *key)
{
   unsigned char di[DI_BUFSIZE], sig[2 * DI_BUFSIZE];
   unsigned long dilen, siglen = sizeof(sig);
   int err, stat;

   dilen = s_build_digestinfo(di, &c->shape);
   if ((err = s_sign_raw_emsa(di, dilen, sig, &siglen, key)) != CRYPT_OK) {
      fprintf(stderr, "DigestInfo '%s': could not create signature: %s\n",
              c->name, error_to_string(err));
      return CRYPT_FAIL_TESTVECTOR;
   }
   stat = -1;
   err = s_verify_v1_5(sig, siglen, c->hash, c->hashlen, c->hash_idx, &stat, key);
   if ((err != c->expected_err) || (stat != c->expected_stat)) {
      fprintf(stderr, "DigestInfo '%s': verifier returned %s (stat=%d), "
                      "expected %s (stat=%d)\n",
              c->name, error_to_string(err), stat,
              error_to_string(c->expected_err), c->expected_stat);
      print_hex("DigestInfo", di, dilen);
      return CRYPT_FAIL_TESTVECTOR;
   }
   return CRYPT_OK;
}

/* Verify that the canonical builder output is byte for byte the standard
 * EMSA-PKCS1-v1_5 DigestInfo for the given hash. */
static int s_check_canonical_encoding(const unsigned char *oid, unsigned long oidlen,
                                      const unsigned char *digest, unsigned long digestlen,
                                      const unsigned char *prefix, unsigned long prefixlen)
{
   unsigned char di[DI_BUFSIZE];
   unsigned long dilen;
   di_shape shape;

   shape = s_base_shape(oid, oidlen, digest, digestlen);
   dilen = s_build_digestinfo(di, &shape);
   if (dilen != prefixlen + digestlen) {
      fprintf(stderr, "DigestInfo canonical encoding has length %lu, expected %lu\n",
              dilen, prefixlen + digestlen);
      return CRYPT_FAIL_TESTVECTOR;
   }
   if (XMEMCMP(di, prefix, prefixlen) != 0) {
      print_hex("DigestInfo canonical encoding", di, prefixlen);
      return CRYPT_FAIL_TESTVECTOR;
   }
   return CRYPT_OK;
}

int pkcs_1_digestinfo_test(void)
{
   static const unsigned char msg[] = "LibTomCrypt PKCS #1 v1.5 DigestInfo regression test";
   static const unsigned char other_msg[] = "LibTomCrypt PKCS #1 v1.5 DigestInfo regression test (other)";
   /* DER content octets of the hash OIDs */
   static const unsigned char oid_sha1[] = {
      0x2b, 0x0e, 0x03, 0x02, 0x1a };
   static const unsigned char oid_sha224[] = {
      0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 };
   static const unsigned char oid_sha256[] = {
      0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
   static const unsigned char oid_sha256_extra_arc[] = {
      0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x01 };
   /* same length as the SHA-256 OID, only the last arc differs */
   static const unsigned char oid_sha256_last_arc[] = {
      0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
   static const unsigned char oid_sha256_padded[] = {
      0x60, 0x80, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
   /* SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING } header without digest */
   static const unsigned char sha1_di_prefix[] = {
      0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
      0x05, 0x00, 0x04, 0x14 };
   static const unsigned char sha256_di_prefix[] = {
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
      0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

   unsigned char d_sha256[MAXBLOCKSIZE], d_sha256_other[MAXBLOCKSIZE], d_sha1[MAXBLOCKSIZE];
   unsigned char d_sha256_long[MAXBLOCKSIZE + 1];
   unsigned long d_sha256_len = sizeof(d_sha256), d_sha256_other_len = sizeof(d_sha256_other);
   unsigned long d_sha1_len = sizeof(d_sha1);
   unsigned char di[DI_BUFSIZE], sig[2 * DI_BUFSIZE], sig_long[2 * DI_BUFSIZE + 1];
   unsigned long dilen, siglen;
   int h256, h1, err, stat, i;
   unsigned int ncases = 0;
   di_case cases[48];
   di_shape s;
   rsa_key key;

   if (ltc_mp.name == NULL) return CRYPT_NOP;

   h256 = find_hash("sha256");
   DO(hash_is_valid(h256));
   h1 = find_hash("sha1");

   DO(hash_memory(h256, msg, sizeof(msg) - 1, d_sha256, &d_sha256_len));
   DO(hash_memory(h256, other_msg, sizeof(other_msg) - 1, d_sha256_other, &d_sha256_other_len));
   XMEMCPY(d_sha256_long, d_sha256, d_sha256_len);
   d_sha256_long[d_sha256_len] = 0x00;
   if (hash_is_valid(h1) == CRYPT_OK) {
      DO(hash_memory(h1, msg, sizeof(msg) - 1, d_sha1, &d_sha1_len));
   }

   /* the canonical encoding must be the standard DigestInfo */
   DO(s_check_canonical_encoding(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len,
                                 sha256_di_prefix, sizeof(sha256_di_prefix)));
   if (hash_is_valid(h1) == CRYPT_OK) {
      DO(s_check_canonical_encoding(oid_sha1, sizeof(oid_sha1), d_sha1, d_sha1_len,
                                    sha1_di_prefix, sizeof(sha1_di_prefix)));
   }

   DO(rsa_import(ltc_rsa_private_test_key, ltc_rsa_private_test_key_sz, &key));

   /* ---- accepted: well formed DigestInfo ---- */
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   cases[ncases++] = s_make_case("canonical SHA-256 DigestInfo", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 1);
   if (hash_is_valid(h1) == CRYPT_OK) {
      s = s_base_shape(oid_sha1, sizeof(oid_sha1), d_sha1, d_sha1_len);
      cases[ncases++] = s_make_case("canonical SHA-1 DigestInfo", &s,
                                    d_sha1, d_sha1_len, h1, CRYPT_OK, 1);
   }

   /* ---- accepted by an existing compatibility convention ----
    * rsa_verify_hash_v2() marks the NULL parameters field of the
    * AlgorithmIdentifier as optional, so a DigestInfo without it verifies even
    * though RFC 8017 says the parameters field SHALL be NULL.  This leniency is
    * deliberate (it keeps signatures from implementations that omit the field
    * verifiable), so pin it down instead of treating it as a forgery. */
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.null_form = DI_NULL_ABSENT;
   cases[ncases++] = s_make_case("DigestInfo without NULL parameters (accepted convention)", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 1);

   /* ---- rejected: malformed NULL parameters ---- */
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.null_form = DI_NULL_BAD_LEN;
   cases[ncases++] = s_make_case("NULL parameters with length 1", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.null_form = DI_NULL_AS_INTEGER;
   cases[ncases++] = s_make_case("INTEGER parameters instead of NULL", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.extra_null = 1;
   cases[ncases++] = s_make_case("extra NULL in AlgorithmIdentifier", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);

   /* ---- rejected: non-canonical DER length encodings ---- */
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.alg_len_form = DI_LEN_LONG1;
   cases[ncases++] = s_make_case("AlgorithmIdentifier length 0x81", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.alg_len_form = DI_LEN_LONG2_ZERO;
   cases[ncases++] = s_make_case("AlgorithmIdentifier length 0x82 00", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.oid_len_form = DI_LEN_LONG1;
   cases[ncases++] = s_make_case("OID length 0x81", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.oid_len_form = DI_LEN_LONG2_ZERO;
   cases[ncases++] = s_make_case("OID length 0x82 00", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.oct_len_form = DI_LEN_LONG1;
   cases[ncases++] = s_make_case("OCTET STRING length 0x81", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.oct_len_form = DI_LEN_LONG2_ZERO;
   cases[ncases++] = s_make_case("OCTET STRING length 0x82 00", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.outer_len_form = DI_LEN_LONG1;
   cases[ncases++] = s_make_case("DigestInfo length 0x81", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.outer_len_form = DI_LEN_LONG2_ZERO;
   cases[ncases++] = s_make_case("DigestInfo length 0x82 00", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);

   /* ---- rejected: trailing data ---- */
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.inner_trailing = 1;
   cases[ncases++] = s_make_case("trailing element inside DigestInfo", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.outer_trailing = 1;
   cases[ncases++] = s_make_case("trailing octet after DigestInfo", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.outer_len_extra = 1;
   cases[ncases++] = s_make_case("DigestInfo length over-claims one octet", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.outer_len_extra = -1;
   cases[ncases++] = s_make_case("DigestInfo length under-claims one octet", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);

   /* ---- rejected: truncated input ---- */
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.include_octet = 0;
   cases[ncases++] = s_make_case("missing OCTET STRING", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.truncate = 1;
   cases[ncases++] = s_make_case("physically truncated DigestInfo", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.omit_outer = 1;
   cases[ncases++] = s_make_case("missing outer DigestInfo SEQUENCE", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, 31);
   cases[ncases++] = s_make_case("OCTET STRING truncated to 31 octets", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256_long, d_sha256_len + 1);
   cases[ncases++] = s_make_case("OCTET STRING extended to 33 octets", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, 0);
   cases[ncases++] = s_make_case("empty OCTET STRING, 32-octet digest argument", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   cases[ncases++] = s_make_case("32-octet OCTET STRING, empty digest argument", &s,
                                 d_sha256, 0, h256, CRYPT_OK, 0);
   /* ---- rejected: algorithm identifier mismatch ---- */
   s = s_base_shape(oid_sha1, sizeof(oid_sha1), d_sha256, d_sha256_len);
   cases[ncases++] = s_make_case("SHA-1 OID, verifier expects SHA-256", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   if (hash_is_valid(h1) == CRYPT_OK) {
      s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha1, d_sha1_len);
      cases[ncases++] = s_make_case("SHA-256 OID, verifier expects SHA-1", &s,
                                    d_sha1, d_sha1_len, h1, CRYPT_OK, 0);
   }
   s = s_base_shape(oid_sha224, sizeof(oid_sha224), d_sha256, d_sha256_len);
   cases[ncases++] = s_make_case("SHA-224 OID, verifier expects SHA-256", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256_extra_arc, sizeof(oid_sha256_extra_arc), d_sha256, d_sha256_len);
   cases[ncases++] = s_make_case("SHA-256 OID with an extra arc", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256_last_arc, sizeof(oid_sha256_last_arc), d_sha256, d_sha256_len);
   cases[ncases++] = s_make_case("SHA-256 OID with a different last arc", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256_padded, sizeof(oid_sha256_padded), d_sha256, d_sha256_len);
   cases[ncases++] = s_make_case("SHA-256 OID padded with a 0x80 octet", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256) - 1, d_sha256, d_sha256_len);
   cases[ncases++] = s_make_case("SHA-256 OID truncated by one octet", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);

   /* ---- rejected: digest mismatch ---- */
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   cases[ncases++] = s_make_case("DigestInfo holds another digest", &s,
                                 d_sha256_other, d_sha256_other_len, h256, CRYPT_OK, 0);

   /* ---- rejected: wrong ASN.1 tags ---- */
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.outer_tag = 0x31;
   cases[ncases++] = s_make_case("DigestInfo encoded as SET", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.alg_tag = 0x31;
   cases[ncases++] = s_make_case("AlgorithmIdentifier encoded as SET", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.oct_tag = 0x24;
   cases[ncases++] = s_make_case("constructed OCTET STRING", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   s.oct_tag = 0x05;
   cases[ncases++] = s_make_case("digest tagged as NULL", &s,
                                 d_sha256, d_sha256_len, h256, CRYPT_OK, 0);

   /* ---- accepted: documented boundary of the digest length check ----
    * The digest argument is supplied by the caller, not by the signature, so an
    * empty OCTET STRING only matches an empty digest argument.  This is the
    * behaviour of the length comparison in the verifier and not reachable
    * through a forged DigestInfo alone. */
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, 0);
   cases[ncases++] = s_make_case("empty OCTET STRING with empty digest argument (accepted)", &s,
                                 d_sha256, 0, h256, CRYPT_OK, 1);

   for (i = 0; i < (int)ncases; i++) {
      DOX(s_run_digestinfo_case(&cases[i], &key), cases[i].name);
   }

   /* ---- rejected: truncated signature ----
    * A signature that is not exactly as long as the modulus is refused before
    * any depadding happens; stat must stay cleared. */
   s = s_base_shape(oid_sha256, sizeof(oid_sha256), d_sha256, d_sha256_len);
   dilen = s_build_digestinfo(di, &s);
   siglen = sizeof(sig);
   DO(s_sign_raw_emsa(di, dilen, sig, &siglen, &key));

   stat = -1;
   err = s_verify_v1_5(sig, siglen - 1, d_sha256, d_sha256_len, h256, &stat, &key);
   if (err != CRYPT_INVALID_PACKET || stat != 0) {
      fprintf(stderr, "DigestInfo 'signature one octet short': got %s (stat=%d)\n",
              error_to_string(err), stat);
   }
   DOX((err == CRYPT_INVALID_PACKET && stat == 0) ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR,
       "signature one octet short");

   XMEMCPY(sig_long, sig, siglen);
   sig_long[siglen] = 0x00;
   stat = -1;
   err = s_verify_v1_5(sig_long, siglen + 1, d_sha256, d_sha256_len, h256, &stat, &key);
   if (err != CRYPT_INVALID_PACKET || stat != 0) {
      fprintf(stderr, "DigestInfo 'signature one octet long': got %s (stat=%d)\n",
              error_to_string(err), stat);
   }
   DOX((err == CRYPT_INVALID_PACKET && stat == 0) ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR,
       "signature one octet long");

   /* the same canonical DigestInfo must still verify with an intact signature */
   stat = -1;
   err = s_verify_v1_5(sig, siglen, d_sha256, d_sha256_len, h256, &stat, &key);
   DOX((err == CRYPT_OK && stat == 1) ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR,
       "intact signature after length checks");

   rsa_free(&key);
   return CRYPT_OK;
}

#else
LTC_NOP_TEST(pkcs_1_digestinfo_test)
#endif
