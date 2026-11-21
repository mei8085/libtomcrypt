# AEAD authenticated decryption: the contract between tag truncation, length checks, plaintext visibility and caller error handling

Status: source-analysis report with runtime verification on `task/247` (commit `8cb3933`).
Scope: the seven AEAD constructions shipped by LibTomCrypt — GCM (`LTC_GCM_MODE`), CCM (`LTC_CCM_MODE`),
EAX (`LTC_EAX_MODE`), OCB3 (`LTC_OCB3_MODE`), ChaCha20-Poly1305 (`LTC_CHACHA20POLY1305_MODE`),
AES-SIV (`LTC_SIV_MODE`) and AES-GCM-SIV (`LTC_GCM_SIV_MODE`).

---

## 1. Why this needs a report

"AEAD decrypt succeeded" is not a single property. In this codebase it is the conjunction of at least
five independent conditions, and different modes express them through *different* APIs:

1. the caller chose a tag length that the verifier will actually check;
2. the tag comparison happens over a well-defined prefix and in constant time;
3. the length fields that enter the MAC are the same ones the peer encoded;
4. the plaintext buffer the caller may read is either authentic or provably scrubbed;
5. the return value / out-parameter the caller inspects actually carries the authentication verdict.

The modes disagree on (1), (4) and (5). Two modes (`eax_decrypt_verify_memory`,
`ocb3_decrypt_verify_memory`) return `CRYPT_OK` on a *failed* tag and put the verdict in `*stat`.
Two different modes treat a zero-length tag as success. One mode (GCM) can *mint* a tag it cannot
*verify*. Three modes do not validate `direction` at all, which is exploitable when it is confused with
an authentication decision. And the "scrub on failure" pattern that CCM and SIV implement correctly is
missing from GCM and ChaCha20-Poly1305.

The rest of the report pins each of these to source lines, then reproduces the interesting ones at
runtime, then proposes changes and names the evidence that is still missing.

---

## 2. The API surface: two families, not one

LibTomCrypt exposes each AEAD twice: a one-shot "memory" call and a streaming triple
(init / process / done). The authentication contract is different in each family.

### 2.1 One-shot decrypt functions

| Mode | Verify entry point | Prototype |
|---|---|---|
| GCM | `gcm_memory` | `src/headers/tomcrypt_mac.h:498` |
| CCM | `ccm_memory` | `src/headers/tomcrypt_mac.h:424` |
| EAX | `eax_decrypt_verify_memory` | `src/headers/tomcrypt_mac.h:312` |
| OCB3 | `ocb3_decrypt_verify_memory` | `src/headers/tomcrypt_mac.h:367` |
| ChaCha20-Poly1305 | `chacha20poly1305_memory` | `src/headers/tomcrypt_mac.h:531` |
| SIV | `siv_decrypt_memory`, `siv_memory` | `src/headers/tomcrypt_mac.h:549,555` |
| GCM-SIV | `gcm_siv_memory` | `src/headers/tomcrypt_mac.h:567` |

Only EAX and OCB3 use the `int *stat` out-parameter; every other mode signals a bad tag with a non-OK
return code. That asymmetry is the root of most of the caller-side risk below.

### 2.2 Streaming decrypt functions

`gcm_process` (`src/headers/tomcrypt_mac.h:490`), `ccm_process` (`:416`), `eax_decrypt` (`:300`),
`ocb3_decrypt`/`ocb3_decrypt_last` (`:353,355`), `chacha20poly1305_decrypt` (`:529`).

None of them verify anything. They decrypt into the caller's plaintext buffer as they go, and the
tag is only produced by the matching `*_done` call. There is no `*_verify` streaming primitive in any
mode. This is inherent to streaming AEAD and is not a bug by itself, but it is a contract that the
documentation states only implicitly (§6).

---

## 3. Authentication success: the precise necessary conditions

### 3.1 GCM

```c
/* src/encauth/gcm/gcm_memory.c:88-105 */
if (direction == GCM_ENCRYPT) {
   if ((err = gcm_done(gcm, tag, taglen)) != CRYPT_OK) goto LTC_ERR;
}
else if (direction == GCM_DECRYPT) {
   unsigned char buf[MAXBLOCKSIZE];
   unsigned long buflen = sizeof(buf);
   if ((err = gcm_done(gcm, buf, &buflen)) != CRYPT_OK) goto LTC_ERR;
   if (buflen != *taglen || XMEM_NEQ(buf, tag, buflen) != 0) {
      err = CRYPT_ERROR;
   }
}
else {
   err = CRYPT_INVALID_ARG;
}
```

`gcm_done` always emits the full tag and reports it as `x` in `[1,16]`
(`src/encauth/gcm/gcm_done.c:65-68`). Therefore on the decrypt path `buflen` is always 16, and
`buflen != *taglen` is true for every `*taglen != 16`. Success is exactly:

- `*taglen == 16`, **and**
- `mem_neq(computed, tag, 16) == 0` (`src/misc/mem_neq.c:29`).

There is **no** minimum-length policy, **no** floor, and — unlike EAX — no prefix comparison. GCM here
is fail-closed with respect to odd tag lengths: `*taglen` of 0, 8 or 32 all produce `CRYPT_ERROR`
(verified at runtime, §5.2). The problem is the opposite direction: the *encrypt* branch of the same
function happily honours a truncated `*taglen` and emits a short tag (probe §5.2), which the decrypt
branch can never accept.

### 3.2 CCM

```c
/* src/encauth/ccm/ccm_memory.c:344-361 */
} else { /* direction == CCM_DECRYPT */
   for (x = 0; x < 16 && x < *taglen; x++) ptTag[x] = tag[x] ^ CTRPAD[x];
   *taglen = x;
   err = XMEM_NEQ(ptTag, PAD, *taglen);
   if (ptlen > 0) copy_or_zeromem(pt, pt_real, ptlen, err);
}
```

Up-front validation at `ccm_memory.c:82` accepts only `*taglen ∈ {4,6,8,10,12,14,16}` and rejects
`headerlen > 0x7fffffff`. Nonce length is 7..13 (`:86`). Crucially the tag length is *not* a free
truncation parameter: it is encoded into `B_0` as the `M` field
(`src/encauth/ccm/ccm_memory.c:155-157`, `(((*taglen - 2)>>1)<<3)`). So the verifier and the producer
must agree on `*taglen` or the MAC input differs and verification fails. Success requires:

- `*taglen` in the CCM legal set, and
- the comparison over exactly `*taglen` bytes of the *decrypted* tag equals the computed `PAD`.

`ccm_memory` also returns `CRYPT_ERROR` (= enum value 1) because `XMEM_NEQ` returns 0/1 and the code
assigns that directly to `err`. `src/encauth/ccm/ccm_memory.c:352-355` carries a comment acknowledging
this relies on `CRYPT_ERR == 1`; see §9 for why that is fragile.

### 3.3 EAX

```c
/* src/encauth/eax/eax_decrypt_verify_memory.c:81-91 */
buflen = taglen;
if ((err = eax_done(eax, buf, &buflen)) != CRYPT_OK) goto LBL_ERR;
if (buflen >= taglen && XMEM_NEQ(buf, tag, taglen) == 0) {
   *stat = 1;
}
err = CRYPT_OK;
```

`eax_done` writes `min(16, *taglen)` bytes and reports that count (`src/encauth/eax/eax_done.c:63-66`).
Because `buf` is allocated with the caller's `taglen` (`eax_decrypt_verify_memory.c:61`), `buflen`
equals `taglen` for every `taglen <= 16`, and the `buflen >= taglen` guard is effectively always true.
Consequently:

- `taglen == 0` ⇒ zero-byte comparison ⇒ `mem_neq` returns 0 ⇒ **`*stat = 1`**. Authentication
  "succeeds" for arbitrary ciphertext with any key.
- `taglen` in 1..16 ⇒ genuine prefix comparison, sound up to `2^(-8*taglen)`.
- `taglen > block_length` ⇒ `CRYPT_INVALID_ARG` (`:56-58`), `*stat` stays 0.

The zero-length acceptance is deliberate: `eax_decrypt_verify_memory` validates only the upper bound
(`src/encauth/eax/eax_decrypt_verify_memory.c:55-58`), and
`doc/crypt.tex:1870-1872` states *"tags may be truncated and a zerolength tag is legal -- it simply
provides no authenticity, which is the caller's choice."* The implementation matches the doc. The
hazard is the *signalling*: `err` is still `CRYPT_OK` and `*stat` is 1, so a caller cannot distinguish
"verified with a 1-byte tag" from "verified with no tag at all".

### 3.4 OCB3

```c
/* src/encauth/ocb3/ocb3_decrypt_verify_memory.c:47-85 */
taglen = MIN(taglen, MAXBLOCKSIZE);
...
if ((err = ocb3_init(ocb, cipher, key, keylen, nonce, noncelen, taglen)) != CRYPT_OK) goto LBL_ERR;
...
if (buflen >= taglen && XMEM_NEQ(buf, tag, taglen) == 0) *stat = 1;
```

OCB3 uses the same `stat` convention as EAX, but its tag length is a *domain-separation parameter*, not
a truncation length:

```c
/* src/encauth/ocb3/ocb3_init.c:26 */
iNonce[0] |= ((taglen*8) % 128) << 1;
```

The tag length is mixed into `Offset_0`, so an `L`-byte tag is not a prefix of a 16-byte tag; it is the
output of a different function. `ocb3_init` rejects `taglen > 16` (`ocb3_init.c:112-114`), so the
`MIN(..., MAXBLOCKSIZE)` clamp at `:48` is only there to bound the allocation before init rejects it.
Success requires `taglen <= 16` and the comparison over `taglen` bytes to match. `taglen == 0` triggers
the same vacuous branch as EAX (zero-length `mem_neq`), and `ocb3_done` accepts a zero-length tag
because `if ((int)*taglen < ocb->tag_len)` is `0 < 0` = false (`src/encauth/ocb3/ocb3_done.c:29`).

### 3.5 ChaCha20-Poly1305

```c
/* src/encauth/chachapoly/chacha20poly1305_memory.c:55-63 */
else if (direction == CHACHA20POLY1305_DECRYPT) {
   unsigned char buf[MAXBLOCKSIZE];
   unsigned long buflen = sizeof(buf);
   if ((err = chacha20poly1305_decrypt(&st, in, inlen, out)) != CRYPT_OK) goto LBL_ERR;
   if ((err = chacha20poly1305_done(&st, buf, &buflen)) != CRYPT_OK)      goto LBL_ERR;
   if (buflen != *taglen || XMEM_NEQ(buf, tag, buflen) != 0) {
      err = CRYPT_ERROR;
      goto LBL_ERR;
   }
}
```

`poly1305_done` always sets `*maclen = 16` (`src/mac/poly1305/poly1305.c:254`), so verification
requires `*taglen == 16` exactly. This is the strictest contract of the seven, and the right one for a
fixed-length AEAD. The catch is on the *encrypt* side: `chacha20poly1305_done` forwards the caller's
`*taglen` to `poly1305_done`, whose only guard is

```c
/* src/mac/poly1305/poly1305.c:175 */
LTC_ARGCHK(*maclen >= 16);
```

a pointer-style argument check, not a return-code check (§4.3, §7.2).

### 3.6 SIV

`siv_decrypt_memory` (`src/encauth/siv/siv.c:334`) and the decrypt arm of `siv_memory`
(`siv.c:492-495`) always compare the full 16-byte synthetic IV and always call `copy_or_zeromem`.
There is no tag-length parameter at all, so there is nothing to truncate and no `stat`-style ambiguity:

```c
err = XMEM_NEQ(&siv.V, ct, sizeof(siv.V));
copy_or_zeromem(pt_work, pt, *ptlen, err);
```

### 3.7 GCM-SIV

`gcm_siv_memory` fixes the tag at 16 bytes (`src/encauth/gcm_siv/gcm_siv.c:168-171` rejects
`*taglen < 16` with `CRYPT_BUFFER_OVERFLOW`) and zeroes the plaintext on mismatch
(`gcm_siv.c:209-212`). Strict and fail-closed, like SIV.

### 3.8 Summary table

| Mode | Mismatch return | Mismatch out-param | Plaintext on failure | Verifier tag-length policy |
|---|---|---|---|---|
| GCM | `CRYPT_ERROR` | — | **left in `pt`** | must be exactly 16 |
| CCM | `CRYPT_ERROR` (via `mem_neq` 0/1) | — | **zeroed** (`copy_or_zeromem`) | 4/6/8/10/12/14/16, encoded in `B_0` |
| EAX | `CRYPT_OK` | `*stat = 0` | **left in `pt`** | prefix, `0..blocklen`; 0 ⇒ success |
| OCB3 | `CRYPT_OK` | `*stat = 0` | **left in `pt`** | `0..16`, domain-separated; 0 ⇒ success |
| ChaCha20-Poly1305 | `CRYPT_ERROR` | — | **left in `out`** | exactly 16 |
| SIV | `CRYPT_ERROR` (via `mem_neq` 0/1) | — | **zeroed** | n/a (fixed 16) |
| GCM-SIV | `CRYPT_ERROR` | — | **zeroed** | exactly 16 |

---

## 4. Length checks and their gaps

### 4.1 GCM message-length bound

`gcm_process` bounds the total processed bits:

```c
/* src/encauth/gcm/gcm_process.c:40-43 */
/* 0xFFFFFFFE0 = ((2^39)-256)/8 */
if (gcm->pttotlen / 8 + (ulong64)gcm->buflen + (ulong64)ptlen >= CONST64(0xFFFFFFFE0)) {
   return CRYPT_INVALID_ARG;
}
```

`gcm_add_aad` (`src/encauth/gcm/gcm_add_aad.c:39`) refuses AAD before an IV, which prevents the
"IV reused as AAD" state confusion. These are sound.

### 4.2 SIV `*outlen` underflow on the error path

```c
/* src/encauth/siv/siv.c:434-439 */
if (direction == LTC_ENCRYPT && *outlen < inlen + 16) {
   *outlen = inlen + 16;
   return CRYPT_BUFFER_OVERFLOW;
} else if (direction == LTC_DECRYPT && (inlen < 16 || *outlen < inlen - 16)) {
   *outlen = inlen - 16;
   return CRYPT_BUFFER_OVERFLOW;
}
```

The `inlen < 16 ||` short-circuits the comparison, but the *assignment on the next line* is not
protected. With `inlen = 0` and `LTC_DECRYPT`, `inlen - 16` underflows to `ULONG_MAX - 15`
(observed: `*outlen = 18446744073709551600`, §5.5). It is an information/contract bug, not a memory
safety bug, but it violates the documented "on failure `*outlen` holds the required size" rule
(`doc/crypt.tex:355`) and can push a caller into an enormous allocation or a nonsensical
"required size" log line.

### 4.3 ChaCha20-Poly1305: a documented tag length becomes a memory-safety question

The one-shot API documents `taglen` as in/out (`src/headers/tomcrypt_mac.h:531`), and the prose says a
tag "of length *taglen* octets (always 16)" (`doc/crypt.tex:2505`). Nothing in
`chacha20poly1305_memory` validates `*taglen`; the value reaches `poly1305_done`, whose `LTC_ARGCHK`
expands to *different behaviour per build*:

| ARGTYPE | `LTC_ARGCHK` expansion | Effect of `*taglen < 16` |
|---|---|---|
| 0 | `crypt_argchk()` → `abort()` (`src/headers/tomcrypt_argchk.h:12-13`, `src/misc/crypt/crypt_argchk.c:11-17`) | process abort (SIGABRT) |
| 1 | `assert()` (`:18`) | abort |
| 2 | print warning, continue (`:22`) | **continues and memcpy's 16 bytes** |
| 3 | empty (`:26`) | **memcpy's 16 bytes with no check** |
| 4 | `return CRYPT_INVALID_ARG` (`:30`) | clean error |

The default build from the top-level makefile forces `ARGTYPE=4` (`makefile_include.mk:152-153`) and
CMake does the same for release builds (`CMakeLists.txt:85-90`), so stock builds are safe. But CI
explicitly builds and tests ARGTYPE 1, 2 and 3 (`.github/workflows/main.yml`, `STOCK+ARGTYPE=1/2/3/4`),
and under ARGTYPE 2/3 this is a heap **write overflow** of up to 4 bytes past a 12-byte tag buffer,
confirmed with ASan (§5.6). It is reachable from a completely ordinary caller mistake, namely treating
`taglen` as the truncation parameter the other modes accept.

### 4.4 Missing `direction` validation

Three functions branch on `direction` without validating it:

- `gcm_process` (`src/encauth/gcm/gcm_process.c:78,96,134,136`): `if (direction == GCM_ENCRYPT) …
  else { decrypt }`. Any non-encrypt value decrypts.
- `gcm_siv_memory` (`src/encauth/gcm_siv/gcm_siv.c:176,208`): `if (direction == LTC_DECRYPT) …
  else { encrypt }`. Any non-decrypt value encrypts — and skips authentication entirely.
- `siv_memory` (`src/encauth/siv/siv.c:434,447,457,492`): the buffer guards only run for
  `LTC_ENCRYPT`/`LTC_DECRYPT`; the body only checks `== LTC_DECRYPT`. Any other value takes the
  encrypt path with the encrypt guards *not* having run.

By contrast `ccm_memory` (`:61`), `ccm_process` (`:27`), `gcm_memory` `else` branch (`:103`) and
`chacha20poly1305_memory` (`:65`) do reject unknown directions.

Runtime consequences (all reproduced, §5.4):

- `gcm_memory(..., direction = 5, GCM_DECRYPT-shaped call)` returns `CRYPT_INVALID_ARG` **after**
  `gcm_process` already wrote the plaintext into `pt` (out0 = `0x20`).
- `gcm_siv_memory(..., direction = 7)` returns `CRYPT_OK` and takes the *encrypt* path. No tag is
  checked.
- `siv_memory(..., direction = 5)` returns `CRYPT_OK`, takes the encrypt path, and writes
  `inlen + 16` bytes into `out` even though the caller only promised `*outlen` bytes. With
  `*outlen = 8` and a 16-byte input this is a 24-byte overrun — an ASan-confirmed heap overflow
  (§5.7). The `*outlen` promise is never re-checked on that path.

`direction` is not attacker-controlled in normal use, but it is exactly the kind of argument that gets
wired to a message-derived "opcode" or sign-extended from a protocol field, and the failure is silent
success rather than an error.

### 4.5 CCM length-field truncation (bounded observation)

CCM writes `l(m)` into `B_0` from `ptlen`, but only four bytes of it:

```c
/* src/encauth/ccm/ccm_memory.c:168-183 */
for (y = L; y < 4; y++) len <<= 8;
/* store l(m) (only store 32-bits) */
for (y = 0; L > 4 && (L-y)>4; y++) PAD[x++] = 0;
for (; y < L; y++) { ... PAD[x++] = (unsigned char)((len >> 24) & 255); len <<= 8; }
```

For `L == 5` (i.e. `ptlen >= 2^32`) the first byte is forced to 0 and the remaining four carry the low
32 bits of `ptlen`, so two plaintext lengths differing by `2^32` encode the same length block. The
comment acknowledges the limitation. The streaming API cannot reach this state because `ccm_init`
takes `int ptlen` (`src/encauth/ccm/ccm_init.c:20`), but `ccm_memory` takes `unsigned long` and can
compute `L = 5` on LP64. This is documented as an **evidence gap** in §10 rather than a confirmed
finding, because exercising it requires a >4 GiB buffer.

---

## 5. Runtime evidence

All probes were compiled against the tree at `8cb3933`. Unless noted, the library was built with the
stock makefile (`ARGTYPE=4`, `LTC_FAST` on). Probe sources live outside the repository
(`/tmp/aeadprobe`); they are not committed tests. Representative outputs:

### 5.1 Default configuration: correct tag verifies, wrong tag is reported correctly

```
GCM   decrypt correct err=0 out0=20
GCM   decrypt WRONG  err=1 out0=20 (plaintext still present)
CCM   decrypt WRONG  err=1 out0=00 (scrubbed)
EAX   decrypt WRONG  err=0 stat=0 out0=20 (plaintext still present)
OCB3  decrypt WRONG  err=0 stat=0 out0=20 (plaintext still present)
CCP   decrypt WRONG  err=1 out0=20 (plaintext still present)
SIV   decrypt WRONG  err=1 out0=00 (scrubbed)
GCM-SIV decrypt WRONG err=1 out0=00 (scrubbed)
```

Confirms §3.8. Note that four of seven modes leave the *decrypted-but-unauthenticated* plaintext in the
caller's buffer.

### 5.2 GCM: mintable truncation that cannot be verified

```
GCM enc taglen(in)= 8 -> err=0 taglen(out)=8
GCM enc taglen(in)=32 -> err=0 taglen(out)=16
minted taglen=1 tag=17
verify via gcm_memory taglen=1 -> err=1        <-- cannot verify what it minted
manual prefix compare -> MATCH (computed full taglen=16)
GCM dec taglen=0/8/16/32 -> err=1/1/0/1
```

The pair `gcm_memory(GCM_ENCRYPT, *taglen=8)` / `gcm_memory(GCM_DECRYPT, *taglen=8)` fails to round
trip. Only a hand-rolled `gcm_init`/`gcm_process`/`gcm_done` + `mem_neq(..., 8)` works, i.e. the
prefix comparison has to be re-implemented by the caller (as the probe does).

### 5.3 EAX/OCB3: vacuous success at `taglen == 0`

```
EAX  taglen=0 garbage ciphertext, wrong key, wrong aad -> err=0 stat=1 out0=06
OCB3 taglen=0 garbage ciphertext, wrong key, wrong aad -> err=0 stat=1 out0=51
EAX  taglen=0 on zero-length ciphertext                 -> err=0 stat=1
```

With `taglen = 0` there is nothing to compare, `mem_neq(..., 0) == 0`, and `*stat` is set to 1 for
*any* bytes and *any* key. EAX reaches that state by design (`doc/crypt.tex:1870`); OCB3 reaches it
because `ocb3_done` allows `taglen == ocb->tag_len == 0`.

Also note that `eax_decrypt_verify_memory`'s doc comment says *"@return CRYPT_OK if successful
regardless of the resulting tag comparison"* (`src/encauth/eax/eax_decrypt_verify_memory.c:27`), so
callers that only look at `err` are guaranteed to accept forged data. The same is true of OCB3
(`ocb3_decrypt_verify_memory.c:27`).

### 5.4 Truncated tags across modes are not interchangeable

For a 16-byte tag minted by each mode, verifying with a shorter `taglen`:

```
CCM  mint 16: verify 4..14 -> err=1 (and out scrubbed); verify 16 -> err=0
CCM  mint  8: verify  4   -> err=1
OCB3 taglen=8 verify -> stat=1; taglen=4 -> stat=0   (tag length is domain-separating)
EAX  taglen=8 verify -> stat=1; taglen=4 -> stat=1   (true prefix)
GCM  taglen<16 verify -> err=1
CCP  taglen=8 verify -> err=1
```

So "truncate the tag" has three mutually incompatible meanings in the same library: prefix (EAX),
different algorithm (OCB3/CCM, because the length is MAC-bound), and hard error (GCM, CCP). This must
be documented per mode, and it is the main interoperability trap for protocol implementers.

### 5.5 SIV `*outlen` underflow

```
siv_memory(LTC_DECRYPT, inlen=0,  *outlen=64) -> err=6, *outlen=18446744073709551600
siv_memory(LTC_DECRYPT, inlen=15, *outlen=64) -> err=6, *outlen=18446744073709551615
```

### 5.6 ChaCha20-Poly1305 tag buffer under ARGTYPE=2/3

ASan, `ARGTYPE=3`, 12-byte tag buffer, otherwise-valid call:

```
ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 4
  #1 poly1305_done src/mac/poly1305/poly1305.c:236
  #2 chacha20poly1305_done ...:33
  #3 chacha20poly1305_memory ...:53
0x... is located 0 bytes after 12-byte region
```

Under ARGTYPE=4 the same call returns `CRYPT_INVALID_ARG`; under ARGTYPE=0 it prints
`LTC_ARGCHK '*maclen >= 16' failure on line 175 of file src/mac/poly1305/poly1305.c` and aborts.
Neither of the two memory-unsafe configurations is exercised by any committed test.

### 5.7 Direction misuse is exploitable

```
gcm_memory direction=5 (decrypt shape) -> err=16, out0=20 (plaintext released)
siv_memory direction=5, *outlen=8, inlen=16 -> err=0, *outlen=32
  -> AddressSanitizer: heap-buffer-overflow, WRITE of size 16, siv.c:502
gcm_siv_memory direction=7 -> err=0 (encrypt path, no authentication)
```

### 5.8 Streaming decrypt releases unauthenticated plaintext

```
CCM   streaming, tampered ct: err=0 out0=21 tagdiff=1
EAX   streaming, tampered ct: err=0 out0=21 tagdiff=1
OCB3  streaming, tampered ct: err=0 out0=66 tagdiff=1
CCP   streaming, tampered ct: err=0 out0=21 tagdiff=1
GCM   streaming, tampered ct: err=0 out0=21
```

Every streaming decrypt returns `CRYPT_OK` and the tampered plaintext. Callers must compare the tag
from `*_done` themselves. No streaming mode ships a comparison helper.

### 5.9 Unvalidated authentication inputs in `gcm_memory`

`gcm_memory` contains **zero** `LTC_ARGCHK` calls (`grep -c LTC_ARGCHK
src/encauth/gcm/gcm_memory.c` → 0). Passing `taglen = NULL` on the decrypt path is a null-dereference
at `gcm_memory.c:99` *after* the entire plaintext has been produced:

```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
  #0 gcm_memory src/encauth/gcm/gcm_memory.c:99
```

This holds under every ARGTYPE, including the stock one, because there is no check to expand. On the
encrypt path the same argument is caught indirectly by `gcm_done`'s checks.

### 5.10 Existing tests: what they do and do not cover

| Mode | Negative test present | Asserts plaintext scrubbed | Tag-length matrix | `direction` misuse |
|---|---|---|---|---|
| GCM | yes — `src/encauth/gcm/gcm_test.c:374-400` | no | no | no |
| CCM | yes — `src/encauth/ccm/ccm_test.c:213-230` | **yes** (`ltc_compare_testvector(buf2, ..., zero, ...)`) | no | partial (nonce) |
| EAX | **no** — `src/encauth/eax/eax_test.c` only checks `res == 1` on valid vectors (`:232-242`) | no | no | no |
| OCB3 | **no** — `src/encauth/ocb3/ocb3_test.c:228-241` only valid vectors | no | no | no |
| ChaCha20-Poly1305 | yes — `chacha20poly1305_test.c:120-152` | no | no | no |
| SIV | yes, via Wycheproof — `tests/siv_wycheproof_test.c:35-52` (`SHOULD_FAIL`) | no | n/a | no |
| GCM-SIV | yes — `gcm_siv_test.c:448-454` | no | no | no |

The CCM test is the only one that asserts the *content* of the plaintext buffer after a failed
verification. EAX and OCB3 have no tampered-tag test at all, which is why the `taglen == 0` vacuous
success has never been caught.

---

## 6. The caller-side contract as it stands

Combining §3 and §5, the de-facto contract callers must implement is:

1. **Never infer authentication from `err` alone for EAX/OCB3.** Use `*stat`.
2. **For GCM/CCP/CCM/SIV/GCM-SIV**, `err == CRYPT_OK` does imply the tag matched — but only if
   `taglen` was exactly what the mode requires (16 for GCM/CCP/GCM-SIV, in-set for CCM).
3. **For streaming APIs, `CRYPT_OK` from `*_process`/`*_decrypt` means nothing.** Only an explicit
   comparison after `*_done` counts.
4. **The plaintext buffer may contain unauthenticated data** after a failure in GCM, CCP, EAX and
   OCB3. Only CCM, SIV and GCM-SIV guarantee scrubbing.
5. **Tag truncation is mode-specific**: prefix for EAX, not a prefix for OCB3/CCM, unsupported for
   GCM mint/verify pairs, fixed-16 for CCP/SIV/GCM-SIV.

Rule 4 and rule 1 are the two that break ordinary code. Rule 4 in particular means that a caller who
logs, retransmits, or partially processes a decryption buffer before checking the verdict is handling
attacker-chosen bytes.

The documentation states rule 1 for EAX (`doc/crypt.tex:1867-1869`) and OCB3 (`:1991-1992`), states
rule 2 for GCM (`:2306-2307`) and CCP (`:2530-2531`), and states "the decrypted plaintext is never
returned to the caller when authentication fails" for GCM-SIV (`:2779-2781`). It does **not** document
rule 4 as a cross-mode difference, and it never states rule 3.

---

## 7. Compatibility vs. refusing unauthenticated plaintext

Two changes are worth discussing separately because they have different blast radii.

### 7.1 Zero-length tags (EAX/OCB3)

The zero-length tag is documented and deliberate for EAX. Removing it is a behaviour change for any
caller that used "no tag" as an explicit mode: for example, an application that wants decrypt-only
semantics and currently passes `taglen = 0` on purpose. But that same escape hatch is indistinguishable
from a length-computation bug (e.g. `taglen` derived from an unvalidated packet field), and in the bug
case the caller sees success.

Options, in order of preference:

1. **Reject `taglen == 0` in the `*_verify_memory` functions** and require decrypt-only callers to call
   the streaming `*_decrypt` API instead. This is fail-closed and forces the intent to be explicit.
   `eax_decrypt_verify_memory` would return `CRYPT_INVALID_ARG` and leave `*stat = 0`.
2. Gate it on a build macro (`LTC_AEAD_ALLOW_ZERO_TAG`), default off. Keeps old behaviour available
   without changing the default; the macro is visible in `crypt_list_all_constants()`-style
   introspection.
3. Add a `min_taglen` parameter to a new `_ex` entry point and deprecate the old one.

Option 1 is the smallest change that removes the footgun; option 2 is the only one that is
source-and-behaviour compatible by default. My recommendation is 1 plus a release note, because a
zero-length tag cannot be part of any sound authentication protocol and the streaming API already
covers the legitimate decrypt-only use case.

### 7.2 Scrubbing plaintext on failure (GCM, ChaCha20-Poly1305, EAX, OCB3)

Scrubbing changes only the contents of an output buffer on a path where authentication already failed.
No correct caller can depend on that buffer, but a caller *can* observe the change (e.g. a test that
asserts the current "decrypt anyway" behaviour, or a forensic tool that deliberately inspects
corrupted plaintext). The choices:

1. **Scrub by default** in the one-shot verify functions, using the existing `copy_or_zeromem`
   pattern already proven in CCM/SIV. Cost: a behaviour change on the failure path only.
2. Add an explicit flag (e.g. `LTC_AEAD_RETAIN_UNAUTHENTICATED`) for the deliberate-inspection case,
   defaulting to scrub.
3. Leave the behaviour and document it loudly, and add a `ltc_aead_scrub` helper that callers must
   invoke.

Recommendation: 1 for the `*_verify_memory` functions (they are the ones that *claim* to verify) and 3
for the streaming API (where scrubbing would be surprising and is impossible to do correctly without
buffering). Note that GCM's `gcm_memory` is a one-shot *and* the GCM streaming entry point shares the
same state, so the scrub has to be done inside `gcm_memory`, not `gcm_process`.

### 7.3 GCM mint/verify asymmetry

Because truncated-tag GCM is used in deployed protocols (NIST SP 800-38D explicitly permits tag lengths
of 128, 120, 112, 104 and 96 bits), refusing to mint truncated tags would break interop. The
compatible fix is to make verification of a truncated tag possible:

- In `gcm_memory`'s decrypt branch, accept `*taglen <= buflen` and compare `*taglen` bytes, i.e. the
  same prefix rule EAX uses. Keep `buflen != *taglen` only for `*taglen > 16`.
- Add a documented floor (`*taglen >= 4`, matching CCM's minimum) so a 1-byte tag is not silently
  accepted.

This makes `gcm_memory` round-trip, matches the EAX semantics that the rest of the library already
uses, and is backwards compatible for callers that pass 16. The risk is that a caller who passes a
short `taglen` *by mistake* now gets a weak-but-successful verification instead of an error; the floor
and a release note mitigate that.

---

## 8. Proposed changes

### 8.1 Code (smallest correct fixes)

**A. Validate `direction` at entry.**

```c
/* siv_memory, src/encauth/siv/siv.c:431 */
if (direction != LTC_ENCRYPT && direction != LTC_DECRYPT) return CRYPT_INVALID_ARG;
/* gcm_siv_memory, src/encauth/gcm_siv/gcm_siv.c:163 */
if (direction != LTC_ENCRYPT && direction != LTC_DECRYPT) return CRYPT_INVALID_ARG;
/* gcm_process, src/encauth/gcm/gcm_process.c:30 */
if (direction != GCM_ENCRYPT && direction != GCM_DECRYPT) return CRYPT_INVALID_ARG;
```

This closes the SIV heap overflow (§5.7) and the silent encrypt-path fallthrough in GCM-SIV.

**B. Fix the SIV `*outlen` underflow.**

```c
/* src/encauth/siv/siv.c:437-439 */
} else if (direction == LTC_DECRYPT && (inlen < 16 || *outlen < inlen - 16)) {
   *outlen = (inlen < 16) ? 0 : inlen - 16;
   return CRYPT_BUFFER_OVERFLOW;
}
```

**C. Add the missing argument check to `gcm_memory`.**

```c
/* src/encauth/gcm/gcm_memory.c, before cipher_is_valid */
LTC_ARGCHK(tag    != NULL);
LTC_ARGCHK(taglen != NULL);
```

Note the accelerator fast path at `:46-55` returns before any of this; the check must be placed before
it.

**D. Make the `mem_neq`-as-error-code pattern explicit.** `ccm_memory.c:356` and `siv.c:384/493`
assign `mem_neq`'s 0/1 to `err`. Replace with:

```c
err = XMEM_NEQ(...) ? CRYPT_ERROR : CRYPT_OK;
```

so a future reordering of the `CRYPT_*` enum cannot silently turn a failed tag into a success code.

**E. Introduce one constant-time tag-comparison helper** and route every mode through it:

```c
/* proposed: src/headers/tomcrypt_misc.h */
int ltc_aead_verify_tag(const unsigned char *computed, unsigned long computedlen,
                        const unsigned char *tag,      unsigned long taglen,
                        unsigned long min_taglen);
/* returns CRYPT_OK iff taglen <= computedlen && taglen >= min_taglen
   && mem_neq(computed, tag, taglen) == 0 */
```

Every mode's one-shot verify becomes a single call with its own `min_taglen` (4 for CCM/GCM/EAX,
16 for CCP/SIV/GCM-SIV, `0` today for OCB3 until §7.1 is decided). This centralises the two properties
that are easy to get wrong — the length floor and constant-time comparison — and gives the test suite
one thing to fuzz.

**F. Enforce the documented GCM-SIV length bound.** `doc/crypt.tex:2741` says plaintext and AAD are at
most `2^36` bytes; `gcm_siv_memory` checks nothing. Add:

```c
if (inlen >= (CONST64(1) << 36) || aadlen >= (CONST64(1) << 36)) return CRYPT_INPUT_TOO_LONG;
```

**G. Document the streaming contract.** Add to each mode's section in `doc/crypt.tex`: "the
`*_process`/`*_decrypt` functions return plaintext that has not been authenticated; authentication is
complete only when the caller compares the output of `*_done` against the received tag." The GCM
section (`:2280-2310`) and CCP section (`:2530-2531`) already describe the one-shot rule; the
streaming rule is missing everywhere.

### 8.2 Tests to add

The committed suite is what makes these contracts durable. The gaps in §5.10 are cheap to close.

1. **A per-mode negative matrix** in each `*_test.c`, with one fixed vector and these mutations:
   flip a tag bit, flip a ciphertext bit, flip an AAD bit, use a wrong key, truncate the ciphertext.
   For each: assert failure AND assert the output buffer equals the expected "failure content"
   (all zeros for CCM/SIV/GCM-SIV; the current plaintext or zeros for the others once §7.2 is decided).
2. **A tag-length matrix**: for `taglen ∈ {0,1,2,3,4,5,...,17,32,ULONG_MAX}`, assert the exact
   documented outcome for both mint and verify. This is the test that would have caught EAX/OCB3
   `taglen = 0 ⇒ stat = 1`, GCM's mint/verify asymmetry, and the CCP overflow under ARGTYPE 2/3.
3. **An ARGTYPE sweep over the negative matrix.** CI already builds `ARGTYPE=1..4`; the probes in
   §5.6 show that the same call is a clean error under 4 and a heap overflow under 3. Add the
   short-tag-buffer call to the CCP test so that at least ARGTYPE 3 fails the build.
4. **Direction-misuse tests** for `siv_memory`, `siv_decrypt_memory`, `gcm_siv_memory`,
   `gcm_memory`, `gcm_process`, `ccm_process` with values `-1, 2, 5, 7, INT_MIN`; assert
   `CRYPT_INVALID_ARG` and no output.
5. **A seal/open property test for truncated tags**, per mode, using the mode's own documented
   semantics: for EAX mint 8 and verify 8 succeeds; for GCM, after §7.3, mint 8 and verify 8 succeeds;
   for OCB3 and CCM, verify that a different `taglen` fails even when the bytes are a prefix.
6. **A `taglen == 0` regression test** asserting the post-§7.1 behaviour (`CRYPT_INVALID_ARG`,
   `*stat == 0`) with a comment referencing the compat decision.
7. **A scrub test using a poisoned buffer**: fill `pt` with `0xA5`, call decrypt with a bad tag, and
   assert the policy-specific result. The CCM test already does this
   (`ccm_test.c:213-230`); replicate it for the other six.

### 8.3 Documentation

- Per-mode table of "what `taglen` means" (prefix / domain parameter / fixed).
- A single statement of the EAX/OCB3 `stat` rule in the "Return codes" section, not buried in each
  mode's prose.
- The ARGTYPE interaction: `LTC_ARGCHK` failures are build-dependent (`doc/crypt.tex:9539-9550`);
  the AEAD sections should say that authentication parameters must be validated by the caller because
  ARGTYPE 2/3 does not enforce them.

---

## 9. Why the current `mem_neq`-as-error-code pattern is fragile

`mem_neq` returns `0` for equal and `1` for unequal (`src/misc/mem_neq.c:29-53`). `ccm_memory` and
`siv.c` assign that directly to `err`, relying on `CRYPT_ERROR == 1` (`src/headers/tomcrypt.h:36-37`).
`copy_or_zeromem` then treats any non-zero as "zero it" (`src/misc/copy_or_zeromem.c:29`). The
scrubbing is therefore correct regardless of the enum, but the *return code* is not: inserting any
error constant before `CRYPT_ERROR` in the enum would make a failed tag return `CRYPT_OK` from CCM and
SIV. The `HACK` comment at `ccm_memory.c:352-355` documents the authors' awareness; it does not make
the code robust. This is a two-line fix (C in §8.1) with a real, if low-probability, failure mode.

---

## 10. Evidence gaps

These are things this analysis could **not** establish from source plus the probes, and that a
reviewer should not treat as settled:

1. **Accelerated descriptors.** `accel_gcm_memory` and `accel_ccm_memory` are declared
   (`src/headers/tomcrypt_cipher.h:521,546`) and called (`gcm_memory.c:46`,
   `ccm_memory.c:91`), but no in-tree cipher registers them. Any out-of-tree descriptor can implement
   its own tag comparison and plaintext policy, bypassing everything in §3 and §7. The contract for
   third-party accelerators is unverified and should be written down.
2. **Constant-time behaviour is asserted, not measured.** `mem_neq` uses `volatile` and a
   branch-free fold; `copy_or_zeromem` uses a mask (`src/misc/copy_or_zeromem.c:24-44`). No timing
   measurements were taken, and no compiler-generated-assembly review was done. In particular the
   `mask *= 1 - coz` formulation and the `LTC_FAST` loop shape should be checked on the target
   toolchains; the `taglen == 0` path in EAX/OCB3 is trivially non-constant-time in the sense that it
   does no work at all, which is a separate concern.
3. **CCM `l(m)` truncation for `ptlen >= 2^32`** (§4.5) was not exercised; it needs a >4 GiB buffer
   or a mocked allocator. The code comment is the only evidence.
4. **Non-16-byte tag interoperability.** OCB3's `taglen` domain separation (§3.4) and CCM's `M`
   encoding (§3.2) were checked against the library's own vectors and
   `tests/siv_wycheproof_test.c`, not against an external implementation for tags shorter than 16.
   The RFC 7253 96-bit vectors in `ocb3_test.c:244-276` cover OCB3; no equivalent cross-implementation
   vector was run for CCM with `M < 16`.
5. **Build-configuration coverage.** The runtime probes used the default `LTC_FAST` configuration with
   ASan on a Linux/x86-64 host. `LTC_CLEAN_STACK`, `LTC_SMALL_CODE`, and non-x86 targets were not
   exercised for these paths; `LTC_CLEAN_STACK` changes which buffers are wiped
   (`gcm_done.c` has no wipe of `gcm->buf`, `eax_done.c:70-75` wipes only under that macro), so the
   "plaintext remains in the state" claim in §3.8 is only about the caller's output buffer.
6. **Whether the plaintext-left-in-buffer behaviour is exploitable** depends entirely on the caller.
   The library-level observation (§3.8, §5.1) is solid; the impact claim is conditional.
7. **`gcm_memory`'s missing checks and the ARGTYPE 2/3 overflow** were found with ad-hoc harnesses
   outside the repo. They are reproducible (commands in the appendix) but are not covered by the
   committed suite, so they can regress silently.
8. **Concurrency.** Nothing here checks whether two threads can share a `gcm_state`/`ccm_state`
   across a failed verification and a scrub; the state structs are caller-owned and the library has no
   locking contract for them.

---

## 11. Summary of findings

| # | Finding | Evidence | Severity |
|---|---|---|---|
| 1 | `eax_decrypt_verify_memory` and `ocb3_decrypt_verify_memory` return `CRYPT_OK` on failure and put the verdict in `*stat`; a caller checking only `err` accepts forgeries | `eax_decrypt_verify_memory.c:27,91`; `ocb3_decrypt_verify_memory.c:27,87`; §3.3, §3.4 | High (caller contract) |
| 2 | `taglen == 0` yields `*stat = 1` for arbitrary ciphertext in EAX and OCB3 | `eax_...c:87`, `ocb3_...c:83`, `ocb3_done.c:29`; §5.3 | High |
| 3 | GCM mints truncated tags it cannot verify (`buflen != *taglen`) | `gcm_memory.c:99`, `gcm_done.c:65-68`; §5.2 | Medium (interop/footgun) |
| 4 | Plaintext is left in the caller's buffer after failed verification in GCM, ChaCha20-Poly1305, EAX, OCB3 | §3.8, §5.1 | High (depends on caller) |
| 5 | `siv_memory` accepts any non-decrypt `direction` as encrypt, skipping buffer guards; ASan-confirmed heap overflow | `siv.c:434-439,492-503`; §5.7 | High |
| 6 | `gcm_siv_memory` treats any non-decrypt `direction` as encrypt with no authentication | `gcm_siv.c:176,208`; §5.7 | Medium |
| 7 | `gcm_memory` has no argument checks; `taglen == NULL` on decrypt segfaults after producing plaintext | `gcm_memory.c` (0 `LTC_ARGCHK`), §5.9 | Medium |
| 8 | ChaCha20-Poly1305 tag buffer shorter than 16 is a heap overflow under ARGTYPE 2/3 | `poly1305.c:175`, `chacha20poly1305_done.c:33`; §5.6 | Medium (build-dependent) |
| 9 | `siv_memory` reports `ULONG_MAX - 15` as the required `*outlen` for `inlen < 16` | `siv.c:437-439`; §5.5 | Low |
| 10 | Return codes for bad tags in CCM/SIV depend on `CRYPT_ERROR == 1` | `ccm_memory.c:352-356`, `siv.c:384`; §9 | Low |
| 11 | Streaming decrypt APIs return unauthenticated plaintext and `CRYPT_OK`; undocumented | §5.8, §6 | Medium (docs) |
| 12 | EAX and OCB3 have no negative self-tests at all | `eax_test.c:232-242`, `ocb3_test.c:228-241`; §5.10 | Medium (test gap) |

The highest-leverage single change is (2)+(1): add a length floor and make the `stat` rule
impossible to miss. The highest-leverage test change is the tag-length matrix in §8.2 (2), because it
exercises findings 1, 2, 3 and 8 in one place.

---

## Appendix: reproduction

All probes were built against this tree with:

```sh
make -j8 libtomcrypt.a
gcc -I src/headers -o probe probe.c libtomcrypt.a
./probe
```

Variant builds used to observe the ARGTYPE-dependent behaviour:

```sh
make clean && make -j8 CFLAGS="-DARGTYPE=3" libtomcrypt.a            # §5.6
make clean && make -j8 CFLAGS="-DARGTYPE=2" libtomcrypt.a            # §5.6
make clean && make -j8 CFLAGS="-fsanitize=address -g -O1" \
    LDFLAGS="-fsanitize=address" libtomcrypt.a                       # ASan probes
```

The committed self-tests were run with `./test mac` (passes), which is the baseline that the
proposed §8.2 tests would extend.
