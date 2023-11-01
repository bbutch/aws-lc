/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

#include <openssl/aead.h>

#include <assert.h>

#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../delocate.h"
#include "../service_indicator/internal.h"
#include "internal.h"


struct ccm128_context {
  block128_f block;
  ctr128_f ctr;
  unsigned M, L;
  void *key;
};

struct ccm128_state {
  union {
    uint64_t u[2];
    uint8_t c[16];
  } nonce, cmac;
};

struct aead_aes_ccm_ctx {
  union {
    double align;
    AES_KEY ks;
  } ks;
  struct ccm128_context ccm;
};

struct cipher_aes_ccm_ctx {
  int key_set;                       // Set if key initialised
  int iv_set;                        // Set if an iv is set
  int tag_set;                       // Set if tag is valid
  int len_set;                       // Set if message length set
  int tls_aad_len;                   // TLS AAD length
  unsigned M, L;
  struct ccm128_state state;
  EVP_AEAD_CTX aead_ctx;  // TODO NOTE: aead_ctx->state == aead_aes_ccm_ctx
};

static int CRYPTO_ccm128_init(struct ccm128_context *ctx, const AES_KEY *key,
                              block128_f block, ctr128_f ctr, unsigned M,
                              unsigned L) {
  if (M < 4 || M > 16 || (M & 1) != 0 || L < 2 || L > 8) {
    return 0;
  }
  ctx->block = block;
  ctx->ctr = ctr;
  ctx->M = M;
  ctx->L = L;
  return 1;
}

static size_t CRYPTO_ccm128_max_input(const struct ccm128_context *ctx) {
  return ctx->L >= sizeof(size_t) ? (size_t)-1
                                  : (((size_t)1) << (ctx->L * 8)) - 1;
}

static size_t CRYPTO_ccm128_tag(const struct ccm128_state *state, uint8_t *tag,
                                size_t len) {
  unsigned int M = (state->nonce.c[0] >> 3) & 7;
  M *= 2;
  M += 2;

  if (len != M) {
    return 0;
  }

  memcpy(tag, state->cmac.c, M);
  return M;
}

static int ccm128_init_state(const struct ccm128_context *ctx,
                             struct ccm128_state *state, const AES_KEY *key,
                             const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *aad, size_t aad_len,
                             size_t plaintext_len) {
  const block128_f block = ctx->block;
  const unsigned M = ctx->M;
  const unsigned L = ctx->L;

  // |L| determines the expected |nonce_len| and the limit for |plaintext_len|.
  if (plaintext_len > CRYPTO_ccm128_max_input(ctx) ||
      nonce_len != 15 - L) {
    return 0;
  }

  // Assemble the first block for computing the MAC.
  OPENSSL_memset(state, 0, sizeof(*state));
  state->nonce.c[0] = (uint8_t)((L - 1) | ((M - 2) / 2) << 3);
  if (aad_len != 0) {
    state->nonce.c[0] |= 0x40;  // Set AAD Flag
  }
  OPENSSL_memcpy(&state->nonce.c[1], nonce, nonce_len);
  for (unsigned i = 0; i < L; i++) {
    state->nonce.c[15 - i] = (uint8_t)(plaintext_len >> (8 * i));
  }

  (*block)(state->nonce.c, state->cmac.c, key);
  size_t blocks = 1;

  if (aad_len != 0) {
    unsigned i;
    // Cast to u64 to avoid the compiler complaining about invalid shifts.
    uint64_t aad_len_u64 = aad_len;
    if (aad_len_u64 < 0x10000 - 0x100) {
      state->cmac.c[0] ^= (uint8_t)(aad_len_u64 >> 8);
      state->cmac.c[1] ^= (uint8_t)aad_len_u64;
      i = 2;
    } else if (aad_len_u64 <= 0xffffffff) {
      state->cmac.c[0] ^= 0xff;
      state->cmac.c[1] ^= 0xfe;
      state->cmac.c[2] ^= (uint8_t)(aad_len_u64 >> 24);
      state->cmac.c[3] ^= (uint8_t)(aad_len_u64 >> 16);
      state->cmac.c[4] ^= (uint8_t)(aad_len_u64 >> 8);
      state->cmac.c[5] ^= (uint8_t)aad_len_u64;
      i = 6;
    } else {
      state->cmac.c[0] ^= 0xff;
      state->cmac.c[1] ^= 0xff;
      state->cmac.c[2] ^= (uint8_t)(aad_len_u64 >> 56);
      state->cmac.c[3] ^= (uint8_t)(aad_len_u64 >> 48);
      state->cmac.c[4] ^= (uint8_t)(aad_len_u64 >> 40);
      state->cmac.c[5] ^= (uint8_t)(aad_len_u64 >> 32);
      state->cmac.c[6] ^= (uint8_t)(aad_len_u64 >> 24);
      state->cmac.c[7] ^= (uint8_t)(aad_len_u64 >> 16);
      state->cmac.c[8] ^= (uint8_t)(aad_len_u64 >> 8);
      state->cmac.c[9] ^= (uint8_t)aad_len_u64;
      i = 10;
    }

    do {
      for (; i < 16 && aad_len != 0; i++) {
        state->cmac.c[i] ^= *aad;
        aad++;
        aad_len--;
      }
      (*block)(state->cmac.c, state->cmac.c, key);
      blocks++;
      i = 0;
    } while (aad_len != 0);
  }

  // Per RFC 3610, section 2.6, the total number of block cipher operations done
  // must not exceed 2^61. There are two block cipher operations remaining per
  // message block, plus one block at the end to encrypt the MAC.
  size_t remaining_blocks = 2 * ((plaintext_len + 15) / 16) + 1;
  if (plaintext_len + 15 < plaintext_len ||
      remaining_blocks + blocks < blocks ||
      (uint64_t) remaining_blocks + blocks > UINT64_C(1) << 61) {
    return 0;
  }

  // Assemble the first block for encrypting and decrypting. The bottom |L|
  // bytes are replaced with a counter and all bit the encoding of |L| is
  // cleared in the first byte.
  state->nonce.c[0] &= 7;
  return 1;
}

static int ccm128_encrypt(const struct ccm128_context *ctx,
                          struct ccm128_state *state, const AES_KEY *key,
                          uint8_t *out, const uint8_t *in, size_t len) {
  // The counter for encryption begins at one.
  for (unsigned i = 0; i < ctx->L; i++) {
    state->nonce.c[15 - i] = 0;
  }
  state->nonce.c[15] = 1;

  uint8_t partial_buf[16];
  unsigned num = 0;
  if (ctx->ctr != NULL) {
    CRYPTO_ctr128_encrypt_ctr32(in, out, len, key, state->nonce.c, partial_buf,
                                &num, ctx->ctr);
  } else {
    CRYPTO_ctr128_encrypt(in, out, len, key, state->nonce.c, partial_buf, &num,
                          ctx->block);
  }
  return 1;
}

static int ccm128_compute_mac(const struct ccm128_context *ctx,
                              struct ccm128_state *state, const AES_KEY *key,
                              uint8_t *out_tag, size_t tag_len,
                              const uint8_t *in, size_t len) {
  block128_f block = ctx->block;
  if (tag_len != ctx->M) {
    return 0;
  }

  // Incorporate |in| into the MAC.
  union {
    uint64_t u[2];
    uint8_t c[16];
  } tmp;
  while (len >= 16) {
    OPENSSL_memcpy(tmp.c, in, 16);
    state->cmac.u[0] ^= tmp.u[0];
    state->cmac.u[1] ^= tmp.u[1];
    (*block)(state->cmac.c, state->cmac.c, key);
    in += 16;
    len -= 16;
  }
  if (len > 0) {
    for (size_t i = 0; i < len; i++) {
      state->cmac.c[i] ^= in[i];
    }
    (*block)(state->cmac.c, state->cmac.c, key);
  }

  // Encrypt the MAC with counter zero.
  for (unsigned i = 0; i < ctx->L; i++) {
    state->nonce.c[15 - i] = 0;
  }
  (*block)(state->nonce.c, tmp.c, key);
  state->cmac.u[0] ^= tmp.u[0];
  state->cmac.u[1] ^= tmp.u[1];

  OPENSSL_memcpy(out_tag, state->cmac.c, tag_len);
  return 1;
}

static int CRYPTO_ccm128_encrypt(const struct ccm128_context *ctx,
                                 const AES_KEY *key, uint8_t *out,
                                 uint8_t *out_tag, size_t tag_len,
                                 const uint8_t *nonce, size_t nonce_len,
                                 const uint8_t *in, size_t len,
                                 const uint8_t *aad, size_t aad_len) {
  struct ccm128_state state;
  return ccm128_init_state(ctx, &state, key, nonce, nonce_len, aad, aad_len,
                           len) &&
         ccm128_compute_mac(ctx, &state, key, out_tag, tag_len, in, len) &&
         ccm128_encrypt(ctx, &state, key, out, in, len);
}

static int CRYPTO_ccm128_decrypt(const struct ccm128_context *ctx,
                                 const AES_KEY *key, uint8_t *out,
                                 uint8_t *out_tag, size_t tag_len,
                                 const uint8_t *nonce, size_t nonce_len,
                                 const uint8_t *in, size_t len,
                                 const uint8_t *aad, size_t aad_len) {
  struct ccm128_state state;
  return ccm128_init_state(ctx, &state, key, nonce, nonce_len, aad, aad_len,
                           len) &&
         ccm128_encrypt(ctx, &state, key, out, in, len) &&
         ccm128_compute_mac(ctx, &state, key, out_tag, tag_len, out, len);
}

#define EVP_AEAD_AES_CCM_MAX_TAG_LEN 16

OPENSSL_STATIC_ASSERT(sizeof(((EVP_AEAD_CTX *)NULL)->state) >=
                          sizeof(struct aead_aes_ccm_ctx),
                      AEAD_state_is_too_small)
OPENSSL_STATIC_ASSERT(alignof(union evp_aead_ctx_st_state) >=
                          alignof(struct aead_aes_ccm_ctx),
                      AEAD_state_has_insufficient_alignment)

static int aead_aes_ccm_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                             size_t key_len, size_t tag_len, unsigned M,
                             unsigned L) {
  if (ctx->aead->aead_id == AEAD_AES_128_CCM_BLUETOOTH_ID ||
      ctx->aead->aead_id == AEAD_AES_128_CCM_BLUETOOTH_8_ID ||
      ctx->aead->aead_id == AEAD_AES_128_CCM_MATTER_ID) {
    assert(M == EVP_AEAD_max_overhead(ctx->aead));
    assert(M == EVP_AEAD_max_tag_len(ctx->aead));
    assert(15 - L == EVP_AEAD_nonce_length(ctx->aead));
  } else if (ctx->aead->aead_id == AEAD_AES_128_CCM_ID /* ||
   TODO      ctx->aead->aead_id == AEAD_AES_192_CCM_ID ||
             ctx->aead->aead_id == AEAD_AES_256_CCM_ID */) {
    assert(M <= EVP_AEAD_max_overhead(ctx->aead));
    assert(M <= EVP_AEAD_max_tag_len(ctx->aead));
    // Cannot assert anything about L since it can be set by the caller
  } else {
    // TODO put_error
    // We shouldn't ever hit this branch
    return 0;
  }

  if (key_len != EVP_AEAD_key_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_KEY_LENGTH);
    return 0;  // EVP_AEAD_CTX_init should catch this.
  }

  if (tag_len == EVP_AEAD_DEFAULT_TAG_LENGTH) {
    tag_len = M;
  }

  if (tag_len != M) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TAG_TOO_LARGE);
    return 0;
  }

  struct aead_aes_ccm_ctx *ccm_ctx = (struct aead_aes_ccm_ctx *)&ctx->state;

  block128_f block;
  ctr128_f ctr = aes_ctr_set_key(&ccm_ctx->ks.ks, NULL, &block, key, key_len);
  ctx->tag_len = tag_len;
  if (!CRYPTO_ccm128_init(&ccm_ctx->ccm, &ccm_ctx->ks.ks, block, ctr, M, L)) {
    OPENSSL_PUT_ERROR(CIPHER, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  return 1;
}

static void aead_aes_ccm_cleanup(EVP_AEAD_CTX *ctx) {}

static int aead_aes_ccm_seal_scatter(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                     uint8_t *out_tag, size_t *out_tag_len,
                                     size_t max_out_tag_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const uint8_t *in, size_t in_len,
                                     const uint8_t *extra_in,
                                     size_t extra_in_len, const uint8_t *ad,
                                     size_t ad_len) {
  const struct aead_aes_ccm_ctx *ccm_ctx =
      (struct aead_aes_ccm_ctx *)&ctx->state;

  if (in_len > CRYPTO_ccm128_max_input(&ccm_ctx->ccm)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (max_out_tag_len < ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (nonce_len != EVP_AEAD_nonce_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (!CRYPTO_ccm128_encrypt(&ccm_ctx->ccm, &ccm_ctx->ks.ks, out, out_tag,
                             ctx->tag_len, nonce, nonce_len, in, in_len, ad,
                             ad_len)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  *out_tag_len = ctx->tag_len;
  AEAD_CCM_verify_service_indicator(ctx);
  return 1;
}

static int aead_aes_ccm_open_gather(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                    const uint8_t *nonce, size_t nonce_len,
                                    const uint8_t *in, size_t in_len,
                                    const uint8_t *in_tag, size_t in_tag_len,
                                    const uint8_t *ad, size_t ad_len) {
  const struct aead_aes_ccm_ctx *ccm_ctx =
      (struct aead_aes_ccm_ctx *)&ctx->state;

  if (in_len > CRYPTO_ccm128_max_input(&ccm_ctx->ccm)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (nonce_len != EVP_AEAD_nonce_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (in_tag_len != ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  uint8_t tag[EVP_AEAD_AES_CCM_MAX_TAG_LEN];
  assert(ctx->tag_len <= EVP_AEAD_AES_CCM_MAX_TAG_LEN);
  if (!CRYPTO_ccm128_decrypt(&ccm_ctx->ccm, &ccm_ctx->ks.ks, out, tag,
                             ctx->tag_len, nonce, nonce_len, in, in_len, ad,
                             ad_len)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (CRYPTO_memcmp(tag, in_tag, ctx->tag_len) != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  AEAD_CCM_verify_service_indicator(ctx);
  return 1;
}

static int aead_aes_ccm_bluetooth_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                       size_t key_len, size_t tag_len) {
  return aead_aes_ccm_init(ctx, key, key_len, tag_len, 4, 2);
}

DEFINE_METHOD_FUNCTION(EVP_AEAD, EVP_aead_aes_128_ccm_bluetooth) {
  memset(out, 0, sizeof(EVP_AEAD));

  out->key_len = 16;
  out->nonce_len = 13;
  out->overhead = 4;
  out->max_tag_len = 4;
  out->aead_id = AEAD_AES_128_CCM_BLUETOOTH_ID;
  out->seal_scatter_supports_extra_in = 0;

  out->init = aead_aes_ccm_bluetooth_init;
  out->cleanup = aead_aes_ccm_cleanup;
  out->seal_scatter = aead_aes_ccm_seal_scatter;
  out->open_gather = aead_aes_ccm_open_gather;
}

static int aead_aes_ccm_bluetooth_8_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                         size_t key_len, size_t tag_len) {
  return aead_aes_ccm_init(ctx, key, key_len, tag_len, 8, 2);
}

DEFINE_METHOD_FUNCTION(EVP_AEAD, EVP_aead_aes_128_ccm_bluetooth_8) {
  memset(out, 0, sizeof(EVP_AEAD));

  out->key_len = 16;
  out->nonce_len = 13;
  out->overhead = 8;
  out->max_tag_len = 8;
  out->aead_id = AEAD_AES_128_CCM_BLUETOOTH_8_ID;
  out->seal_scatter_supports_extra_in = 0;

  out->init = aead_aes_ccm_bluetooth_8_init;
  out->cleanup = aead_aes_ccm_cleanup;
  out->seal_scatter = aead_aes_ccm_seal_scatter;
  out->open_gather = aead_aes_ccm_open_gather;
}

static int aead_aes_ccm_matter_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                    size_t key_len, size_t tag_len) {
  return aead_aes_ccm_init(ctx, key, key_len, tag_len, 16, 2);
}

DEFINE_METHOD_FUNCTION(EVP_AEAD, EVP_aead_aes_128_ccm_matter) {
  memset(out, 0, sizeof(EVP_AEAD));

  out->key_len = 16;
  out->nonce_len = 13;
  out->overhead = 16;
  out->aead_id = AEAD_AES_128_CCM_MATTER_ID;
  out->max_tag_len = 16;

  out->init = aead_aes_ccm_matter_init;
  out->cleanup = aead_aes_ccm_cleanup;
  out->seal_scatter = aead_aes_ccm_seal_scatter;
  out->open_gather = aead_aes_ccm_open_gather;
}

static int aead_aes_128_ccm_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                 size_t key_len, size_t tag_len) {
  struct aead_aes_ccm_ctx *ccm_ctx = (struct aead_aes_ccm_ctx *)&ctx->state;
  return aead_aes_ccm_init(ctx, key, key_len, tag_len, tag_len, ccm_ctx->ccm.L);
}

static void aead_aes_128_ccm_cleanup(EVP_AEAD_CTX *ctx) {}

static int aead_aes_128_ccm_seal_scatter(const EVP_AEAD_CTX *ctx, uint8_t *out, uint8_t *out_tag,
                                         size_t *out_tag_len, size_t max_out_tag_len,
                                         const uint8_t *nonce, size_t nonce_len, const uint8_t *in,
                                         size_t in_len, const uint8_t *extra_in,
                                         size_t extra_in_len, const uint8_t *ad, size_t ad_len) {
  return 1;
}

static int aead_aes_128_ccm_open_gather(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                        const uint8_t *nonce, size_t nonce_len, const uint8_t *in,
                                        size_t in_len, const uint8_t *in_tag, size_t in_tag_len,
                                        const uint8_t *ad, size_t ad_len) {
  return 1;
}

static const EVP_AEAD aead_aes_128_ccm = {
  .key_len =                          16,
  // Default IV length for AES-CCM is 7. This EVP_AEAD is only used inside an
  // EVP_CIPHER_CTX wrapper, the caller can set a custom nonce length through
  // the EVP_CIPHER_CTX_ctrl API and passing in the top-level EVP_CIPHER_CTX
  // wrapper.
  .nonce_len =                        7,
  .overhead =                         16,
  .max_tag_len =                      16,
  .aead_id =                          AEAD_AES_128_CCM_ID,
  .seal_scatter_supports_extra_in =   1,

  .init =                             aead_aes_128_ccm_init,
  .init_with_direction =              NULL,
  .cleanup =                          aead_aes_128_ccm_cleanup,
  .open =                             NULL,
  .seal_scatter =                     aead_aes_128_ccm_seal_scatter,
  .open_gather =                      aead_aes_128_ccm_open_gather,
  .get_iv =                           NULL,
  .tag_len =                          NULL,
  .serialize_state =                  NULL,
  .deserialize_state =                NULL,
};

static int cipher_aes_ccm_init(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                        const uint8_t *iv, int enc) {
  struct cipher_aes_ccm_ctx *cipher_ctx = (struct cipher_aes_ccm_ctx *)ctx->cipher_data; // TODO nullcheck?

  if (!iv && !key) {
    return 1;
  }

  if (key) {
    const unsigned key_len = ctx->key_len;
    if (key_len != ctx->cipher->key_len) {
      OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_KEY_LENGTH);
      return 0;
    }
  }

  const EVP_AEAD *aead = NULL;

  switch (ctx->cipher->nid) {
    case NID_aes_128_ccm:
      aead = &aead_aes_128_ccm;
      break;
    default:
      return -1; // FIXME
  }

  struct aead_aes_ccm_ctx *ccm_ctx = (struct aead_aes_ccm_ctx *)&cipher_ctx->aead_ctx.state;
  ccm_ctx->ccm.M = cipher_ctx->M;
  ccm_ctx->ccm.L = cipher_ctx->L;
  EVP_AEAD_CTX_init(&cipher_ctx->aead_ctx, aead, key, ctx->key_len, cipher_ctx->M, NULL);


  return 1;
}

static int cipher_aes_ccm_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                          size_t len) {
  return 1;
}

static void cipher_aes_ccm_cleanup(EVP_CIPHER_CTX *ctx) {}

static int cipher_aes_ccm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
  // TODO null check ctx?????
  // TODO or maybe those wrapper/getting functions/macros
  struct cipher_aes_ccm_ctx *cipher_ctx = (struct cipher_aes_ccm_ctx *)ctx->cipher_data;

  switch (type) {
    case EVP_CTRL_INIT:
      cipher_ctx->key_set = 0;
      cipher_ctx->iv_set = 0;
      // The default values for AES-CCM are L = 8 and M = 12. The caller can
      // set custom values by additional calls to EVP_CIPHER_CTX_ctrl.
      cipher_ctx->L = 8;
      cipher_ctx->M = 12;
      cipher_ctx->tag_set = 0;
      cipher_ctx->len_set = 0;
      cipher_ctx->tls_aad_len = -1;
      return 1;

    case EVP_CTRL_GET_IVLEN:
      *(unsigned *)ptr = 15 - cipher_ctx->L;
      return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
      // Save the AAD for later use
      if (arg != EVP_AEAD_TLS1_AAD_LEN) {
        return 0;
      }
      // TODO ctx->buf weird wrapper macro? EVP_CIPHER_CTX_buf_noconst??
      memcpy(ctx->buf, ptr, arg);
      cipher_ctx->tls_aad_len = arg;
      uint16_t len = ctx->buf[arg - 2] << 8 | ctx->buf[arg - 1];

      // Correct length for explicit IV
      if (len < EVP_CCM_TLS_EXPLICIT_IV_LEN) {
        return 0;
      }

      len -= EVP_CCM_TLS_EXPLICIT_IV_LEN;

      // If decrypting, correct for tag too
      if (!ctx->encrypt) {
        if (len < cipher_ctx->M) {
          return 0;
        }

        len -= cipher_ctx->M;
      }

      ctx->buf[arg - 2] = len >> 8; // TODO ctx->buf weird wrapper macro? EVP_CIPHER_CTX_buf_noconst??
      ctx->buf[arg - 1] = len & 0xff;

      // Extra padding: tag appended to record
      return (int)cipher_ctx->M;

    case EVP_CTRL_CCM_SET_IV_FIXED:
      // Sanity check length
      if (arg != EVP_CCM_TLS_FIXED_IV_LEN) {
        return 0;
      }

      // Just copy to first part of IV
      memcpy(ctx->iv, ptr, arg);
      return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
      arg = 15 - arg;
      // Fall through
    case EVP_CTRL_CCM_SET_L:
      if (arg < 2 || arg > 8) {
        return 0;
      }
      cipher_ctx->L = arg;
      return 1;

    case EVP_CTRL_AEAD_SET_TAG:
      if ((arg & 1) || arg < 4 || arg > 16) {
        return 0;
      }

      if (ctx->encrypt && ptr) {
        return 0;
      }

      if (ptr) {
        cipher_ctx->tag_set = 1;
        memcpy(ctx->buf, ptr, arg);
      }
      cipher_ctx->M = arg;
      return 1;

    case EVP_CTRL_AEAD_GET_TAG:
      if (!ctx->encrypt || !cipher_ctx->tag_set) {
        return 0;
      }

      if (!CRYPTO_ccm128_tag(&cipher_ctx->state, ptr, (size_t)arg)) {
        return 0;
      }

      cipher_ctx->tag_set = 0;
      cipher_ctx->iv_set = 0;
      cipher_ctx->len_set = 0;
      return 1;

    case EVP_CTRL_COPY:
    {
      struct aead_aes_ccm_ctx *ccm_ctx = (struct aead_aes_ccm_ctx *)&cipher_ctx->aead_ctx.state;
      EVP_CIPHER_CTX *out = (EVP_CIPHER_CTX *)ptr;
      struct cipher_aes_ccm_ctx *out_cipher_ctx = (struct cipher_aes_ccm_ctx *)out->cipher_data;
      struct aead_aes_ccm_ctx *out_ccm_ctx = (struct aead_aes_ccm_ctx *)&out_cipher_ctx->aead_ctx.state;

      if (ccm_ctx->ccm.key) {
        if (ccm_ctx->ccm.key != &ccm_ctx->ks) {
          return 0;
        }
        out_ccm_ctx->ccm.key = &out_ccm_ctx->ks;
      }
      return 1;
    }

    default:
      return -1;
  }
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_aes_128_ccm) {
  memset(out, 0, sizeof(EVP_CIPHER));

  out->nid = NID_aes_128_ccm;
  out->block_size = 1;
  out->key_len = 16;

  // Default IV length for AES-CCM is 7. Caller can set a custom IV length in
  // the context using EVP_CIPHER_CTX_ctrl with EVP_CTRL_AEAD_SET_IVLEN.
  out->iv_len = 7;
  out->ctx_size = sizeof(struct cipher_aes_ccm_ctx);
  out->flags = EVP_CIPH_CCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_CUSTOM_COPY |
               EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT |
               EVP_CIPH_CTRL_INIT | EVP_CIPH_FLAG_AEAD_CIPHER;
  out->init = cipher_aes_ccm_init;
  out->cipher = cipher_aes_ccm_cipher;
  out->cleanup = cipher_aes_ccm_cleanup;
  out->ctrl = cipher_aes_ccm_ctrl;
}
