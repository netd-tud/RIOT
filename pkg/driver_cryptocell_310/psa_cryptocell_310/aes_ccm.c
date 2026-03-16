/*
 * Copyright (C) 2025 TU Dresden
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto pkg_driver_cryptocell_310
 * @{
 *
 * @brief       Glue code translating between PSA Crypto and the PSA Cryptocell 310 APIs
 *
 * @author      Lukas Luger <lukas.luger@mailbox.tu-dresden.de>
 *
 * @}
 */

#include "crypto/helper.h"
#include "psa/aead/types.h"
#include "psa/cipher/types.h"
#include "psa/crypto.h"
#include "crys_aesccm.h"
#include "crys_aesccm_error.h"
#include "psa/error.h"
#include "psa_crypto_operation_encoder.h"
#include "psa_error.h"
#include "cryptocell_310_util.h"
#include <crys_error.h>
#include <math.h>
#include <ssi_aes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ENABLE_DEBUG 0
#include "debug.h"

psa_status_t psa_aead_aes_128_ccm_encrypt(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer, size_t key_buffer_length,
                                          uint8_t tag_length, const uint8_t *nonce,
                                          size_t nonce_length, const uint8_t *additional_data,
                                          size_t additional_data_length, const uint8_t *plaintext,
                                          size_t plaintext_length, uint8_t *ciphertext,
                                          size_t ciphertext_size, size_t *ciphertext_length)
{
    (void)attributes;
    (void)key_buffer_length;
    /* This should already have been checked by PSA. */
    assert(ciphertext_size >= plaintext_length + tag_length);
    (void)ciphertext_size; /* avoid compilation problems with NDEBUG */

    if (!cryptocell_310_data_within_ram(nonce) ||
        !cryptocell_310_data_within_ram(key_buffer) ||
        !cryptocell_310_data_within_ram(additional_data) ||
        !cryptocell_310_data_within_ram(plaintext)) {
        DEBUG("%s : cryptocell_310 data required to be in RAM.\n", __FILE__);
        return PSA_ERROR_DATA_INVALID;
    }

    uint8_t tag[PSA_AES_CCM_TAG_MAX_SIZE];

    CRYSError_t ret = CC_AESCCM(SASI_AES_ENCRYPT, (uint8_t *)key_buffer, CRYS_AES_Key128BitSize,
                                (uint8_t *)nonce, nonce_length, (uint8_t *)additional_data,
                                additional_data_length, (uint8_t *)plaintext, plaintext_length,
                                ciphertext, tag_length, tag, CRYS_AESCCM_MODE_CCM);

    if (ret != CRYS_OK) {
        DEBUG("%s : cryptocell_310 failed to encrypt with %s.\n", __FILE__,
              cryptocell310_status_to_humanly_readable(ret));
        return CRYS_to_psa_error(ret);
    }

    memcpy(&ciphertext[plaintext_length], tag, tag_length);

    *ciphertext_length = plaintext_length + tag_length;

    return PSA_SUCCESS;
}

psa_status_t psa_aead_aes_128_ccm_decrypt(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer, size_t key_buffer_length,
                                          uint8_t tag_length, const uint8_t *nonce,
                                          size_t nonce_length, const uint8_t *additional_data,
                                          size_t additional_data_length, const uint8_t *ciphertext,
                                          size_t ciphertext_length, uint8_t *plaintext,
                                          size_t plaintext_size, size_t *plaintext_length)
{
    (void)attributes;
    (void)key_buffer_length;
    /* This should already have been checked by PSA. */
    assert(plaintext_size >= ciphertext_length - tag_length);

    if (!cryptocell_310_data_within_ram(nonce) ||
        !cryptocell_310_data_within_ram(key_buffer) ||
        !cryptocell_310_data_within_ram(additional_data) ||
        !cryptocell_310_data_within_ram(ciphertext)) {
        DEBUG("%s : cryptocell_310 data required to be in RAM.\n", __FILE__);
        return PSA_ERROR_DATA_INVALID;
    }

    uint8_t tag[PSA_AES_CCM_TAG_MAX_SIZE];
    memcpy(tag, &ciphertext[plaintext_size], tag_length);

    CRYSError_t ret = CC_AESCCM(SASI_AES_DECRYPT, (uint8_t *)key_buffer, CRYS_AES_Key128BitSize,
                                (uint8_t *)nonce, nonce_length, (uint8_t *)additional_data,
                                additional_data_length, (uint8_t *)ciphertext,
                                ciphertext_length - tag_length, plaintext, tag_length,
                                tag, CRYS_AESCCM_MODE_CCM);

    if (ret != CRYS_OK) {
        DEBUG("%s : cryptocell_310 failed to decrypt with %s.\n", __FILE__,
              cryptocell310_status_to_humanly_readable(ret));
        return CRYS_to_psa_error(ret);
    }

    *plaintext_length = ciphertext_length - tag_length;

    return PSA_SUCCESS;
}

psa_status_t psa_aead_aes_128_ccm_setup(CRYS_AESCCM_UserContext_t *ctx,
                                        uint8_t *key_data,
                                        size_t key_length,
                                        uint8_t tag_length)
{
    if (key_length != 16) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Valid tag sizes are 4, 6, 8, 10, 12, 14 and 16. */
    if (tag_length % 2 != 0 || tag_length < 4 || tag_length > 16) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Store the key and the tag length until all the information
     * required for initialization is available. */
    memcpy(ctx->buff, key_data, key_length);
    memcpy(&ctx->buff[key_length], &tag_length, sizeof tag_length);

    return PSA_SUCCESS;
}

psa_status_t psa_aead_aes_128_ccm_set_nonce(psa_aead_operation_t *operation,
                                            const uint8_t *nonce,
                                            size_t nonce_length)
{
    if (nonce_length < 7 || nonce_length > 13) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Now we can check if the provided inputs work together. */
    const size_t L = 15 - nonce_length;
    if (operation->message_length >= pow(2, 8 * L)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Then finally, setup the context. */
    psa_encrypt_or_decrypt_t _direction = operation->state & PSA_AEAD_OP_DIRECTION_MASK;
    SaSiAesEncryptMode_t direction = SASI_AES_ENCRYPT ? (_direction == PSA_CRYPTO_DRIVER_ENCRYPT) : SASI_AES_DECRYPT;

    uint8_t key[16];
    memcpy(key, operation->backend_ctx.crys_aesccm.buff, sizeof key);
    uint8_t tag_length;
    memcpy(&tag_length, &operation->backend_ctx.crys_aesccm.buff[16], sizeof tag_length);

    CRYSError_t ret = CC_AESCCM_Init(&operation->backend_ctx.crys_aesccm,
                                     direction,
                                     key,
                                     CRYS_AES_Key128BitSize,
                                     operation->ad_length,
                                     operation->message_length,
                                     (uint8_t *)nonce,
                                     nonce_length,
                                     tag_length,
                                     CRYS_AESCCM_MODE_CCM);
    if (ret != CRYS_OK) {
        DEBUG("%s : cryptocell_310 failed to decrypt with %s.\n", __FILE__,
              cryptocell310_status_to_humanly_readable(ret));
        return CRYS_to_psa_error(ret);
    }

    crypto_secure_wipe(key, 16);

    return PSA_SUCCESS;
}

psa_status_t psa_aead_aes_128_ccm_update_ad(psa_aead_operation_t *operation,
                                            const uint8_t *input,
                                            size_t input_length)
{
    CRYSError_t ret = CRYS_AESCCM_BlockAdata(CRYS_AESCCM_UserContext_t *ContextID_ptr, uint8_t *DataIn_ptr, uint32_t DataInSize)
}
