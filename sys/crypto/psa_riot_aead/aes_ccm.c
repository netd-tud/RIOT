/*
 * SPDX-FileCopyrightText: 2025 TU Dresden
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @ingroup     sys_psa_crypto
 * @{
 *
 * @file
 * @brief       Glue code translating between PSA Crypto and the RIOT Cipher module
 *
 * @author  Oliver Fritz <oliver.fritz-default@protonmail.com>
 *
 * @}
 */

#include "psa/cipher/types.h"
#include <stddef.h>
#include <stdint.h>
#include "psa/error.h"
#include "psa/key/attributes.h"
#include "crypto/modes/ccm.h"
#include <stdio.h>

static psa_status_t _ccm_to_psa_error(int ccm_error)
{
    switch (ccm_error) {
    case CCM_ERR_INVALID_NONCE_LENGTH:
    case CCM_ERR_INVALID_LENGTH_ENCODING:
    case CCM_ERR_INVALID_MAC_LENGTH:
        return PSA_ERROR_INVALID_ARGUMENT;
    case CCM_ERR_INVALID_CBC_MAC:
        return PSA_ERROR_INVALID_SIGNATURE;
    default:
        return PSA_ERROR_GENERIC_ERROR;
    }
}

static psa_status_t _cipher_to_psa_error(int error)
{
    switch (error) {
    case CIPHER_ERR_INVALID_KEY_SIZE:
    case CIPHER_ERR_INVALID_LENGTH:
    case CIPHER_ERR_BAD_CONTEXT_SIZE:
        return PSA_ERROR_INVALID_ARGUMENT;
    default:
        return PSA_ERROR_GENERIC_ERROR;
    }
}

static psa_status_t _ccm_encrypt_decrypt(const psa_encrypt_or_decrypt_t direction,
                                         uint8_t *key_buffer, size_t key_buffer_length,
                                         uint8_t tag_length, const uint8_t *nonce,
                                         size_t nonce_length, const uint8_t *additional_data,
                                         size_t additional_data_length, const uint8_t *input,
                                         size_t input_length, uint8_t *output,
                                         size_t output_size, size_t *output_length)
{
    int ret;

    if (direction == PSA_CRYPTO_DRIVER_ENCRYPT) {
        if (output_size < input_length + tag_length) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
    }
    else {
        if (output_size < input_length - tag_length) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
    }
    if (nonce_length < 7 || nonce_length > 13) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    cipher_t ctx;
    ret = cipher_init(&ctx, CIPHER_AES, key_buffer, key_buffer_length);
    if (ret != CIPHER_INIT_SUCCESS) {
        return _cipher_to_psa_error(ret);
    }

    /* This is set statically by PSA Crypto. */
    const uint8_t length_encoding = 15 - nonce_length;
    if (direction == PSA_CRYPTO_DRIVER_ENCRYPT) {
        ret = cipher_encrypt_ccm(&ctx,
                                 additional_data,
                                 additional_data_length,
                                 tag_length,
                                 length_encoding,
                                 nonce,
                                 nonce_length,
                                 input,
                                 input_length,
                                 output);
    }
    else {
        ret = cipher_decrypt_ccm(&ctx,
                                 additional_data,
                                 additional_data_length,
                                 tag_length,
                                 length_encoding,
                                 nonce,
                                 nonce_length,
                                 input,
                                 input_length,
                                 output);
    }
    if (ret < 0) {
        return _ccm_to_psa_error(ret);
    }

    *output_length = ret;

    return PSA_SUCCESS;
}

#if IS_USED(MODULE_PSA_AEAD_AES_128_CCM_BACKEND_RIOT)
psa_status_t psa_aead_aes_128_ccm_encrypt(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer, size_t key_buffer_length,
                                          uint8_t tag_length, const uint8_t *nonce,
                                          size_t nonce_length, const uint8_t *additional_data,
                                          size_t additional_data_length, const uint8_t *plaintext,
                                          size_t plaintext_length, uint8_t *ciphertext,
                                          size_t ciphertext_size, size_t *ciphertext_length)
{
    (void)attributes;

    return _ccm_encrypt_decrypt(PSA_CRYPTO_DRIVER_ENCRYPT, key_buffer, key_buffer_length,
                                tag_length, nonce, nonce_length, additional_data,
                                additional_data_length, plaintext, plaintext_length,
                                ciphertext, ciphertext_size, ciphertext_length);
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

    return _ccm_encrypt_decrypt(PSA_CRYPTO_DRIVER_DECRYPT, key_buffer, key_buffer_length,
                                tag_length, nonce, nonce_length, additional_data,
                                additional_data_length, ciphertext, ciphertext_length,
                                plaintext, plaintext_size, plaintext_length);
}
#endif

#if IS_USED(MODULE_PSA_AEAD_AES_192_CCM_BACKEND_RIOT)
psa_status_t psa_aead_aes_192_ccm_encrypt(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer, size_t key_buffer_length,
                                          uint8_t tag_length, const uint8_t *nonce,
                                          size_t nonce_length, const uint8_t *additional_data,
                                          size_t additional_data_length, const uint8_t *plaintext,
                                          size_t plaintext_length, uint8_t *ciphertext,
                                          size_t ciphertext_size, size_t *ciphertext_length)
{
    (void)attributes;

    return _ccm_encrypt_decrypt(PSA_CRYPTO_DRIVER_ENCRYPT, key_buffer, key_buffer_length,
                                tag_length, nonce, nonce_length, additional_data,
                                additional_data_length, plaintext, plaintext_length,
                                ciphertext, ciphertext_size, ciphertext_length);
}

psa_status_t psa_aead_aes_192_ccm_decrypt(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer, size_t key_buffer_length,
                                          uint8_t tag_length, const uint8_t *nonce,
                                          size_t nonce_length, const uint8_t *additional_data,
                                          size_t additional_data_length, const uint8_t *ciphertext,
                                          size_t ciphertext_length, uint8_t *plaintext,
                                          size_t plaintext_size, size_t *plaintext_length)
{
    (void)attributes;

    return _ccm_encrypt_decrypt(PSA_CRYPTO_DRIVER_DECRYPT, key_buffer, key_buffer_length,
                                tag_length, nonce, nonce_length, additional_data,
                                additional_data_length, ciphertext, ciphertext_length,
                                plaintext, plaintext_size, plaintext_length);
}
#endif

#if IS_USED(MODULE_PSA_AEAD_AES_256_CCM_BACKEND_RIOT)
psa_status_t psa_aead_aes_256_ccm_encrypt(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer, size_t key_buffer_length,
                                          uint8_t tag_length, const uint8_t *nonce,
                                          size_t nonce_length, const uint8_t *additional_data,
                                          size_t additional_data_length, const uint8_t *plaintext,
                                          size_t plaintext_length, uint8_t *ciphertext,
                                          size_t ciphertext_size, size_t *ciphertext_length)
{
    (void)attributes;

    return _ccm_encrypt_decrypt(PSA_CRYPTO_DRIVER_ENCRYPT, key_buffer, key_buffer_length,
                                tag_length, nonce, nonce_length, additional_data,
                                additional_data_length, plaintext, plaintext_length,
                                ciphertext, ciphertext_size, ciphertext_length);
}

psa_status_t psa_aead_aes_256_ccm_decrypt(const psa_key_attributes_t *attributes,
                                          uint8_t *key_buffer, size_t key_buffer_length,
                                          uint8_t tag_length, const uint8_t *nonce,
                                          size_t nonce_length, const uint8_t *additional_data,
                                          size_t additional_data_length, const uint8_t *ciphertext,
                                          size_t ciphertext_length, uint8_t *plaintext,
                                          size_t plaintext_size, size_t *plaintext_length)
{
    (void)attributes;

    return _ccm_encrypt_decrypt(PSA_CRYPTO_DRIVER_DECRYPT, key_buffer, key_buffer_length,
                                tag_length, nonce, nonce_length, additional_data,
                                additional_data_length, ciphertext, ciphertext_length,
                                plaintext, plaintext_size, plaintext_length);
}
#endif
