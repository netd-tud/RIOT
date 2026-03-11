/* 
 * SPDX-FileCopyrightText: 2025 TU Dresden
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @ingroup     sys_psa_crypto pkg_cifra
 * @{
 *
 * @brief       Glue code translating between PSA Crypto and the Cifra APIs
 *
 * @author      Oliver Fritz <oliver.fritz-default@protonmail.com>
 *
 * @}
 */

#include "chacha20poly1305.h"
#include "crypto/chacha20poly1305.h"
#include "psa/error.h"
#include "psa/key/attributes.h"
#include <stdio.h>

psa_status_t psa_aead_chacha20_poly1305_encrypt(const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer, size_t key_buffer_length,
                                                uint8_t tag_length, const uint8_t *nonce,
                                                size_t nonce_length, const uint8_t *additional_data,
                                                size_t additional_data_length, const uint8_t *plaintext,
                                                size_t plaintext_length, uint8_t *ciphertext,
                                                size_t ciphertext_size, size_t *ciphertext_length)
{
    (void)attributes;

    if (key_buffer_length != CHACHA20POLY1305_KEY_BYTES ||
        nonce_length != CHACHA20POLY1305_NONCE_BYTES ||
        tag_length != CHACHA20POLY1305_TAG_BYTES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ciphertext_size < plaintext_length + tag_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    cf_chacha20poly1305_encrypt(key_buffer, nonce, additional_data, additional_data_length,
                                plaintext, plaintext_length, ciphertext, &ciphertext[plaintext_length]);

    *ciphertext_length = plaintext_length + tag_length;

    return PSA_SUCCESS;
}

psa_status_t psa_aead_chacha20_poly1305_decrypt(const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer, size_t key_buffer_length,
                                                uint8_t tag_length, const uint8_t *nonce,
                                                size_t nonce_length, const uint8_t *additional_data,
                                                size_t additional_data_length, const uint8_t *ciphertext,
                                                size_t ciphertext_length, uint8_t *plaintext,
                                                size_t plaintext_size, size_t *plaintext_length)
{
    (void)attributes;

    if (key_buffer_length != CHACHA20POLY1305_KEY_BYTES ||
        nonce_length != CHACHA20POLY1305_NONCE_BYTES ||
        tag_length != CHACHA20POLY1305_TAG_BYTES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (plaintext_size < ciphertext_length - tag_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    int ret = cf_chacha20poly1305_decrypt(key_buffer, nonce, additional_data, additional_data_length,
                                          ciphertext, ciphertext_length - tag_length,
                                          &ciphertext[ciphertext_length - tag_length], plaintext);

    if (ret != 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    *plaintext_length = ciphertext_length - tag_length;

    return PSA_SUCCESS;
}
