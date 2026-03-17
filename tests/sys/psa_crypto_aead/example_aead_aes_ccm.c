/*
 * SPDX-FileCopyrightText: 2025 TU Dresden
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @ingroup     tests
 * @{
 *
 * @brief       Example functions for AES CCM Encryption and Decryption with PSA Crypto
 *
 * @author  Oliver Fritz <oliver.fritz-default@protonmail.com>
 *
 * @}
 */

#include <stdio.h>
#include "psa/crypto.h"

/* 
 * Test Vectors from the National Institute of Standards and Technology (NIST)
 *
 * https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES
 */

/* Keys */
static uint8_t KEY_CCM_128[] = {
    0x7d, 0x87, 0x0d, 0x7e, 0x52, 0xd3, 0x05, 0x3c,
    0x65, 0xee, 0xfa, 0xd4, 0x77, 0x64, 0xcf, 0xeb
};

static const uint8_t KEY_CCM_192[] = {
    0x8c, 0xc6, 0x22, 0x64, 0x50, 0x65, 0xc7, 0x2d,
    0x0d, 0x2a, 0xca, 0x75, 0x80, 0x2c, 0xf1, 0xbb,
    0xbd, 0x81, 0x09, 0x67, 0x21, 0x62, 0x7c, 0x08
};

static const uint8_t KEY_CCM_256[] = {
    0xc6, 0xc1, 0x4c, 0x65, 0x5e, 0x52, 0xc8, 0xa4,
    0xc7, 0xe8, 0xd5, 0x4e, 0x97, 0x4d, 0x69, 0x8e,
    0x1f, 0x21, 0xee, 0x3b, 0xa7, 0x17, 0xa0, 0xad,
    0xfa, 0x61, 0x36, 0xd0, 0x26, 0x68, 0xc4, 0x76
};

/* Nonces */
static uint8_t NONCE_CCM_128[] = {
    0x37, 0xd8, 0x88, 0xf4, 0xaa, 0x45, 0x2d, 0x7b,
    0xf2, 0x17, 0xf5, 0xa5, 0x29
};

static const uint8_t NONCE_CCM_192[] = {
    0xcd, 0x84, 0xac, 0xbe, 0x9a, 0xbb, 0x6a, 0x99,
    0x0a
};

static const uint8_t NONCE_CCM_256[] = {
    0x29, 0x1e, 0x91, 0xb1, 0x9d, 0xe5, 0x18, 0xcd,
    0x78, 0x06, 0xde, 0x44, 0xf6
};

/* Plaintexts */
static uint8_t PLAINTEXT_CCM_128[] = {
    0x10, 0x93, 0x17, 0x55, 0x6c, 0x21, 0xc9, 0x69,
    0xed, 0xa6, 0x5a, 0x94, 0x17, 0x6d, 0x7a, 0x11,
    0x46, 0x2c, 0x9a, 0xe1, 0x8a, 0x86, 0x5b, 0x6d
};

static const uint8_t PLAINTEXT_CCM_192[] = {
    0x59, 0x7b, 0x36, 0x14, 0xff, 0x9c, 0xd5, 0x67,
    0xaf, 0xd1, 0xaa, 0xd4, 0xe5, 0xf5, 0x2c, 0xc3,
    0xfa, 0x4c, 0xa3, 0x2b, 0x9b, 0x21, 0x3c, 0x55
};

static const uint8_t PLAINTEXT_CCM_256[] = {};

/* Additional Data */
static uint8_t ADDITIONAL_DATA_CCM_128[] = {
    0x96, 0x10, 0x94, 0x9f, 0x6d, 0x23, 0xd5, 0xb1,
    0xf3, 0x98, 0x9b, 0x2f, 0x4e, 0x52, 0x4f, 0xab,
    0x4f, 0x29, 0x7a, 0x5b, 0xec, 0x8d, 0xda, 0xd4,
    0xf1, 0x6c, 0xb6, 0x16
};

static const uint8_t ADDITIONAL_DATA_CCM_192[] = {
    0x44, 0x7b, 0x6f, 0x36, 0xac, 0xda, 0xd2, 0xd1,
    0xcf, 0xd6, 0xe9, 0xa9, 0x2f, 0x40, 0x55, 0xad,
    0x90, 0x14, 0x2e, 0x61, 0xf4, 0xa1, 0x99, 0x27,
    0xca, 0xea, 0x9d, 0xbe, 0x63, 0x4d, 0x32, 0x08
};

static const uint8_t ADDITIONAL_DATA_CCM_256[] = {
    0xb4, 0xf8, 0x32, 0x69, 0x44, 0xa4, 0x5d, 0x95,
    0xf9, 0x18, 0x87, 0xc2, 0xa6, 0xac, 0x36, 0xb6,
    0x0e, 0xea, 0x5e, 0xde, 0xf8, 0x4c, 0x1c, 0x35,
    0x81, 0x46, 0xa6, 0x66, 0xb6, 0x87, 0x83, 0x35
};

/* Ciphertexts */
static uint8_t CIPHERTEXT_CCM_128[] = {
    0x4e, 0x6b, 0x96, 0x7b, 0x15, 0x71, 0xc6, 0xd7,
    0xb9, 0xe1, 0x18, 0xb1, 0x12, 0xb7, 0xac, 0x94,
    0x9a, 0x4a, 0x17, 0x56, 0x50, 0x31, 0x6a, 0x24,
    /* The last 16B of the ciphertext are the tag. */
    0x2d, 0xd5, 0x79, 0xcb, 0x0d, 0x20, 0x1d, 0x22,
    0xc8, 0x6b, 0xbc, 0x7f, 0xbe, 0x47, 0xbd, 0x0d
};

static const uint8_t CIPHERTEXT_CCM_192[] = {
    0x2d, 0x7f, 0xb8, 0x3e, 0x66, 0x21, 0xee, 0xd9,
    0x07, 0x3e, 0x03, 0x86, 0xd0, 0x32, 0xc6, 0x94,
    0x1b, 0xef, 0x37, 0xb2, 0xcf, 0x36, 0xa4, 0xc6,
    0xc5, 0xe3, 0x62, 0x22, 0xd1, 0x7c, 0x6f, 0xb0,
    0x63, 0x1c, 0x3f, 0x56, 0x0a, 0x3c, 0xe4, 0xa4
};

static const uint8_t CIPHERTEXT_CCM_256[] = {
    0xca, 0x48, 0x2c, 0x67, 0x4b, 0x59, 0x90, 0x46,
    0xcc, 0x7d, 0x7e, 0xe0, 0xd0, 0x0e, 0xec, 0x1e
};

psa_status_t _example_aes_ccm(const uint8_t *key, const size_t key_length,
                              const uint8_t *nonce, const size_t nonce_length,
                              const uint8_t *plaintext, const size_t plaintext_length,
                              const uint8_t *aad, const size_t aad_length,
                              const uint8_t *ciphertext, const size_t ciphertext_length)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    /* KEY IMPORT ------------------------ */
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT;
    /* Note: To have a truncated tag, use PSA_ALG_AEAD_WITH_SHORTENED_TAG */
    psa_algorithm_t alg = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(PSA_ALG_CCM);

    psa_set_key_algorithm(&attr, alg);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(key_length));
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    status = psa_import_key(&attr, key, key_length, &key_id);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        printf("Import Key Error: %s\n", psa_status_to_humanly_readable(status));
        return status;
    }
    /* KEY IMPORT ------------------------ */

    /* ENCRYPT & TAG-GEN ----------------- */
    const size_t ciphertext_out_size = PSA_AEAD_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES,
                                                                    alg,
                                                                    plaintext_length);
    uint8_t ciphertext_out[ciphertext_out_size];

    size_t output_len;
    status = psa_aead_encrypt(key_id,
                              alg,
                              nonce,
                              nonce_length,
                              aad,
                              aad_length,
                              plaintext,
                              plaintext_length,
                              ciphertext_out,
                              ciphertext_out_size,
                              &output_len);

    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        printf("Encrypt Error: %s\n", psa_status_to_humanly_readable(status));
        return status;
    }

    if (memcmp(ciphertext_out, ciphertext, ciphertext_length) != 0) {
        psa_destroy_key(key_id);
        puts("Wrong ciphertext on encryption\n");
        return PSA_ERROR_DATA_INVALID;
    }
    /* ENCRYPT & TAG-GEN ----------------- */

    /* DECRYPT & VERIFY ------------------ */
    const size_t plaintext_out_size = PSA_AEAD_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES,
                                                                   alg,
                                                                   ciphertext_length);
    uint8_t plaintext_out[plaintext_out_size];

    status = psa_aead_decrypt(key_id,
                              alg,
                              nonce,
                              nonce_length,
                              aad,
                              aad_length,
                              ciphertext,
                              ciphertext_length,
                              plaintext_out,
                              plaintext_out_size,
                              &output_len);

    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        printf("Decrypt Error: %s\n", psa_status_to_humanly_readable(status));
        return status;
    }

    if (memcmp(plaintext_out, plaintext, plaintext_length) != 0) {
        printf("Wrong plaintext on decryption\n");
        return PSA_ERROR_DATA_INVALID;
    }
    /* DECRYPT & VERIFY ------------------ */

    psa_destroy_key(key_id);

    return status;
}

/**
 * @brief   Example function to perform an AEAD AES CCM 128 encryption and decryption
 *          with the PSA Crypto API.
 *
 * @return  psa_status_t
 */
psa_status_t example_aead_aes_ccm_128_oneshot(void)
{
    return _example_aes_ccm(KEY_CCM_128, sizeof(KEY_CCM_128),
                            NONCE_CCM_128, sizeof(NONCE_CCM_128),
                            PLAINTEXT_CCM_128, sizeof(PLAINTEXT_CCM_128),
                            ADDITIONAL_DATA_CCM_128, sizeof(ADDITIONAL_DATA_CCM_128),
                            CIPHERTEXT_CCM_128, sizeof(CIPHERTEXT_CCM_128));
}

/**
 * @brief   Example function to perform an AEAD AES CCM 192 encryption and decryption
 *          with the PSA Crypto API.
 *
 * @return  psa_status_t
 */
psa_status_t example_aead_aes_ccm_192_oneshot(void)
{
    return _example_aes_ccm(KEY_CCM_192, sizeof(KEY_CCM_192),
                            NONCE_CCM_192, sizeof(NONCE_CCM_192),
                            PLAINTEXT_CCM_192, sizeof(PLAINTEXT_CCM_192),
                            ADDITIONAL_DATA_CCM_192, sizeof(ADDITIONAL_DATA_CCM_192),
                            CIPHERTEXT_CCM_192, sizeof(CIPHERTEXT_CCM_192));
}

/**
 * @brief   Example function to perform an AEAD AES CCM 256 encryption and decryption
 *          with the PSA Crypto API.
 *
 * @return  psa_status_t
 */
psa_status_t example_aead_aes_ccm_256_oneshot(void)
{
    return _example_aes_ccm(KEY_CCM_256, sizeof(KEY_CCM_256),
                            NONCE_CCM_256, sizeof(NONCE_CCM_256),
                            PLAINTEXT_CCM_256, sizeof(PLAINTEXT_CCM_256),
                            ADDITIONAL_DATA_CCM_256, sizeof(ADDITIONAL_DATA_CCM_256),
                            CIPHERTEXT_CCM_256, sizeof(CIPHERTEXT_CCM_256));
}
