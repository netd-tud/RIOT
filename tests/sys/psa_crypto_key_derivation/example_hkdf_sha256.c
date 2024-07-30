/*
 * Copyright (C) 2024 TU Dresden
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @brief       Tests the PSA HKDF SHA256 configurations
 *
 * @author      Daria Zatokovenko <daria.zatokovenko@tu-dresden.de>
 *
 * @}
 */

#include "psa/crypto.h"

#include <stdio.h>
#include <stdint.h>

#include <limits.h>
#include <string.h>
#include <stdlib.h>

/**
 * @brief   Example function to perform an HKDF using SHA-256 computation
 *          with the PSA Crypto API.
 *
 * @return  psa_status_t
 */
psa_status_t example_hkdf_sha256(void)
{
    psa_status_t status = psa_crypto_init();

    if (status != PSA_SUCCESS) {
        printf("psa_crypto_init failed with status: %d\n", status);
        return status;
    }

    static const unsigned char key[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b
    };
    static const unsigned char salt[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    static const unsigned char info[] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
        0xf7, 0xf8, 0xf9
    };

    size_t data_length;
    psa_algorithm_t alg = PSA_ALG_HKDF(PSA_ALG_SHA_256);
    psa_key_attributes_t attributes = psa_key_attributes_init();
    psa_key_derivation_operation_t operation = psa_key_derivation_operation_init();

    size_t derived_bits = 128;
    size_t capacity = PSA_BITS_TO_BYTES(derived_bits);

    psa_key_id_t base_key;
    psa_key_id_t derived_key;

    /* Import the IKM to later pass it to the operation */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
    status = psa_import_key(&attributes, key, sizeof(key), &base_key);
    if (status != PSA_SUCCESS) {
        printf("Failed to import IKM with status: %d\n", status);
        return status;
    }
    psa_reset_key_attributes(&attributes);

    status = psa_key_derivation_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin key derivation with status: %d\n", status);
        return status;
    }
    status = psa_key_derivation_set_capacity(&operation, capacity);
    if (status != PSA_SUCCESS) {
        printf("Failed to set capacity with status: %d\n", status);
        return status;
    }
    /* Input the salt directly */
    status = psa_key_derivation_input_bytes(&operation,
                                            PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, sizeof(salt));
    if (status != PSA_SUCCESS) {
        printf("Failed to input salt (extract) with status: %d\n", status);
        return status;
    }
    /* Input the secret IKM */
    status = psa_key_derivation_input_key(&operation,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          base_key);
    if (status != PSA_SUCCESS) {
        printf("Failed to input key (extract) with status: %d\n", status);
        return status;
    }
    /* Input the info directly */
    status = psa_key_derivation_input_bytes(&operation,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            info, sizeof(info));
    if (status != PSA_SUCCESS) {
        printf("Failed to input info (expand) with status: %d\n", status);
        return status;
    }
    /* Set attributes for the derived key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);

    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION
                                      (PSA_KEY_LIFETIME_PERSISTENT, PSA_KEY_LOCATION_LOCAL_STORAGE);
    psa_set_key_lifetime(&attributes, lifetime);

    status = psa_key_derivation_output_key(&attributes, &operation,
                                           &derived_key);
    if (status != PSA_SUCCESS) {
        printf("Failed to derive key with status: %d\n", status);
        return status;
    }

    status = psa_export_key(derived_key, NULL, 0, &data_length);
    if (status != PSA_ERROR_BUFFER_TOO_SMALL) {
        printf("Buffer allocation wrong with status: %d\n", status);
    }

    uint8_t *buffer = malloc(data_length);
    if (buffer == NULL) {
        printf("Failed to allocate buffer with status: %d\n", status);
    }

    status = psa_export_key(derived_key, buffer, sizeof(buffer), &data_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to export derived key with status: %d\n", status);
        return status;
    }

    printf("Derived key: \n");
    for (size_t i = 0; i < data_length; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");

    psa_reset_key_attributes(&attributes);

    /* Clean up key derivation operation */
    psa_key_derivation_abort(&operation);

    /* Destroy the keys */
    psa_destroy_key(derived_key);
    psa_destroy_key(base_key);

    return status;
}
