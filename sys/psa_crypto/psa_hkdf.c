/*
 * Copyright (C) 2024 TU Dresden
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto
 * @defgroup    sys_psa_crypto_kdf  PSA KDF
 * @{
 *
 * @file        psa_kdf.c
 * @brief       PSA Crypto KDF implementation.
 *
 * @author      Daria Zatokovenko <daria.zatokovenko@mailbox.tu-dresden.de>
 *
 * @}
 */

#include "kernel_defines.h"
#include "psa/crypto.h"
#include "psa/crypto_contexts.h"
#include "psa/crypto_sizes.h"
#include "psa_hkdf.h"
#include "string_utils.h"


#if IS_USED(MODULE_PSA_KDF_HKDF)


// TODO:
psa_status_t psa_hkdf_input(psa_key_derivation_operation_t *operation,
                                            psa_key_derivation_step_t step,
                                            const uint8_t *data,
                                            size_t data_length,
                                            psa_algorithm_t alg)
{
    psa_status_t status;

    switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SALT:
            // TODO: input salt case
#if defined(PSA_ALG_HKDF_EXPAND)
            if (PSA_ALG_IS_HKDF_EXPAND(alg)) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
#endif /* PSA_ALG_HKDF_EXPAND */
            if (!PSA_ALG_IS_HKDF(alg)) {
                return PSA_ERROR_NOT_SUPPORTED;
            }
            status = hkdf_extract(operation, data, data_length);
            if (status != PSA_SUCCESS) {
                return status;
            }
            break;
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            //TODO: input secret case
            return PSA_SUCCESS;
        case PSA_KEY_DERIVATION_INPUT_INFO:
            //TODO: ipnut info case 
            return PSA_SUCCESS;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
    }
}


psa_status_t hkdf_extract(psa_key_derivation_operation_t *operation,
                          const uint8_t *salt,
                          size_t salt_length)
{
    size_t block_size = PSA_HASH_BLOCK_LENGTH(operation.ctx->hash_alg);

    //If salt exceeds the block size of the hash function
    if (salt_length > block_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // If salt is NULL or has zero length, set it to a string of zeroes
    uint8_t *allocated_salt = NULL;
    if (salt == NULL || salt_length == 0) {
        salt_length = hash_len;
        salt = calloc(1, salt_length);
        if (salt == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        allocated_salt = salt;
    }

    //TODO: multi-part HMAC for HKDF
    // Calculate HMAC of the input keying material (ikm) using the salt as the key
    // psa_status_t status = multi-part psa_hmac(...);

    if (status != PSA_SUCCESS) {
        free(allocated_salt);
        return status;
    }

    operation.ctx->prk_length = operation.ctx->hash_length;

    free(allocated_salt);
    return PSA_SUCCESS;
}

psa_status_t hkdf_expand(psa_key_derivation_operation_t *operation)
{
    // TODO: Implement HKDF expand
}

#endif /* MODULE_PSA_KDF_HKDF */
