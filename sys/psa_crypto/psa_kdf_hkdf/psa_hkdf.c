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
#include "psa/crypto_struct.h"
#include "psa/crypto_types.h"
#include "psa_hkdf.h"
#include <math.h>
#include "string_utils.h"
#include "psa_crypto_slot_management.h"

#if IS_USED(MODULE_PSA_KDF_HKDF)

psa_status_t psa_hkdf_key_derivation_setup(psa_key_derivation_operation_t *operation,
                                                psa_algorithm_t alg)
{
    operation->alg = alg;


    // operation->ctx.hkdf->hash_alg = PSA_ALG_GET_HASH(alg);
    operation->ctx.hkdf.hash_length = PSA_HASH_LENGTH(alg);

    // psa_algorithm_t hash_alg = operation->ctx.hkdf->hash_alg;
    size_t hash_length = operation->ctx.hkdf.hash_length;

    if (PSA_ALG_IS_HKDF(alg)) {
        psa_key_derivation_set_capacity(operation, 255 * hash_length);
    }else
    if (PSA_ALG_IS_HKDF_EXTRACT(alg)) {
        psa_key_derivation_set_capacity(operation, hash_length);
    } else
    if (PSA_ALG_IS_HKDF_EXPAND(alg)) {
        psa_key_derivation_set_capacity(operation, 255 * hash_length);
    } 

    return PSA_SUCCESS;
}


psa_status_t psa_hkdf_input_bytes(psa_key_derivation_operation_t *operation,
                                  psa_key_derivation_step_t step,
                                  const uint8_t *data,
                                  size_t data_length,
                                  psa_algorithm_t alg)
{
    psa_status_t status = PSA_SUCCESS;

    /** The operation state is not valid for this input step*/
    if (!is_valid_step_for_current_state(operation->state, step))
    {
        return PSA_ERROR_BAD_STATE;
    }

    switch (step)
    {
    case PSA_KEY_DERIVATION_INPUT_SALT:
#if defined(PSA_ALG_HKDF_EXPAND)
        if (PSA_ALG_IS_HKDF_EXPAND(alg))
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
#endif /* PSA_ALG_HKDF_EXPAND */
        if (operation->ctx.hkdf.salt != NULL)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        operation->ctx.hkdf.salt = data;
        operation->ctx.hkdf.salt_length = data_length;
        operation->state = STATE_SALT_PROVIDED;
        break;
        /** The secret can also be a direct input passed to psa_key_derivation_input_bytes().
         *  In this case, the derivation operation cannot be used to derive keys:
         *  the operation will not permit a call to psa_key_derivation_output_key().*/
    case PSA_KEY_DERIVATION_INPUT_SECRET:
        operation->can_output_key = 0;
        operation->state = STATE_SECRET_PROVIDED;
        break;
    case PSA_KEY_DERIVATION_INPUT_INFO:
#if defined(PSA_ALG_HKDF_EXTRACT)
        if (PSA_ALG_IS_HKDF_EXTRACT(alg))
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
#endif /* PSA_ALG_HKDF_EXTRACT */
        if (operation->ctx.hkdf.info != NULL)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        operation->ctx.hkdf.info = data;
        operation->ctx.hkdf.info_length = data_length;
        operation->state = STATE_INFO_PROVIDED;
        break;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

psa_status_t psa_hkdf_input_key(psa_key_derivation_operation_t *operation,
                                psa_key_derivation_step_t step,
                                psa_key_type_t key_type,
                                const uint8_t *data,
                                size_t data_length,
                                psa_algorithm_t alg)
{
    psa_status_t status = PSA_SUCCESS;

    /** The operation state is not valid for this input step*/
    if (!is_valid_step_for_current_state(operation->state, step))
    {
        return PSA_ERROR_BAD_STATE;
    }

    switch (step)
    {
    case PSA_KEY_DERIVATION_INPUT_SALT:
#if defined(PSA_ALG_HKDF_EXPAND)
        if (PSA_ALG_IS_HKDF_EXPAND(alg))
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
#endif /* PSA_ALG_HKDF_EXPAND */
        if (operation->ctx.hkdf.salt != NULL)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (!(key_type == PSA_KEY_TYPE_RAW_DATA))
        {
            return PSA_ERROR_NOT_PERMITTED;
        }

        operation->ctx.hkdf.salt = data;
        operation->ctx.hkdf.salt_length = data_length;
        operation->state = STATE_SALT_PROVIDED;
        break;
    case PSA_KEY_DERIVATION_INPUT_SECRET:
#if defined(PSA_ALG_HKDF_EXPAND)
        if (PSA_ALG_IS_HKDF_EXPAND(operation->alg))
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
#endif /* PSA_ALG_HKDF_EXPAND */
        if (operation->ctx.hkdf.ikm != NULL)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (!(key_type == PSA_KEY_TYPE_DERIVE))
        {
            return PSA_ERROR_NOT_PERMITTED;
        }
        operation->ctx.hkdf.ikm = data;
        operation->ctx.hkdf.ikm_length = data_length;
        operation->state = STATE_SECRET_PROVIDED;
        break;
    case PSA_KEY_DERIVATION_INPUT_INFO:
#if defined(PSA_ALG_HKDF_EXTRACT)
        if (PSA_ALG_IS_HKDF_EXTRACT(alg))
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
#endif /* PSA_ALG_HKDF_EXTRACT */
        if (operation->ctx.hkdf.info != NULL)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (!(key_type == PSA_KEY_TYPE_RAW_DATA))
        {
            return PSA_ERROR_NOT_PERMITTED;
        }
        operation->ctx.hkdf.info = data;
        operation->ctx.hkdf.info_length = data_length;
        operation->state = STATE_INFO_PROVIDED;
        break;
    default:
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (operation->ctx.hkdf.ikm != NULL)
    {
        status = hkdf_extract(operation, operation->ctx.hkdf.ikm, operation->ctx.hkdf.ikm_length, operation->ctx.hkdf.salt, operation->ctx.hkdf.salt_length);
        if (status != PSA_SUCCESS)
        {
            return status;
        }
    }

    return status;
}

psa_status_t psa_hkdf_output_bytes(psa_key_derivation_operation_t *operation,
                                   uint8_t *output,
                                   size_t output_length,
                                   psa_algorithm_t alg)
{

    psa_status_t status = PSA_SUCCESS;

    if (operation->state != STATE_INFO_PROVIDED)
    {
        return PSA_ERROR_BAD_STATE;
    }

#if defined(PSA_ALG_HKDF_EXTRACT)
    if (PSA_ALG_IS_HKDF_EXTRACT(alg))
    {
        return PSA_ERROR_BAD_STATE;
    }
#endif /* PSA_ALG_HKDF_EXTRACT */

    // Call the HKDF expand function to generate the output bytes
    status = hkdf_expand(operation, output, output_length);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    operation->state = STATE_OUTPUT_GENERATED;

    return status;
}

psa_status_t psa_hkdf_output_key(psa_key_derivation_operation_t *operation,
                                 const psa_key_attributes_t *attributes,
                                 const uint8_t *key_buffer,
                                 size_t key_buffer_size,
                                 psa_key_id_t *key)
{
    psa_status_t status = PSA_SUCCESS;
    (void)key_buffer;
    // psa_se_drv_data_t *driver = NULL;
    
    // Set the attributes for the key
    psa_set_key_usage_flags((psa_key_attributes_t *)attributes, PSA_KEY_CREATION_DERIVE);
    psa_set_key_type((psa_key_attributes_t *)attributes, PSA_KEY_CREATION_DERIVE);
    psa_set_key_bits((psa_key_attributes_t *)attributes, key_buffer_size * 8); // size in bits

    status = psa_generate_derived_key(key_buffer_size, attributes, operation, key);
    // status = psa_generate_derived_key(key_buffer, key_buffer_size, attributes, operation, key);


    if (status != PSA_SUCCESS)
    {
        return status;
        // if (&slot == NULL) {
        //     return;
        // }
        // psa_wipe_key_slot(slot);
    }

    return status;

    // psa_key_slot_t slot;
    // // Import the key into the slot
    // status = psa_import_key((psa_key_attributes_t *)attributes, key_buffer, key_buffer_size, key);
    // if (status != PSA_SUCCESS) {
    //     return status;
    // }

    // status = psa_start_key_creation_wrapper(PSA_KEY_CREATION_DERIVE, attributes,
    //                                 &slot, &driver);

    // if (status != PSA_SUCCESS)
    // {
    //     if (&slot == NULL) {
    //         return;
    //     }
    //     psa_wipe_key_slot(slot);
    // }

    // status = psa_finish_key_creation_wrapper(slot, driver, key);

    // if (status != PSA_SUCCESS)
    // {
    //     if (&slot == NULL) {
    //         return;
    //     }
    //     psa_wipe_key_slot(slot);
    // }

    // psa_unlock_key_slot(slot);

}
//const uint8_t *key_buffer,
psa_status_t psa_generate_derived_key(
                                      size_t key_buffer_size,
                                      const psa_key_attributes_t *attributes,
                                      psa_key_derivation_operation_t *operation,
                                      psa_key_id_t *key)
{

    uint8_t *derived_data = NULL; // Buffer to hold the derived key data
    size_t bits = key_buffer_size * 8; // Size of the key in bits
    // size_t storage_size = key_buffer_size; 
    // size_t bytes = PSA_BITS_TO_BYTES(bits); // Size of the key in bytes

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    // psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;

    if (attributes->type != PSA_KEY_TYPE_RAW_DATA)
    {
        return PSA_ERROR_NOT_PERMITTED;
    }

    // The key size must be a multiple of 8 bits
    if (bits % 8 != 0)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // Allocate a buffer of size bytes to store the derived key data
    derived_data = calloc(1, key_buffer_size);
    if (derived_data == NULL)
    {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = hkdf_expand(operation, derived_data, key_buffer_size);
    if (status != PSA_SUCCESS)
    {
        explicit_bzero(derived_data, key_buffer_size);
        free(derived_data);
        return status;
    }

    status = psa_import_key((psa_key_attributes_t *)attributes, derived_data, key_buffer_size, key);

    if (status != PSA_SUCCESS)
    {
        psa_destroy_key(*key);
        return status;
    }

    /* key export from an external device is currently not supported */

    // if (psa_key_lifetime_is_external(attributes->lifetime))
    // {
        
    //     status = PSA_ERROR_NOT_SUPPORTED;
    //     unlock_status = psa_unlock_key_slot(slot);
    //     if (unlock_status != PSA_SUCCESS)
    //     {
    //         status = unlock_status;
    //     }
    //     return status;
    // }

    // Allocate a buffer of size storage_size to the key slot
    // This buffer will be used to store the key data
    // if (key_buffer != NULL)
    // {
    //     return PSA_ERROR_ALREADY_EXISTS;
    // }

    // &key_buffer = calloc(1, storage_size);
    // if (&key_buffer == NULL)
    // {
    //     return PSA_ERROR_INSUFFICIENT_MEMORY;
    // }

    // bytes = storage_size;
    return status;
}

psa_status_t hkdf_extract(psa_key_derivation_operation_t *operation,
                          const uint8_t *ikm, size_t ikm_length,
                          const uint8_t *salt, size_t salt_length)
{
    size_t block_size = PSA_HASH_BLOCK_LENGTH(operation->ctx.hkdf.hash_alg);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_status_t status;
    size_t actual_hash_length;

    // If salt is NULL or has zero length, set it to a string of zeroes
    uint8_t *allocated_salt = NULL;
    if (salt == NULL || salt_length == 0)
    {
        salt_length = operation->ctx.hkdf.hash_length;
        allocated_salt = calloc(1, salt_length);
        if (allocated_salt == NULL)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
    }
    else if (salt_length > block_size)
    {
        // If salt exceeds the block size of the hash function, hash it
        allocated_salt = malloc(salt_length);
        if (allocated_salt == NULL)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        status = psa_hash_compute(operation->ctx.hkdf.hash_alg, salt, salt_length, allocated_salt, salt_length, &actual_hash_length);
        if (status != PSA_SUCCESS)
        {
            free(allocated_salt);
            return status;
        }
    }
    else
    {
        allocated_salt = malloc(salt_length);
        if (allocated_salt == NULL)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        memcpy(allocated_salt, salt, salt_length);
    }

    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(operation->ctx.hkdf.hash_alg));
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(salt_length));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);

    status = psa_import_key(&attributes, allocated_salt, salt_length, &key_id);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    status = psa_mac_compute(key_id, PSA_ALG_HMAC(operation->ctx.hkdf.hash_alg), ikm, ikm_length, operation->ctx.hkdf.prk, operation->ctx.hkdf.hash_length, &operation->ctx.hkdf.prk_length);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    free(allocated_salt);
    return PSA_SUCCESS;
}

/**
 * @brief Perform the HKDF-Expand operation
 * 
 * @param operation The key derivation operation
 * @param output The output buffer
 * @param output_length The length of the output buffer
 * @return psa_status_t 
*/
psa_status_t hkdf_expand(psa_key_derivation_operation_t *operation,
                         uint8_t *output, size_t output_length)
{
    uint8_t hash_len = operation->ctx.hkdf.hash_length;
    size_t info_len = operation->ctx.hkdf.info_length;
    const uint8_t *info = operation->ctx.hkdf.info;
    size_t N = (size_t)ceil((double)output_length/hash_len);
    uint8_t T[hash_len];
    T[0] = '\0';
    size_t T_len = 0;
    uint8_t counter = 1;
    psa_status_t status;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t prk_id;

    //set prk key attributes
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(operation->ctx.hkdf.hash_alg));
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(operation->ctx.hkdf.prk_length));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);

    // create key from the PRK
    status = psa_import_key(&attributes, operation->ctx.hkdf.prk, operation->ctx.hkdf.prk_length, &prk_id);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    // expand the key
    for (size_t i = 0; i < N; i++)
    {   // Concatenate the previous T, info and the counter
        uint8_t data[hash_len + info_len + 1];  // Buffer to hold the concatenated data
        memcpy(data, T, T_len);                 // Copy the previous T to the data buffer
        memcpy(data + T_len, info, info_len);   // Copy the info to the data buffer
        data[T_len + info_len] = counter++;     // Copy the counter to the data buffer

        // Calculate HMAC of the concatenated data using the PRK as the key
        status = psa_mac_compute(prk_id, PSA_ALG_HMAC(operation->ctx.hkdf.hash_alg), data, T_len + info_len + 1, T, sizeof(T), &T_len);
        if (status != PSA_SUCCESS)
        {
            return status;
        }
        // Copy the first min(T_len, output_length) bytes of T to the output
        memcpy(output + i * hash_len, T, i == N - 1 ? output_length - i * hash_len : hash_len);
    }

    return status;

    // psa_status_t status = PSA_SUCCESS;
    // uint8_t hash_length = operation->ctx.hkdf.hash_length; // Length of the hash function output
    // uint8_t T[PSA_HASH_MAX_SIZE] = {0};                    // Buffer to hold the intermediate values
    // uint8_t counter = 1;                                   // Counter for the iteration
    // size_t n, T_length = 0;                                // Length of the intermediate value
    // size_t data_length;

    // psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    // psa_key_id_t key_id;

    // psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(operation->ctx.hkdf.hash_alg));
    // psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(operation->ctx.hkdf.prk_length));
    // psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    // psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);

    // // create key from the PRK
    // status = psa_import_key(&attributes, operation->ctx.hkdf.prk, operation->ctx.hkdf.prk_length, &key_id);
    // if (status != PSA_SUCCESS)
    // {
    //     return status;
    // }

    // // Perform the HKDF-Expand operation
    // while (output_length > 0)
    // {
    //     // Concatenate the previous T, info and the counter
    //     uint8_t data[PSA_HASH_MAX_SIZE + operation->ctx.hkdf.info_length + 1]; // Buffer to hold the concatenated data

    //     // Copy the previous T to the data buffer
    //     for (size_t i = 0; i < T_length; i++)
    //     {
    //         data[i] = T[i];
    //     }

    //     // Copy the info to the data buffer
    //     for (size_t i = 0; i < operation->ctx.hkdf.info_length; i++)
    //     {
    //         data[T_length + i] = operation->ctx.hkdf.info[i];
    //     }

    //     data[T_length + operation->ctx.hkdf.info_length] = counter;
    //     data_length = T_length + operation->ctx.hkdf.info_length + 1;

    //     // Calculate HMAC of the concatenated data using the PRK as the key
    //     status = psa_mac_compute(key_id, PSA_ALG_HMAC(operation->ctx.hkdf.hash_alg), data, data_length, T, sizeof(T), &T_length);
    //     if (status != PSA_SUCCESS)
    //     {
    //         return status;
    //     }

    //     // Copy the first min(T_length, output_length) bytes of T to the output
    //     n = (output_length < hash_length) ? output_length : hash_length;
    //     for (size_t i = 0; i < n; i++)
    //     {
    //         output[i] = T[i];
    //     }

    //     output += n;
    //     output_length -= n;
    //     counter++;
    // }

}

bool is_valid_step_for_current_state(operation_state_t state, psa_key_derivation_step_t step)
{
    switch (state)
    {
    case STATE_NONE:
        /** At the start either the salt or the secret can be provided*/
        return step == PSA_KEY_DERIVATION_INPUT_SALT || step == PSA_KEY_DERIVATION_INPUT_SECRET;
    case STATE_SALT_PROVIDED: /** After salt */
                              /** After the salt, either the secret or the info can be provided*/
        return step == PSA_KEY_DERIVATION_INPUT_SECRET || step == PSA_KEY_DERIVATION_INPUT_INFO;
    case STATE_SECRET_PROVIDED:
        /** After the secret, only the info can be provided*/
        return step == PSA_KEY_DERIVATION_INPUT_INFO;
    case STATE_INFO_PROVIDED:
        /** After the info, no more steps are valid*/
        return false;
    default:
        return false;
    }
}


#endif