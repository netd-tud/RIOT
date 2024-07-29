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
#include "psa_kdf.h"
#include "string_utils.h"


#if IS_USED(MODULE_PSA_KEY_DERIVATION)

psa_status_t psa_kdf_abort(psa_key_derivation_operation_t *operation)
{
    // Clear operation structure
    explicit_bzero(operation, sizeof(psa_key_derivation_operation_t));

    *operation = psa_key_derivation_operation_init();

    return PSA_SUCCESS;
}


#endif /* MODULE_PSA_KEY_DERIVATION */
