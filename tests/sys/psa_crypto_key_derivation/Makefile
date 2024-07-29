include ../Makefile.sys_common

USEMODULE += ztimer
USEMODULE += ztimer_usec

USEMODULE += psa_crypto


USEMODULE += psa_persistent_storage
USEMODULE += psa_key_management

USEMODULE += psa_kdf_hkdf
USEMODULE += psa_key_derivation

USEMODULE += psa_mac
USEMODULE += psa_mac_hmac_sha_256


USEMODULE += hashes
USEMODULE += psa_hash_sha_256
USEMODULE += psa_riot_mac_hmac_generic

USEMODULE += cipher_modes
USEMODULE += crypto_aes_128
USEMODULE += psa_cipher
USEMODULE += psa_cipher_aes_128_cbc

# USEMODULE += psa_asymmetric_ecc_ed25519
# USEMODULE += psa_asymmetric

CFLAGS += -DCONFIG_PSA_SINGLE_KEY_COUNT=2
CFLAGS += -DCONFIG_PSA_ASYMMETRIC_KEYPAIR_COUNT=1

include $(RIOTBASE)/Makefile.include
