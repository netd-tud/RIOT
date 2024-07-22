include ../Makefile.sys_common

USEMODULE += ztimer
USEMODULE += ztimer_usec

USEMODULE += psa_crypto
USEMODULE += psa_key_management
# USEMODULE += psa_key_slot_mgmt


# USEMODULE += psa_mac
# USEMODULE += psa_mac_hmac_sha_256
USEMODULE += psa_kdf_hkdf
USEMODULE += psa_key_derivation


CFLAGS += -DCONFIG_PSA_SINGLE_KEY_COUNT=1
# CFLAGS += -DCONFIG_PSA_PROTECTED_KEY_COUNT=1

include $(RIOTBASE)/Makefile.include
