include ../Makefile.sys_common

USEMODULE += ztimer
USEMODULE += ztimer_usec
USEMODULE += psa_crypto

USEMODULE += psa_aead
USEMODULE += psa_aead_aes_128_ccm
#USEMODULE += psa_aead_aes_128_ccm_custom_backend
#USEMODULE += psa_aead_aes_128_ccm_backend_riot
USEMODULE += psa_aead_aes_192_ccm
#USEMODULE += psa_aead_aes_192_ccm_custom_backend
#USEMODULE += psa_aead_aes_192_ccm_backend_riot
USEMODULE += psa_aead_aes_256_ccm
#USEMODULE += psa_aead_aes_256_ccm_custom_backend
#USEMODULE += psa_aead_aes_256_ccm_backend_riot

CFLAGS += -DCONFIG_PSA_SINGLE_KEY_COUNT=2

include $(RIOTBASE)/Makefile.include
