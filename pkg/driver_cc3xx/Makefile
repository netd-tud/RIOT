PKG_NAME=driver_cc3xx
PKG_URL=https://github.com/TrustedFirmware-M/trusted-firmware-m.git
# main @ 2024-11-01
PKG_VERSION=8241443cd200c075bd16d6e7aa41ec6a69a96630
PKG_LICENSE=BSD-3-Clause

include $(RIOTBASE)/pkg/pkg.mk

# todo: what's the difference between this and Makefile.include?
INCLUDES += -I$(PKGDIRBASE)/driver_cc3xx/platform/ext/target/arm/drivers/cc3xx/low_level_driver/include
INCLUDES += -I$(PKG_SOURCE_DIR)/platform/ext/target/arm/drivers/cc3xx/common
INCLUDES += -I$(PKG_SOURCE_DIR)/platform/include
INCLUDES += -I$(RIOTPKG)/driver_cc3xx/include

# todo: this is an nrf52840 specific value
CFLAGS += -DCC3XX_CONFIG_BASE_ADDRESS=0x5002B000

CFLAGS += -Wno-error=cast-align
CFLAGS += -Wno-error=unused-parameter
CFLAGS += -Wno-error=type-limits
CFLAGS += -Wno-error=old-style-declaration

all: $(filter driver_cc3xx driver_cc3xx-test,$(USEMODULE))

driver_cc3xx: driver_cc3xx-common
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/platform/ext/target/arm/drivers/cc3xx/low_level_driver/src -f $(RIOTBASE)/Makefile.base MODULE=driver_cc3xx

driver_cc3xx-common:
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/platform/ext/target/arm/drivers/cc3xx/common -f $(RIOTBASE)/Makefile.base MODULE=driver_cc3xx-common

driver_cc3xx-test: driver_cc3xx driver_cc3xx-test-ll
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/platform/ext/target/arm/drivers/cc3xx/tests/src -f $(CURDIR)/Makefile.driver_cc3xx-test MODULE=driver_cc3xx-test

driver_cc3xx-test-ll: test-framework
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/platform/ext/target/arm/drivers/cc3xx/tests/src/low_level_driver -f $(CURDIR)/Makefile.driver_cc3xx-test MODULE=driver_cc3xx-test-ll

test-framework:
	$(QQ)"$(MAKE)" -C $(RIOTPKG)/driver_cc3xx/tests -f $(CURDIR)/Makefile.test-suite
