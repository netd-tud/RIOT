BOARD ?= nrf52840dk

include ../Makefile.pkg_common

USEPKG += driver_cc3xx

USEMODULE += driver_cc3xx-test
USEMODULE += driver_cc3xx-testsuite

CFLAGS += -DUSE_STDIO

include $(RIOTBASE)/Makefile.include
