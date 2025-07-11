/*
 * Copyright (C) 2014-2016 Freie Universität Berlin
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_nrf5x_common
 * @ingroup     drivers_periph_spi
 * @{
 *
 * @file
 * @brief       Low-level SPI driver implementation based on the SPIM peripheral
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 * @author      Frank Holtz <frank-riot2015@holtznet.de>
 * @author      Jan Wagner <mail@jwagner.eu>
 * @author      Koen Zandberg <koen@bergzand.net>
 *
 * @}
 */

#include <assert.h>

#include "cpu.h"
#include "mutex.h"
#include "periph/spi.h"
#include "periph/gpio.h"
#include "periph_cpu.h"
#include <string.h>

#define RAM_MASK            (0x20000000)

/**
 * @brief   array holding one pre-initialized mutex for each SPI device
 */
static mutex_t locks[SPI_NUMOF];

/**
 * @brief   array with a busy mutex for each SPI device, used to block the
 *          thread until the transfer is done
 */
static mutex_t busy[SPI_NUMOF];

static uint8_t _mbuf[SPI_NUMOF][CONFIG_SPI_MBUF_SIZE];

static void spi_isr_handler(void *arg);

static inline NRF_SPIM_Type *dev(spi_t bus)
{
    return (NRF_SPIM_Type *)spi_config[bus].dev;
}

static inline bool _in_ram(const uint8_t *data)
{
    return ((uint32_t)data & RAM_MASK);
}

#ifdef ERRATA_SPI_SINGLE_BYTE_WORKAROUND
void spi_gpio_handler(void *arg)
{
    spi_t bus = (spi_t)(uintptr_t)arg;

    /**
     * Immediately disable the IRQ, we only care about one PPI event per
     * transfer
     */
    gpio_irq_disable(spi_config[bus].sclk);
}
#endif

/**
 * @brief Work-around for transmitting 1 byte with SPIM on the nrf52832.
 * @warning Must not be used when transmitting multiple bytes.
 * @warning After this workaround is used, the user must reset the PPI channel
 *          and the GPIOTE channel before attempting to transmit multiple bytes.
 *
 * @param bus   The SPI instance that is in use.
 */
static void _setup_workaround_for_ftpan_58(spi_t bus)
{
#ifdef ERRATA_SPI_SINGLE_BYTE_WORKAROUND
    gpio_init_int(spi_config[bus].sclk, GPIO_OUT, GPIO_BOTH,
                  spi_gpio_handler, (void *)(uintptr_t)bus);
    gpio_irq_disable(spi_config[bus].sclk);
    uint8_t channel = gpio_int_get_exti(spi_config[bus].sclk);
    assert(channel != 0xff);

    // Stop the spim instance when SCK toggles.
    NRF_PPI->CH[spi_config[bus].ppi].EEP =
        (uint32_t)&NRF_GPIOTE->EVENTS_IN[channel];
    NRF_PPI->CH[spi_config[bus].ppi].TEP = (uint32_t)&dev(bus)->TASKS_STOP;
#else
    (void)bus;
#endif
}

static void _enable_workaround(spi_t bus)
{
#ifdef ERRATA_SPI_SINGLE_BYTE_WORKAROUND
    /**
     * The spim instance cannot be stopped mid-byte, so it will finish
     * transmitting the first byte and then stop. Effectively ensuring
     * that only 1 byte is transmitted.
     */
    NRF_PPI->CHENSET = 1U << spi_config[bus].ppi;
    gpio_irq_enable(spi_config[bus].sclk);
#else
    (void)bus;
#endif
}

static void _clear_workaround(spi_t bus)
{
#ifdef ERRATA_SPI_SINGLE_BYTE_WORKAROUND
    NRF_PPI->CHENCLR = 1U << spi_config[bus].ppi;
#else
    (void)bus;
#endif
}

/* Beware: This needs to be kept in sync with the I2C version of this.
 * Specifically, when registers are configured that are valid to the peripheral
 * in both SPI and I2C mode, the register needs to be configured in both the I2C
 * and the SPI variant of _setup_shared_peripheral() to avoid from parameters
 * leaking from one bus into the other */
static void _setup_shared_peripheral(spi_t bus)
{
    SPI_SCKSEL = spi_config[bus].sclk;
    SPI_MOSISEL = spi_config[bus].mosi;
    SPI_MISOSEL = spi_config[bus].miso;
}

void spi_init(spi_t bus)
{
    assert(bus < SPI_NUMOF);

    /* initialize mutex */
    mutex_init(&busy[bus]);
    mutex_lock(&busy[bus]);
    /* initialize pins */
    spi_init_pins(bus);
    _setup_shared_peripheral(bus);
}

int spi_init_with_gpio_mode(spi_t bus, const spi_gpio_mode_t* mode)
{
    assert(bus < SPI_NUMOF);

    if (gpio_is_valid(spi_config[bus].mosi)) {
        gpio_init(spi_config[bus].mosi, mode->mosi);
    }

    if (gpio_is_valid(spi_config[bus].miso)) {
        gpio_init(spi_config[bus].miso, mode->miso);
    }

    if (gpio_is_valid(spi_config[bus].sclk)) {
        /* clk_pin will be muxed during acquire / release */
        gpio_init(spi_config[bus].sclk, mode->sclk);
    }

    return 0;
}

void spi_init_pins(spi_t bus)
{
    const spi_gpio_mode_t gpio_modes = {
        .mosi = GPIO_OUT,
        .sclk = GPIO_OUT,
        .miso = GPIO_IN,
    };
    spi_init_with_gpio_mode(bus, &gpio_modes);

    /* select pins for the SPI device */
    _setup_workaround_for_ftpan_58(bus);
    shared_irq_register_spi(dev(bus), spi_isr_handler, (void *)(uintptr_t)bus);
}

void spi_acquire(spi_t bus, spi_cs_t cs, spi_mode_t mode, spi_clk_t clk)
{
    (void)cs;
    assert((unsigned)bus < SPI_NUMOF);

    if (IS_USED(MODULE_PERIPH_SPI_RECONFIGURE)) {
        mutex_lock(&locks[bus]);
    }

    nrf5x_spi_acquire(dev(bus), spi_isr_handler, (void *)(uintptr_t)bus);
    _setup_shared_peripheral(bus);

    /* configure bus */
    dev(bus)->CONFIG = mode;
    dev(bus)->FREQUENCY = clk;
    /* enable the bus */
    dev(bus)->ENABLE = SPIM_ENABLE_ENABLE_Enabled;
}

void spi_release(spi_t bus)
{
    /* power off everything */
    dev(bus)->ENABLE = 0;

    if (IS_USED(MODULE_PERIPH_SPI_RECONFIGURE)) {
        mutex_unlock(&locks[bus]);
    }

    nrf5x_spi_release(dev(bus));
}

static size_t _transfer(spi_t bus, const uint8_t *out_buf, uint8_t *in_buf,
                        size_t remaining_len)
{
    uint8_t transfer_len = remaining_len > UINT8_MAX ? UINT8_MAX : remaining_len;
    const uint8_t *out_mbuf = out_buf;

    /**
     * Copy the out buffer in case it resides in flash, EasyDMA only works from
     * RAM
     */
    if (out_buf && !_in_ram(out_buf)) {
        /* The SPI MBUF can be smaller than UINT8_MAX */
        transfer_len = transfer_len > CONFIG_SPI_MBUF_SIZE
                     ? CONFIG_SPI_MBUF_SIZE : transfer_len;
        memcpy(_mbuf[bus], out_buf, transfer_len);
        out_mbuf = _mbuf[bus];
    }

    uint8_t out_len = (out_buf) ? transfer_len : 0;
    uint8_t in_len = (in_buf) ? transfer_len : 0;

    dev(bus)->TXD.PTR = (uint32_t)out_mbuf;
    dev(bus)->RXD.PTR = (uint32_t)in_buf;

    dev(bus)->TXD.MAXCNT = out_len;
    dev(bus)->RXD.MAXCNT = in_len;

    /* clear any spurious END events */
    dev(bus)->EVENTS_END = 0;
    dev(bus)->TASKS_START = 1;
    return transfer_len;
}

void spi_transfer_bytes(spi_t bus, spi_cs_t cs, bool cont,
                        const void *out, void *in, size_t len)
{
    const uint8_t *out_buf = out;
    uint8_t *in_buf = in;

    assert(out_buf || in_buf);

    if (cs != SPI_CS_UNDEF) {
        gpio_clear((gpio_t)cs);
    }

    /* Enable the workaround when the length is only 1 byte */
    size_t _len = len;
    if (_len == 1) {
        _enable_workaround(bus);
    }

    /* Enable IRQ */
    dev(bus)->INTENSET = SPIM_INTENSET_END_Msk;

    do {
        size_t transfer_len = _transfer(bus, out_buf, in_buf, len);
        /* Block until the irq releases the mutex, then lock it again for the
         * next transfer */
        mutex_lock(&busy[bus]);
        out_buf += out_buf ? transfer_len : 0;
        in_buf += in_buf ? transfer_len : 0;
        len -= transfer_len;
    } while (len);

    /* Disable IRQ */
    dev(bus)->INTENCLR = SPIM_INTENCLR_END_Msk;

    /**
     * While we could always disable the workaround, only doing this when
     * required spares us some cycles by not having to write to volatile
     * registers
     */
    if (_len == 1) {
        _clear_workaround(bus);
    }

    if ((cs != SPI_CS_UNDEF) && (!cont)) {
        gpio_set((gpio_t)cs);
    }
}

void spi_isr_handler(void *arg)
{
    spi_t bus = (spi_t)(uintptr_t)arg;

    mutex_unlock(&busy[bus]);
    dev(bus)->EVENTS_END = 0;
}
