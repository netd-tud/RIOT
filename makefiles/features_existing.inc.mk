# WARNING: This has been auto-generated from features.yaml.
#          Do not edit this by hand, but update features.yaml instead.
#          Finally, run `make generate-features` in the root of the RIOT repo.
FEATURES_EXISTING := \
    arch_16bit \
    arch_32bit \
    arch_64bit \
    arch_8bit \
    arch_arm \
    arch_arm7 \
    arch_avr8 \
    arch_efm32 \
    arch_esp \
    arch_esp32 \
    arch_esp32_xtensa \
    arch_esp8266 \
    arch_esp_riscv \
    arch_esp_xtensa \
    arch_msp430 \
    arch_native \
    arch_nuclei \
    arch_riscv \
    arduino_analog \
    arduino_dac \
    arduino_i2c \
    arduino_pins \
    arduino_pwm \
    arduino_shield_isp \
    arduino_shield_mega \
    arduino_shield_nano \
    arduino_shield_uno \
    arduino_spi \
    arduino_uart \
    atmega_pcint0 \
    atmega_pcint1 \
    atmega_pcint2 \
    atmega_pcint3 \
    atxmega_ebi \
    backup_ram \
    ble_adv_ext \
    ble_nimble \
    ble_nimble_netif \
    ble_phy_2mbit \
    ble_phy_coded \
    bootloader_stm32 \
    can_rx_mailbox \
    cortexm_fpu \
    cortexm_mpu \
    cortexm_stack_limit \
    cortexm_svc \
    cpp \
    cpu_arm7tdmi_gba \
    cpu_atmega1281 \
    cpu_atmega1284p \
    cpu_atmega128rfa1 \
    cpu_atmega2560 \
    cpu_atmega256rfr2 \
    cpu_atmega328p \
    cpu_atmega32u4 \
    cpu_atmega8 \
    cpu_atxmega \
    cpu_cc2538 \
    cpu_cc26x0_cc13x0 \
    cpu_cc26x2_cc13x2 \
    cpu_check_address \
    cpu_core_atmega \
    cpu_core_atxmega \
    cpu_core_cortexm \
    cpu_efm32 \
    cpu_esp32 \
    cpu_esp8266 \
    cpu_fe310 \
    cpu_gd32v \
    cpu_kinetis \
    cpu_lm4f120 \
    cpu_lpc1768 \
    cpu_lpc23xx \
    cpu_msp430 \
    cpu_msp430_f2xx_g2xx \
    cpu_msp430_x1xx \
    cpu_native \
    cpu_nrf51 \
    cpu_nrf52 \
    cpu_nrf53 \
    cpu_nrf9160 \
    cpu_qn908x \
    cpu_rpx0xx \
    cpu_sam3 \
    cpu_samd21 \
    cpu_samd5x \
    cpu_saml1x \
    cpu_saml21 \
    cpu_stm32 \
    cpu_stm32c0 \
    cpu_stm32f0 \
    cpu_stm32f1 \
    cpu_stm32f2 \
    cpu_stm32f3 \
    cpu_stm32f4 \
    cpu_stm32f7 \
    cpu_stm32g0 \
    cpu_stm32g4 \
    cpu_stm32l0 \
    cpu_stm32l1 \
    cpu_stm32l4 \
    cpu_stm32l5 \
    cpu_stm32mp1 \
    cpu_stm32u5 \
    cpu_stm32wb \
    cpu_stm32wl \
    dbgpin \
    efm32_coretemp \
    emulator_renode \
    esp_ble \
    esp_ble_esp32 \
    esp_ble_esp32c3 \
    esp_hw_counter \
    esp_jtag \
    esp_now \
    esp_rmt \
    esp_rtc_timer_32k \
    esp_spi_oct \
    esp_spi_ram \
    esp_spiffs \
    esp_wifi \
    esp_wifi_ap \
    esp_wifi_enterprise \
    gecko_sdk_librail_fpu \
    gecko_sdk_librail_nonfpu \
    highlevel_stdio \
    libstdcpp \
    motor_driver \
    netif \
    netif_ethernet \
    netif_openwsn \
    newlib \
    no_idle_thread \
    periph_adc \
    periph_adc_continuous \
    periph_can \
    periph_cipher_aes_128_cbc \
    periph_clic \
    periph_coretimer \
    periph_cpuid \
    periph_cryptocell_310 \
    periph_dac \
    periph_dma \
    periph_ecc_ed25519 \
    periph_ecc_p192r1 \
    periph_ecc_p256r1 \
    periph_eeprom \
    periph_eth \
    periph_flashpage \
    periph_flashpage_aux \
    periph_flashpage_in_address_space \
    periph_flashpage_pagewise \
    periph_flashpage_rwee \
    periph_fmc \
    periph_fmc_16bit \
    periph_fmc_32bit \
    periph_fmc_nor_sram \
    periph_fmc_sdram \
    periph_freqm \
    periph_gpio \
    periph_gpio_fast_read \
    periph_gpio_irq \
    periph_gpio_ll \
    periph_gpio_ll_disconnect \
    periph_gpio_ll_input_pull_down \
    periph_gpio_ll_input_pull_keep \
    periph_gpio_ll_input_pull_up \
    periph_gpio_ll_irq \
    periph_gpio_ll_irq_level_triggered_high \
    periph_gpio_ll_irq_level_triggered_low \
    periph_gpio_ll_irq_unmask \
    periph_gpio_ll_open_drain \
    periph_gpio_ll_open_drain_pull_up \
    periph_gpio_ll_open_source \
    periph_gpio_ll_open_source_pull_down \
    periph_gpio_ll_switch_dir \
    periph_gpio_tamper_wake \
    periph_hash_md5 \
    periph_hash_sha_1 \
    periph_hash_sha_224 \
    periph_hash_sha_256 \
    periph_hash_sha_384 \
    periph_hash_sha_512 \
    periph_hash_sha_512_224 \
    periph_hash_sha_512_256 \
    periph_hmac_md5 \
    periph_hmac_sha_1 \
    periph_hmac_sha_224 \
    periph_hmac_sha_256 \
    periph_hmac_sha_384 \
    periph_hmac_sha_512 \
    periph_hwrng \
    periph_i2c \
    periph_i2c_reconfigure \
    periph_ics \
    periph_lpuart \
    periph_ltdc \
    periph_mcg \
    periph_mcg_lite \
    periph_nvm \
    periph_pio \
    periph_plic \
    periph_pm \
    periph_pmp \
    periph_ptp \
    periph_ptp_speed_adjustment \
    periph_ptp_timer \
    periph_ptp_txrx_timestamps \
    periph_pwm \
    periph_qdec \
    periph_rtc \
    periph_rtc_mem \
    periph_rtc_ms \
    periph_rtt \
    periph_rtt_overflow \
    periph_rtt_set_counter \
    periph_sdmmc \
    periph_sdmmc_8bit \
    periph_sdmmc_auto_clk \
    periph_sdmmc_auto_cmd12 \
    periph_sdmmc_clk \
    periph_sdmmc_hs \
    periph_sdmmc_mmc \
    periph_sdmmc_sdhc \
    periph_spi \
    periph_spi_gpio_mode \
    periph_spi_on_qspi \
    periph_spi_reconfigure \
    periph_spi_stmod \
    periph_temperature \
    periph_timer \
    periph_timer_periodic \
    periph_timer_poll \
    periph_timer_query_freqs \
    periph_uart \
    periph_uart_collision \
    periph_uart_hw_fc \
    periph_uart_modecfg \
    periph_uart_nonblocking \
    periph_uart_reconfigure \
    periph_uart_rxstart_irq \
    periph_uart_tx_ondemand \
    periph_usbdev \
    periph_usbdev_hs \
    periph_usbdev_hs_ulpi \
    periph_usbdev_hs_utmi \
    periph_vbat \
    periph_wdt \
    periph_wdt_cb \
    periph_wdt_warning_period \
    picolibc \
    pio_i2c \
    puf_sram \
    radio_nrf802154 \
    radio_nrfble \
    radio_nrfmin \
    riotboot \
    rust_target \
    sdcard_spi \
    ssp \
    tinyusb_device \
    vdd_lc_filter_reg0 \
    vdd_lc_filter_reg1 \
    #
