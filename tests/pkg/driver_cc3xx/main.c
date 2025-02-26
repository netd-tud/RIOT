/*
 * Copyright (C) 2024 TU Dresden
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       Test the correct loading and linking of the driver_cc3xx package and
                execute built-in selftests.
 *
 * @author      Mikolai Gütschow <mikolai.guetschow@tu-dresden.de>
 *
 * @}
 */

#include <stdio.h>

#include "container.h"

#include "test_framework.h"

#include "vendor/nrf52840.h"
#include "cc3xx_init.h"

void stub(struct test_suite_t *p_test_suite)
{
    // intentionally empty
    (void)p_test_suite;
}

static struct test_suite_t cc3xx_test_suite = { .freg = stub };

void add_cc3xx_tests_to_testsuite(struct test_suite_t *p_ts, uint32_t ts_size);
static struct test_t cc3xx_tests[100];

int main(void)
{
    puts("driver_cc3xx test\n");

    NRF_CRYPTOCELL->ENABLE = 1;

    cc3xx_lowlevel_init();

    set_testsuite("cc3xx tests", cc3xx_tests, 0, &cc3xx_test_suite);
    add_cc3xx_tests_to_testsuite(&cc3xx_test_suite, ARRAY_SIZE(cc3xx_tests));

    run_testsuite(&cc3xx_test_suite);

    return 0;
}
