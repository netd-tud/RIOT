#include <stdio.h>
#include "psa/crypto.h"
#include "ztimer.h"

extern psa_status_t example_hkdf_sha256(void);

int main(void)
{
    bool failed = false;
    psa_status_t status;

    psa_crypto_init();

    ztimer_acquire(ZTIMER_USEC);
    ztimer_now_t start = ztimer_now(ZTIMER_USEC);

    printf("KDF TEST RUNNING\n");

    status = example_hkdf_sha256();
    if (status != PSA_SUCCESS) {
        failed = true;
        printf("HKDF SHA256 failed: %s\n", psa_status_to_humanly_readable(status));
    }

    ztimer_release(ZTIMER_USEC);

    if (failed) {
        puts("Tests failed...");
    }
    else {
        puts("All Done");
    }
    return 0;
}
