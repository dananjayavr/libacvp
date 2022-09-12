/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <openssl/evp.h>

#include "acvp/acvp.h"
#include "app_lcl.h"
#ifdef ACVP_NO_RUNTIME
#include "app_fips_lcl.h"
#endif

// CycloneCRYPTO includes
#include "core/crypto.h"
#include "crypto_config.h"
#include "hash/hash_algorithms.h"
#include "xof/shake.h"
#include "debug.h"

#define TRACE_LEVEL TRACE_LEVEL_DEBUG

int app_sha_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_HASH_TC *tc;

    const HashAlgo *hashAlgo;  // for CycloneCRYPTO
    HashContext context;       // for CycloneCRYPTO
    ShakeContext shakeContext; // for CycloneCRYPTO

    uint8_t *shakeDigest;

    /* assume fail */
    int rc = 1;
    int sha3 = 0, shake = 0;
    int shake128 = 0;

    ACVP_SUB_HASH alg;

    if (!test_case)
    {
        return 1;
    }

    tc = test_case->tc.hash;
    if (!tc)
        return rc;

    alg = acvp_get_hash_alg(tc->cipher);
    if (alg == 0)
    {
        printf("Invalid cipher value");
        return 1;
    }

    switch (alg)
    {

    case ACVP_SUB_HASH_SHA1:
        hashAlgo = SHA1_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHA2_224:
        hashAlgo = SHA224_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHA2_256:
        hashAlgo = SHA256_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHA2_384:
        hashAlgo = SHA384_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHA2_512:
        hashAlgo = SHA512_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHA2_512_224:
        hashAlgo = SHA512_224_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHA2_512_256:
        hashAlgo = SHA512_256_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHA3_224:
        sha3 = 1;
        hashAlgo = SHA3_224_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHA3_256:
        sha3 = 1;
        hashAlgo = SHA3_256_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHA3_384:
        sha3 = 1;
        hashAlgo = SHA3_384_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHA3_512:
        sha3 = 1;
        hashAlgo = SHA3_512_HASH_ALGO;
        break;

    case ACVP_SUB_HASH_SHAKE_128:
        shake = 1;
        shake128 = 1;
        break;
    case ACVP_SUB_HASH_SHAKE_256:
        shake = 1;
        break;

    default:
        printf("Error: Unsupported hash algorithm requested by ACVP server\n");
        return ACVP_NO_CAP;
    }

    if (!tc->md)
    {
        printf("\nCrypto module error, md memory not allocated by library\n");
        goto end;
    }

    if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT && !sha3 && !shake)
    { // SHA
        /* If Monte Carlo we need to be able to init and then update
         * one thousand times before we complete each iteration.
         * This style doesn't apply to sha3 MCT.
         */
        if (!tc->m1 || !tc->m2 || !tc->m3)
        {
            printf("\nCrypto module error, m1, m2, or m3 missing in sha mct test case\n");
            goto end;
        }

        hashAlgo->init(&context);
        hashAlgo->update(&context, tc->m1, tc->msg_len);
        hashAlgo->update(&context, tc->m2, tc->msg_len);
        hashAlgo->update(&context, tc->m3, tc->msg_len);
        hashAlgo->final(&context, tc->md);

        tc->md_len = hashAlgo->digestSize;

        rc = 0;
    }
    else if (shake)
    {
        if (tc->test_type == ACVP_HASH_TEST_TYPE_VOT ||
            (tc->test_type == ACVP_HASH_TEST_TYPE_MCT && shake))
        {
#if 0
            if(shake128) {
                shakeInit(&shakeContext, 128);
            } else {
                shakeInit(&shakeContext, 256);
            }

            shakeAbsorb(&shakeContext, tc->msg, tc->msg_len);
            shakeFinal(&shakeContext);
            shakeSqueeze(&shakeContext, tc->md, tc->xof_len);
#endif
            if(shake128) {
                shakeCompute(128, tc->msg, tc->msg_len, tc->md, tc->xof_len);
            } else {
                shakeCompute(256, tc->msg, tc->msg_len, tc->md, tc->xof_len);
            }
            tc->md_len = tc->xof_len;
            rc = 0;

            goto end;
        }
    }
    else
    {
        hashAlgo->init(&context);
        hashAlgo->update(&context, tc->msg, tc->msg_len);
        hashAlgo->final(&context, tc->md);

        tc->md_len = hashAlgo->digestSize;
    }

    rc = 0;

end:
    return rc;
}
