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
#include "safe_lib.h"
#ifdef ACVP_NO_RUNTIME
#include "app_fips_lcl.h"
#endif

// CycloneCRYPTO includes
#include "core/crypto.h"
#include "cipher/cipher_algorithms.h"
#include "aead/ccm.h"
#include "aead/gcm.h"
#include "cipher_modes/cbc.h"
#include "aead/chacha20_poly1305.h"
#include "debug.h"

static EVP_CIPHER_CTX *glb_cipher_ctx = NULL; /* need to maintain across calls for MCT */

// CycloneCRYPTO context for MCT
static CipherContext mctCipherContext = {0};
static GcmContext mctGcmCipherContext = {0};

<<<<<<< HEAD
// Forward declarations
void dumpGcmTestVector(ACVP_SYM_CIPHER_TC *tc);
void dumpCbcTestVector(ACVP_SYM_CIPHER_TC *tc);

=======
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0
void app_aes_cleanup(void)
{
    if (glb_cipher_ctx)
        EVP_CIPHER_CTX_free(glb_cipher_ctx);
    glb_cipher_ctx = NULL;
}

int app_aes_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_SYM_CIPHER_TC *tc = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    unsigned char *iv = 0;

    // CycloneCRYPTO stuff
    CipherContext cipherContext = {0};
    uint8_t cyclone_error;
    const CipherAlgo *cipherAlgo;

    /* assume fail at first */
    int rv = 0;
    ACVP_SUB_AES alg;

    if (!test_case)
    {
        return rv;
    }

    tc = test_case->tc.symmetric;

    if (glb_cipher_ctx == NULL)
    {
        glb_cipher_ctx = EVP_CIPHER_CTX_new();
        if (glb_cipher_ctx == NULL)
        {
            printf("Failed to allocate global cipher_ctx");
            return 1;
        }
    }

    /* Begin encrypt code section */
    cipher_ctx = glb_cipher_ctx;
    if ((tc->test_type != ACVP_SYM_TEST_TYPE_MCT))
    {
        EVP_CIPHER_CTX_init(cipher_ctx);
    }

    alg = acvp_get_aes_alg(tc->cipher);
    if (alg == 0)
    {
        printf("Invalid cipher value");
        return 1;
    }

    switch (alg)
    {
    case ACVP_SUB_AES_ECB:
        switch (tc->key_len)
        {
        case 128:
            cipher = EVP_aes_128_ecb();
            break;
        case 192:
            cipher = EVP_aes_192_ecb();
            break;
        case 256:
            cipher = EVP_aes_256_ecb();
            break;
        default:
            printf("Unsupported AES key length\n");
            rv = 1;
            goto err;
        }
        break;
    case ACVP_SUB_AES_CTR:
        iv = tc->iv;
        switch (tc->key_len)
        {
        case 128:
            cipher = EVP_aes_128_ctr();
            break;
        case 192:
            cipher = EVP_aes_192_ctr();
            break;
        case 256:
            cipher = EVP_aes_256_ctr();
            break;
        default:
            printf("Unsupported AES key length\n");
            rv = 1;
            goto err;
        }
        break;
    case ACVP_SUB_AES_CFB1:
        iv = tc->iv;
        switch (tc->key_len)
        {
        case 128:
            cipher = EVP_aes_128_cfb1();
            break;
        case 192:
            cipher = EVP_aes_192_cfb1();
            break;
        case 256:
            cipher = EVP_aes_256_cfb1();
            break;
        default:
            printf("Unsupported AES key length\n");
            rv = 1;
            goto err;
        }
        break;
    case ACVP_SUB_AES_CFB8:
        iv = tc->iv;
        switch (tc->key_len)
        {
        case 128:
            cipher = EVP_aes_128_cfb8();
            break;
        case 192:
            cipher = EVP_aes_192_cfb8();
            break;
        case 256:
            cipher = EVP_aes_256_cfb8();
            break;
        default:
            printf("Unsupported AES key length\n");
            rv = 1;
            goto err;
        }
        break;
    case ACVP_SUB_AES_CFB128:
        iv = tc->iv;
        switch (tc->key_len)
        {
        case 128:
            cipher = EVP_aes_128_cfb128();
            break;
        case 192:
            cipher = EVP_aes_192_cfb128();
            break;
        case 256:
            cipher = EVP_aes_256_cfb128();
            break;
        default:
            printf("Unsupported AES key length\n");
            rv = 1;
            goto err;
        }
        break;
    case ACVP_SUB_AES_OFB:
        iv = tc->iv;
        switch (tc->key_len)
        {
        case 128:
            cipher = EVP_aes_128_ofb();
            break;
        case 192:
            cipher = EVP_aes_192_ofb();
            break;
        case 256:
            cipher = EVP_aes_256_ofb();
            break;
        default:
            printf("Unsupported AES key length\n");
            rv = 1;
            goto err;
        }
        break;
    case ACVP_SUB_AES_CBC:
        iv = tc->iv;
        switch (tc->key_len)
        {
        case 128:
<<<<<<< HEAD
        case 192:
        case 256:
=======
            cipher = EVP_aes_128_cbc();
            cipherAlgo = AES_CIPHER_ALGO;
            cipherAlgo->init(&cipherContext, tc->key, tc->key_len);
            break;
        case 192:
            cipher = EVP_aes_192_cbc();
            cipherAlgo = AES_CIPHER_ALGO;
            cipherAlgo->init(&cipherContext, tc->key, tc->key_len);
            break;
        case 256:
            cipher = EVP_aes_256_cbc();
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0
            cipherAlgo = AES_CIPHER_ALGO;
            cipherAlgo->init(&cipherContext, tc->key, tc->key_len);
            break;
        default:
            printf("Unsupported AES key length\n");
            rv = 1;
            goto err;
        }
        break;
    case ACVP_SUB_AES_CBC_CS1:
    case ACVP_SUB_AES_CBC_CS2:
    case ACVP_SUB_AES_CBC_CS3:
        printf("AES-CBC-CSX algorithms are unsupported currently\n");
        rv = 1;
        goto err;
    case ACVP_SUB_AES_XTS:
        switch (tc->key_len)
        {
        case 128:
            cipher = EVP_aes_128_xts();
            break;
        case 256:
            cipher = EVP_aes_256_xts();
            break;
        default:
            printf("Unsupported AES key length\n");
            rv = 1;
            goto err;
        }
        switch (tc->tw_mode)
        {
        case ACVP_SYM_CIPH_TWEAK_HEX:
            iv = tc->iv;
            break;
        case ACVP_SYM_CIPH_TWEAK_NUM:
        case ACVP_SYM_CIPH_TWEAK_NONE:
        default:
            printf("\nUnsupported tweak mode %d %d\n", tc->seq_num, tc->tw_mode);
            rv = 1;
            goto err;
            break;
        }
        break;
    case ACVP_SUB_AES_GCM:
    case ACVP_SUB_AES_GCM_SIV:
    case ACVP_SUB_AES_CCM:
    case ACVP_SUB_AES_XPN:
    case ACVP_SUB_AES_KW:
    case ACVP_SUB_AES_KWP:
    case ACVP_SUB_AES_GMAC:
    default:
        printf("Error: Unsupported AES mode requested by ACVP server\n");
        rv = 1;
        goto err;
    }

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT)
    {
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
        {
            if (tc->mct_index == 0)
            {
                EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 1);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
                if (tc->cipher == ACVP_AES_CFB1)
                {
                    EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
                }
            }
            EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            tc->ct_len = tc->pt_len;
        }
        else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT)
        {
            if (tc->mct_index == 0)
            {
                EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 0);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
                if (tc->cipher == ACVP_AES_CFB1)
                {
                    EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
                }
            }
            EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
            tc->pt_len = tc->ct_len;
        }
        else
        {
            printf("Unsupported direction\n");
            rv = 1;
            goto err;
        }
        if (tc->mct_index == ACVP_AES_MCT_INNER - 1)
        {
            EVP_CIPHER_CTX_free(cipher_ctx);
            glb_cipher_ctx = NULL;
        }
    }
    else
    {
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
        {
            // EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 1);
            // EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            // if (tc->cipher == ACVP_AES_CFB1)
            // {
            //     EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            // }
            // EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);

            // CycloneCRYPTO
            if (alg == ACVP_SUB_AES_CBC)
            {
                cipherAlgo->init(&cipherContext, tc->key, tc->key_len / 8);
                cyclone_error = cbcEncrypt(cipherAlgo, &cipherContext, tc->iv, tc->pt, tc->ct, tc->pt_len);
                if (cyclone_error != 0)
                {
                    printf("ERROR (%d): cbcEncrypt Failed.\n", cyclone_error);
<<<<<<< HEAD
                    rv = 1;
                    goto err;
=======
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0
                }
            }
            else
            {
                EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 1);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
                if (tc->cipher == ACVP_AES_CFB1)
                {
                    EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
                }
                EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            }

            tc->ct_len = tc->pt_len;
        }
        else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT)
        {
            // EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 0);
            // EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            // if (tc->cipher == ACVP_AES_CFB1)
            // {
            //     EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
            // }
            // EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);

            // CycloneCRYPTO
            if (alg == ACVP_SUB_AES_CBC)
            {
                cipherAlgo->init(&cipherContext, tc->key, tc->key_len / 8);

<<<<<<< HEAD
                cyclone_error = cbcDecrypt(cipherAlgo, &cipherContext, tc->iv, tc->ct, tc->pt, tc->ct_len); // CipherText Len is in Bytes (16bits = 2 bytes)
=======
                cipherAlgo->init(&cipherContext, tc->key, tc->key_len / 8);
#if 0  
                // Dump test vector information
                printf("Cipher Text: ");
                for (int i = 0; i < tc->ct_len; i++)
                {
                    printf("%02X ", tc->ct[i]);
                }
                printf("\n");

                printf("Cipher Text Length: %d bits\n", tc->ct_len);

                printf("IV: ");
                for (int i = 0; i < tc->iv_len; i++)
                {
                    printf("%02X ", tc->iv[i]);
                }
                printf("\n");
                printf("IV Length: %d bits\n", tc->iv_len);

                printf("KEY: ");
                for (int i = 0; i < tc->key_len; i++)
                {
                    printf("%02X ", tc->key[i]);
                }
                printf("\n");
                printf("KEY Length: %d bits\n", tc->key_len);
#endif
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0

                cyclone_error = cbcDecrypt(cipherAlgo, &cipherContext, tc->iv, tc->ct, tc->pt, tc->ct_len);
                if (cyclone_error != 0)
                {
<<<<<<< HEAD
                    printf("ERROR (%d): cbcDecrypt Failed\n", cyclone_error);
                    rv = 1;
                    goto err;
=======
                    printf("ERROR (%d): cbcDecrypt Failed.\n", cyclone_error);
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0
                }
            }
            else
            {
                EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, iv, 0);
                EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
                if (tc->cipher == ACVP_AES_CFB1)
                {
                    EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_LENGTH_BITS);
                }
                EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
            }

            tc->pt_len = tc->ct_len;
        }
        else
        {
            printf("Unsupported direction\n");
            rv = 1;
            goto err;
        }
        EVP_CIPHER_CTX_free(cipher_ctx);
        glb_cipher_ctx = NULL;
    }
    return rv;
err:
    if (glb_cipher_ctx)
        EVP_CIPHER_CTX_free(glb_cipher_ctx);
    glb_cipher_ctx = NULL;
    return rv;
}

/* NOTE - openssl does not support inverse option */
int app_aes_keywrap_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_SYM_CIPHER_TC *tc;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    const EVP_CIPHER *cipher;
    int c_len;
    int rc = 1;
    ACVP_SUB_AES alg;

    if (!test_case)
    {
        return rc;
    }

    tc = test_case->tc.symmetric;

    if (tc->kwcipher != ACVP_SYM_KW_CIPHER)
    {
        printf("Invalid cipher for AES keywrap operation\n");
        return rc;
    }

    /* Begin encrypt code section */
    cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(cipher_ctx);

    alg = acvp_get_aes_alg(tc->cipher);
    if (alg == 0)
    {
        printf("Invalid cipher value");
        return 1;
    }

    switch (alg)
    {
    case ACVP_SUB_AES_KW:
    case ACVP_SUB_AES_KWP:
        switch (tc->key_len)
        {
        case 128:
            cipher = EVP_aes_128_wrap();
            break;
        case 192:
            cipher = EVP_aes_192_wrap();
            break;
        case 256:
            cipher = EVP_aes_256_wrap();
            break;
        default:
            printf("Unsupported AES keywrap key length\n");
            goto end;
        }
        break;
    case ACVP_SUB_AES_GCM:
    case ACVP_SUB_AES_GCM_SIV:
    case ACVP_SUB_AES_CCM:
    case ACVP_SUB_AES_ECB:
    case ACVP_SUB_AES_CBC:
    case ACVP_SUB_AES_CBC_CS1:
    case ACVP_SUB_AES_CBC_CS2:
    case ACVP_SUB_AES_CBC_CS3:
    case ACVP_SUB_AES_CFB1:
    case ACVP_SUB_AES_CFB8:
    case ACVP_SUB_AES_CFB128:
    case ACVP_SUB_AES_OFB:
    case ACVP_SUB_AES_CTR:
    case ACVP_SUB_AES_XTS:
    case ACVP_SUB_AES_XPN:
    case ACVP_SUB_AES_GMAC:
    default:
        printf("Error: Unsupported AES keywrap mode requested by ACVP server\n");
        goto end;
    }

    if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
    {
        EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, NULL, 1);
        c_len = EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
        if (c_len <= 0)
        {
            goto end;
        }
        else
        {
            tc->ct_len = c_len;
        }
    }
    else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT)
    {
        EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, NULL, 0);

#ifdef OPENSSL_KWP
        if (tc->cipher == ACVP_AES_KWP)
        {
            EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPHER_CTX_FLAG_UNWRAP_WITHPAD);
        }
#endif
        c_len = EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
        if (c_len <= 0)
        {
            goto end;
        }
        else
        {
            tc->pt_len = c_len;
        }
    }
    else
    {
        printf("Unsupported direction\n");
        goto end;
    }
    rc = 0;

end:
    /* Cleanup */
    if (cipher_ctx)
        EVP_CIPHER_CTX_free(cipher_ctx);

    return rc;
}

/*
 * This fuction is invoked by libacvp when an AES crypto
 * operation is needed from the crypto module being
 * validated.  This is a callback provided to libacvp when
 * acvp_enable_capability() is invoked to register the
 * AES-GCM capabilitiy with libacvp.  libacvp will in turn
 * invoke this function when it needs to process an AES-GCM
 * test case.
 */
int app_aes_handler_aead(ACVP_TEST_CASE *test_case)
{
    ACVP_SYM_CIPHER_TC *tc;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    const EVP_CIPHER *cipher;
    unsigned char iv_fixed[4] = {1, 2, 3, 4};
    int rc = 0;
    int ret = 0;
    ACVP_SUB_AES alg;

    if (!test_case)
    {
        return 1;
    }

    tc = test_case->tc.symmetric;

    if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT && tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT)
    {
        printf("Unsupported direction\n");
        return 1;
    }

    /* Begin encrypt code section */
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx)
    {
        printf("Error initializing cipher CTX\n");
        rc = 1;
        goto end;
    }
    EVP_CIPHER_CTX_init(cipher_ctx);

    /* Validate key length and assign OpenSSL EVP cipher */
    alg = acvp_get_aes_alg(tc->cipher);
    if (alg == 0)
    {
        printf("Invalid cipher value");
        return 1;
    }

    switch (alg)
    {
    case ACVP_SUB_AES_GMAC:
    case ACVP_SUB_AES_GCM:
        if (tc->cipher == ACVP_AES_GMAC && (tc->pt_len || tc->ct_len ||
                                            strnlen_s((const char *)tc->ct, 1) || strnlen_s((const char *)tc->pt, 1)))
        {
            printf("Invalid AES-GMAC ct/pt data\n");
            rc = 1;
            goto end;
        }
        switch (tc->key_len)
        {
        case 128:
<<<<<<< HEAD
            //cipherAlgo = AES_CIPHER_ALGO;
            cipher = EVP_aes_128_gcm();
            break;
        case 192:
            //cipherAlgo = AES_CIPHER_ALGO;
            cipher = EVP_aes_192_gcm();
            break;
        case 256:
            //cipherAlgo = AES_CIPHER_ALGO;
=======
            cipher = EVP_aes_128_gcm();
            break;
        case 192:
            cipher = EVP_aes_192_gcm();
            break;
        case 256:
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0
            cipher = EVP_aes_256_gcm();
            break;
        default:
            printf("Unsupported AES-GCM key length\n");
            rc = 1;
            goto end;
        }
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
        {
<<<<<<< HEAD
#if 1
=======
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0
            EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_NON_FIPS_ALLOW);
            EVP_CipherInit(cipher_ctx, cipher, NULL, NULL, 1);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CipherInit(cipher_ctx, NULL, tc->key, NULL, 1);

            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED, 4, iv_fixed);
            if (!EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_IV_GEN, tc->iv_len, tc->iv))
            {
                printf("acvp_aes_encrypt: iv gen error\n");
                rc = 1;
                goto end;
            }
            if (tc->aad_len)
            {
                EVP_Cipher(cipher_ctx, NULL, tc->aad, tc->aad_len);
            }
            if (tc->cipher != ACVP_AES_GMAC)
            {
                EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            }
            EVP_Cipher(cipher_ctx, NULL, NULL, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, tc->tag_len, tc->tag);
<<<<<<< HEAD
#endif
            /* //dumpGcmTestVector(tc);
            cyclone_error = gcmInit(&gcmContext,AES_CIPHER_ALGO,&cipherContext);
            if (cyclone_error)
            {
                printf("ERROR (%d): gcmInit Failed.\n", cyclone_error);
                goto end;
            }

            cyclone_error = gcmEncrypt(&gcmContext,tc->iv,tc->iv_len,tc->aad,tc->aad_len,tc->pt,tc->ct,tc->pt_len / 8,tc->tag,tc->tag_len);

            if (cyclone_error)
            {
                printf("ERROR (%d): gcmEncrypt Failed.\n", cyclone_error);
                goto end;
            } */
        }
        else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT)
        {
#if 1
=======
        }
        else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT)
        {
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0
            EVP_CIPHER_CTX_set_flags(cipher_ctx, EVP_CIPH_FLAG_NON_FIPS_ALLOW);
            EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, NULL, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, tc->iv);
            if (!EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_IV_GEN, tc->iv_len, tc->iv))
            {
                printf("\nFailed to set IV");
                rc = 1;
                goto end;
            }
            if (tc->aad_len)
            {
                /*
                 * Set dummy tag before processing AAD.  Otherwise the AAD can
                 * not be processed.
                 */
                EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, tc->tag_len, tc->tag);
                EVP_Cipher(cipher_ctx, NULL, tc->aad, tc->aad_len);
            }
            /*
             * Set the tag when decrypting
             */
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, tc->tag_len, tc->tag);

            /*
             * Decrypt the CT
             */
            if (tc->cipher != ACVP_AES_GMAC)
            {
                EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
            }
            /*
             * Check the tag
             */
            ret = EVP_Cipher(cipher_ctx, NULL, NULL, 0);
            if (ret)
            {
                rc = 1;
                goto end;
            }
<<<<<<< HEAD
#endif
            /* cyclone_error = gcmInit(&gcmContext,AES_CIPHER_ALGO,&cipherContext);
            if (cyclone_error)
            {
                printf("ERROR (%d): gcmInit Failed\n", cyclone_error);
                goto end;
            }

            cyclone_error = gcmDecrypt(&gcmContext,tc->iv,tc->iv_len / 8,tc->aad,tc->aad_len / 8,tc->ct,tc->pt,tc->ct_len / 8,tc->tag,tc->tag_len / 8);

            if (cyclone_error)
            {
                printf("ERROR (%d): gcmDecrypt Failed\n", cyclone_error);
                goto end;
            } */
=======
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0
        }
        break;
    case ACVP_SUB_AES_CCM:
        switch (tc->key_len)
        {
        case 128:
            cipher = EVP_aes_128_ccm();
            break;
        case 192:
            cipher = EVP_aes_192_ccm();
            break;
        case 256:
            cipher = EVP_aes_256_ccm();
            break;
        default:
            printf("Unsupported AES-CCM key length\n");
            rc = 1;
            goto end;
        }
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
        {
            EVP_CipherInit(cipher_ctx, cipher, NULL, NULL, 1);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_SET_TAG, tc->tag_len, 0);
            EVP_CipherInit(cipher_ctx, NULL, tc->key, tc->iv, 1);
            EVP_Cipher(cipher_ctx, NULL, NULL, tc->pt_len);
            EVP_Cipher(cipher_ctx, NULL, tc->aad, tc->aad_len);
            ret = EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
            if (ret < 0)
            {
                printf("Error performing encrypt operation CCM\n");
                rc = 1;
                goto end;
            }
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_GET_TAG, tc->tag_len, tc->ct + tc->ct_len);
            tc->ct_len += tc->tag_len;
        }
        else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT)
        {
            EVP_CipherInit(cipher_ctx, cipher, NULL, NULL, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_SET_IVLEN, tc->iv_len, 0);
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_CCM_SET_TAG, tc->tag_len, tc->ct + tc->pt_len);
            EVP_CipherInit(cipher_ctx, NULL, tc->key, tc->iv, 0);
            EVP_Cipher(cipher_ctx, NULL, NULL, tc->pt_len);
            EVP_Cipher(cipher_ctx, NULL, tc->aad, tc->aad_len);
            /*
             * Decrypt and check the tag
             */
            ret = EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
            if (ret < 0)
            {
                rc = 1;
                goto end;
            }
        }
        break;
    case ACVP_SUB_AES_GCM_SIV:
    case ACVP_SUB_AES_ECB:
    case ACVP_SUB_AES_CBC:
<<<<<<< HEAD
        // Modified version (to add CycloneCRYPTO)
        switch (tc->key_len)
        {
        case 128:
            cipherAlgo = AES_CIPHER_ALGO;
            break;
        case 192:
            cipherAlgo = AES_CIPHER_ALGO;
            break;
        case 256:
            cipherAlgo = AES_CIPHER_ALGO;
            break;
        default:
            printf("Unsupported AES-CBC key length\n");
            rc = 1;
            goto end;
        }
        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
        {

            cyclone_error = cipherAlgo->init(&cipherContext, tc->key, tc->key_len);
            if (cyclone_error)
            {
                printf("Error initializing CipherAlgo.\n");
                rc = 1;
                goto end;
            }

            cyclone_error = cbcEncrypt(cipherAlgo, &cipherContext, tc->iv, tc->pt, tc->ct, tc->pt_len);
            if (cyclone_error)
            {
                printf("ERROR (%d): cbcEncrypt Failed\n", cyclone_error);
                rc = 1;
                goto end;
            }
        }
        else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT)
        {

            cyclone_error = cipherAlgo->init(&cipherContext, tc->key, tc->key_len / 8);
            if (cyclone_error)
            {
                printf("Error initializing CipherAlgo.\n");
                rc = 1;
                goto end;
            }

            if (tc->ct_len != 16)
            {
                printf("%d\n", tc->ct_len);
            }
            cyclone_error = cbcDecrypt(cipherAlgo, &cipherContext, tc->iv, tc->ct, tc->pt, (tc->ct_len/8));

            if (cyclone_error)
            {
                printf("ERROR (%d): cbcDecrypt Failed\n", cyclone_error);
                rc = 1;
                goto end;
            }
        }
        break;
=======
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0
    case ACVP_SUB_AES_CFB1:
    case ACVP_SUB_AES_CFB8:
    case ACVP_SUB_AES_CFB128:
    case ACVP_SUB_AES_OFB:
    case ACVP_SUB_AES_CTR:
    case ACVP_SUB_AES_XTS:
    case ACVP_SUB_AES_KW:
    case ACVP_SUB_AES_KWP:
    case ACVP_SUB_AES_XPN:
    case ACVP_SUB_AES_CBC_CS1:
    case ACVP_SUB_AES_CBC_CS2:
    case ACVP_SUB_AES_CBC_CS3:
    default:
        printf("Error: Unsupported AES AEAD mode requested by ACVP server\n");
        rc = 1;
        goto end;
    }

end:
    /* Cleanup */
    if (cipher_ctx)
        EVP_CIPHER_CTX_free(cipher_ctx);

    return rc;
}
<<<<<<< HEAD


// Helper functions
void dumpCbcTestVector(ACVP_SYM_CIPHER_TC *tc) {
    if(tc->key) {
        printf("KEY: ");
        for (int i = 0; i < tc->key_len; i++ )
        {
            printf("%02X ", tc->key[i]);
        }
        printf("\n");
        printf("KEY LEN: %d\n",tc->key_len);
    }
    
    if(tc->iv_len) {
        printf("IV: ");
        for (int i = 0; i < tc->iv_len; i++ )
        {
            printf("%02X ", tc->iv[i]);
        }
        printf("\n");
        printf("IV LEN: %d\n",tc->iv_len);
    }

    if(tc->ct_len) {
        printf("CT: ");
        for (int i = 0; i < tc->ct_len; i++ )
        {
            printf("%02X ", tc->ct[i]);
        }
        printf("\n");
        printf("CT LEN: %d\n",tc->ct_len);
    }
    if(tc->pt_len) {
        printf("PT: ");
        for (int i = 0; i < tc->pt_len; i++ )   
        {
            printf("%02X ", tc->pt[i]);
        }
        printf("\n");
        printf("PT LEN: %d\n",tc->pt_len);
    }

}

void dumpGcmTestVector(ACVP_SYM_CIPHER_TC *tc) {
    if(tc->iv_len) {
        printf("IV: ");
        for (int i = 0; i < tc->iv_len; i++ )
        {
            printf("%02X ", tc->iv[i]);
        }
        printf("\n");
        printf("IV LEN: %d\n",tc->iv_len);
    }

    if(tc->aad_len) {
        printf("AAD: ");
        for (int i = 0; i < tc->aad_len; i++ )
        {
            printf("%02X ", tc->aad[i]);
        }
        printf("\n");
        printf("AAD LEN: %d\n",tc->aad_len);
    }
    
    if(tc->ct_len) {
        printf("CT: ");
        for (int i = 0; i < tc->ct_len; i++ )
        {
            printf("%02X ", tc->ct[i]);
        }
        printf("\n");
        printf("CT LEN: %d\n",tc->ct_len);
    }
    if(tc->pt_len) {
        printf("PT: ");
        for (int i = 0; i < tc->pt_len; i++ )   
        {
            printf("%02X ", tc->pt[i]);
        }
        printf("\n");
        printf("PT LEN: %d\n",tc->pt_len);
    }
    if(tc->tag_len) {
        printf("TAG: ");
        for (int i = 0; i < tc->tag_len; i++ )
        {
            printf("%02X ", tc->tag[i]);
        }
        printf("\n");
        printf("TAG LEN: %d\n",tc->tag_len);
    }

}
=======
>>>>>>> 31d004f657c94ce6ea6d1b0892a180666b752be0
