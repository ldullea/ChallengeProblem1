#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/decoder.h>
#include <openssl/core_names.h>

/* AES-GCM test data obtained from NIST public test vectors */

/* AES key */
static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

/* Unique initialisation vector */
static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

/* Example plaintext to encrypt */
static unsigned char gcm_pt[] = {
    "Hi how are you"
};

static unsigned char key[] = {
    0x25, 0xfd, 0x12, 0x99, 0xdf, 0xad, 0x1a, 0x03,
    0x0a, 0x81, 0x3c, 0x2d, 0xcc, 0x05, 0xd1, 0x5c,
    0x17, 0x7a, 0x36, 0x73, 0x17, 0xef, 0x41, 0x75,
    0x71, 0x18, 0xe0, 0x1a, 0xda, 0x99, 0xc3, 0x61,
    0x38, 0xb5, 0xb1, 0xe0, 0x82, 0x2c, 0x70, 0xa4,
    0xc0, 0x8e, 0x5e, 0xf9, 0x93, 0x9f, 0xcf, 0xf7,
    0x32, 0x4d, 0x0c, 0xbd, 0x31, 0x12, 0x0f, 0x9a,
    0x15, 0xee, 0x82, 0xdb, 0x8d, 0x29, 0x54, 0x14,
};

typedef struct peer_data_st {
    const char *name;               /* name of peer */
    const char *curvename;          /* The shared curve name */
    EVP_PKEY *priv;                 /* private keypair */
    EVP_PKEY *pub;                  /* public key to send to other peer */
    unsigned char *secret;          /* allocated shared secret buffer */
    size_t secretlen;
} PEER_DATA;


static const char *hamlet=
    "To be, or not to be, that is the question,\n"
    "Whether tis nobler in the minde to suffer\n"
    "The slings and arrowes of outragious fortune,\n"
    "Or to take Armes again in a sea of troubles,\n"
;



/////////////////////////////////////////////////////////////////////////////////////


static OSSL_LIB_CTX *libctx = NULL;
static const char *propq = NULL;
static unsigned char Coutbuf[2048];
static unsigned char Poutbuf[2048];

static int aes_gcm_encrypt(int n)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int outlen;
    size_t gcm_ivlen = sizeof(gcm_iv);
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "AES-256-GCM", propq)) == NULL)
        goto err;

    /* Set IV length if default 96 bits is not appropriate */
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &gcm_ivlen);

    if (!EVP_EncryptInit_ex2(ctx, cipher, gcm_key, gcm_iv, params))
        goto err;

    /* Encrypt plaintext */
    if (!EVP_EncryptUpdate(ctx, Coutbuf, &outlen, Poutbuf, n))
        goto err;


    ret = 1;
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

static int decrypt(int n)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int outlen;
    size_t gcm_ivlen = sizeof(gcm_iv);
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "AES-256-GCM", propq)) == NULL)
        goto err;

    /* Set IV length if default 96 bits is not appropriate */
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &gcm_ivlen);

    if (!EVP_DecryptInit_ex2(ctx, cipher, gcm_key, gcm_iv, params))
        goto err;


    /* Decrypt plaintext */
    if (!EVP_DecryptUpdate(ctx, Poutbuf, &outlen, Coutbuf, n))
        goto err;

    if (!EVP_CIPHER_CTX_set_params(ctx, params))
        goto err;


    ret = 1;
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}


int encrypt(char* Buffer, int n){
    for (int i = 0; i < n; ++i) {
            Coutbuf[i] = Buffer[i];
        }
    aes_gcm_encrypt(n);
    return 0;
}



int MAC(int MODE, int n)
{
    int ret = EXIT_FAILURE;
    OSSL_LIB_CTX *library_context = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    EVP_MD_CTX *digest_context = NULL;
    unsigned char *out = NULL;
    size_t out_len = 0;
    OSSL_PARAM params[4], *p = params;
    char digest_name[] = "SHA3-512";

    library_context = OSSL_LIB_CTX_new();
    if (library_context == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        goto end;
    }

    /* Fetch the HMAC implementation */
    mac = EVP_MAC_fetch(library_context, "HMAC", propq);
    if (mac == NULL) {
        fprintf(stderr, "EVP_MAC_fetch() returned NULL\n");
        goto end;
    }

    /* Create a context for the HMAC operation */
    mctx = EVP_MAC_CTX_new(mac);
    if (mctx == NULL) {
        fprintf(stderr, "EVP_MAC_CTX_new() returned NULL\n");
        goto end;
    }

    /* The underlying digest to be used */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name,
                                            sizeof(digest_name));
    *p = OSSL_PARAM_construct_end();

    /* Initialise the HMAC operation */
    if (!EVP_MAC_init(mctx, key, sizeof(key), params)) {
        fprintf(stderr, "EVP_MAC_init() failed\n");
        goto end;
    }
    if(MODE == 1){
        /* Make one or more calls to process the data to be authenticated */
        if (!EVP_MAC_update(mctx, gcm_pt, sizeof(gcm_pt))) {
            fprintf(stderr, "EVP_MAC_update() failed\n");
            goto end;
        }
    }else{
        if (!EVP_MAC_update(mctx, Poutbuf, n)) {
            fprintf(stderr, "EVP_MAC_update() failed\n");
            goto end;
        }
    }

    /* Make a call to the final with a NULL buffer to get the length of the MAC */
    if (!EVP_MAC_final(mctx, NULL, &out_len, 0)) {
        fprintf(stderr, "EVP_MAC_final() failed\n");
        goto end;
    }
    out = OPENSSL_malloc(out_len);
    if (out == NULL) {
        fprintf(stderr, "malloc failed\n");
        goto end;
    }
    /* Make one call to the final to get the MAC */
    if (!EVP_MAC_final(mctx, out, &out_len, out_len)) {
        fprintf(stderr, "EVP_MAC_final() failed\n");
        goto end;
    }

    printf("Generated MAC:\n");
    BIO_dump_indent_fp(stdout, out, out_len, 2);
    putchar('\n');

    ret = EXIT_SUCCESS;
end:
    if (ret != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);
    /* OpenSSL free functions will ignore NULL arguments */
    OPENSSL_free(out);
    EVP_MD_CTX_free(digest_context);
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    OSSL_LIB_CTX_free(library_context);
    return ret;
}

static int get_key_values(EVP_PKEY *pkey);

static EVP_PKEY *do_ec_keygen(void)
{
    /*
     * The libctx and propq can be set if required, they are included here
     * to show how they are passed to EVP_PKEY_CTX_new_from_name().
     */
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[3];
    EVP_PKEY_CTX *genctx = NULL;
    const char *curvename = "P-256";
    int use_cofactordh = 1;

    genctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);
    if (genctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name() failed\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(genctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init() failed\n");
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)curvename, 0);
    /*
     * This is an optional parameter.
     * For many curves where the cofactor is 1, setting this has no effect.
     */
    params[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                         &use_cofactordh);
    params[2] = OSSL_PARAM_construct_end();
    if (!EVP_PKEY_CTX_set_params(genctx, params)) {
        fprintf(stderr, "EVP_PKEY_CTX_set_params() failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Generating EC key\n\n");
    if (EVP_PKEY_generate(genctx, &key) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate() failed\n");
        goto cleanup;
    }
cleanup:
    EVP_PKEY_CTX_free(genctx);
    return key;
}


static unsigned char out_pubkey[200];
static unsigned char out_privkey[200];
static size_t out_pubkey_len, out_privkey_len = 0;

static int get_key_values(EVP_PKEY *pkey)
{
    int ret = 0;
    char out_curvename[80];
    BIGNUM *out_priv = NULL;

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        out_curvename, sizeof(out_curvename),
                                        NULL)) {
        fprintf(stderr, "Failed to get curve name\n");
        goto cleanup;
    }

    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        out_pubkey, sizeof(out_pubkey),
                                        &out_pubkey_len)) {
        fprintf(stderr, "Failed to get public key\n");
        goto cleanup;
    }

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &out_priv)) {
        fprintf(stderr, "Failed to get private key\n");
        goto cleanup;
    }

    out_privkey_len = BN_bn2bin(out_priv, out_privkey);
    if (out_privkey_len <= 0 || out_privkey_len > sizeof(out_privkey)) {
        fprintf(stderr, "BN_bn2bin failed\n");
        goto cleanup;
    }

    ret = 1;
cleanup:
    /* Zeroize the private key data when we free it */
    BN_clear_free(out_priv);
    return ret;
}

static int demo_verify(OSSL_LIB_CTX *libctx, const char *sig_name,
                       size_t sig_len, unsigned char *sig_value, EVP_PKEY *pkey)
{
    int ret = 0, public = 1;
    const char *propq = NULL;
    EVP_MD_CTX *verify_context = NULL;
    EVP_PKEY *pub_key = NULL;

    /*
     * Make a verify signature context to hold temporary state
     * during signature verification
     */
    verify_context = EVP_MD_CTX_new();
    if (verify_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }
    /* Get public key */
    /* Verify */
    if (!EVP_DigestVerifyInit_ex(verify_context, NULL, sig_name,
                                libctx, NULL, pkey, NULL)) {
        fprintf(stderr, "EVP_DigestVerifyInit failed.\n");
        goto cleanup;
    }
    /*
     * EVP_DigestVerifyUpdate() can be called several times on the same context
     * to include additional data.
     */
    if (!EVP_DigestVerifyUpdate(verify_context, Poutbuf, strlen(Poutbuf))) {
        fprintf(stderr, "EVP_DigestVerifyUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }
    if (!EVP_DigestVerifyUpdate(verify_context, Coutbuf, strlen(Coutbuf))) {
        fprintf(stderr, "EVP_DigestVerifyUpdate(hamlet_2) failed.\n");
        goto cleanup;
    }
    if (EVP_DigestVerifyFinal(verify_context, sig_value, sig_len) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyFinal failed.\n");
        goto cleanup;
    }
    fprintf(stdout, "Signature verified.\n");
    ret = 1;

cleanup:
    /* OpenSSL free functions will ignore NULL arguments */
    EVP_PKEY_free(pub_key);
    EVP_MD_CTX_free(verify_context);
    return ret;
}

static int demo_sign(OSSL_LIB_CTX *libctx,  const char *sig_name,
                     size_t *sig_out_len, unsigned char **sig_out_value, EVP_PKEY *pkey)
{
    int ret = 0, public = 0;
    size_t sig_len;
    unsigned char *sig_value = NULL;
    const char *propq = NULL;
    EVP_MD_CTX *sign_context = NULL;
    /*
     * Make a message signature context to hold temporary state
     * during signature creation
     */
    sign_context = EVP_MD_CTX_new();
    if (sign_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }
    /*
     * Initialize the sign context to use the fetched
     * sign provider.
     */
    if (!EVP_DigestSignInit_ex(sign_context, NULL, sig_name,
                              libctx, NULL, pkey, NULL)) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed.\n");
        goto cleanup;
    }
    /*
     * EVP_DigestSignUpdate() can be called several times on the same context
     * to include additional data.
     */
    if (!EVP_DigestSignUpdate(sign_context, Poutbuf, strlen(Poutbuf))) {
        fprintf(stderr, "EVP_DigestSignUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }
    if (!EVP_DigestSignUpdate(sign_context, Coutbuf, strlen(Coutbuf))) {
        fprintf(stderr, "EVP_DigestSignUpdate(hamlet_2) failed.\n");
        goto cleanup;
    }
    /* Call EVP_DigestSignFinal to get signature length sig_len */
    if (!EVP_DigestSignFinal(sign_context, NULL, &sig_len)) {
        fprintf(stderr, "EVP_DigestSignFinal failed.\n");
        goto cleanup;
    }
    if (sig_len <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal returned invalid signature length.\n");
        goto cleanup;
    }
    sig_value = OPENSSL_malloc(sig_len);
    if (sig_value == NULL) {
        fprintf(stderr, "No memory.\n");
        goto cleanup;
    }
    if (!EVP_DigestSignFinal(sign_context, sig_value, &sig_len)) {
        fprintf(stderr, "EVP_DigestSignFinal failed.\n");
        goto cleanup;
    }
    *sig_out_len = sig_len;
    *sig_out_value = sig_value;
    fprintf(stdout, "Generating signature:\n");
    BIO_dump_indent_fp(stdout, sig_value, sig_len, 2);
    fprintf(stdout, "\n");
    ret = 1;

cleanup:
    /* OpenSSL free functions will ignore NULL arguments */
    if (!ret)
        OPENSSL_free(sig_value);
    EVP_MD_CTX_free(sign_context);
    return ret;
}

static int get_peer_public_key(PEER_DATA *peer, OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx;
    OSSL_PARAM params[3];
    unsigned char pubkeydata[256];
    size_t pubkeylen;

    /* Get the EC encoded public key data from the peers private key */
    if (!EVP_PKEY_get_octet_string_param(peer->priv, OSSL_PKEY_PARAM_PUB_KEY,
                                         pubkeydata, sizeof(pubkeydata),
                                         &pubkeylen))
        return 0;

    /* Create a EC public key from the public key data */
    ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    if (ctx == NULL)
        return 0;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)peer->curvename, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  pubkeydata, pubkeylen);
    params[2] = OSSL_PARAM_construct_end();
    ret = EVP_PKEY_fromdata_init(ctx) > 0
          && (EVP_PKEY_fromdata(ctx, &peer->pub, EVP_PKEY_PUBLIC_KEY,
                                params) > 0);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int create_peer(PEER_DATA *peer, OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)peer->curvename, 0);
    params[1] = OSSL_PARAM_construct_end();

    ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    if (ctx == NULL)
        return 0;

    if (EVP_PKEY_keygen_init(ctx) <= 0
            || !EVP_PKEY_CTX_set_params(ctx, params)
            || EVP_PKEY_generate(ctx, &peer->priv) <= 0
            || !get_peer_public_key(peer, libctx)) {
        EVP_PKEY_free(peer->priv);
        peer->priv = NULL;
        goto err;
    }
    ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static void destroy_peer(PEER_DATA *peer)
{
    EVP_PKEY_free(peer->priv);
    EVP_PKEY_free(peer->pub);
}

static int generate_secret(PEER_DATA *peerA, EVP_PKEY *peerBpub,
                           OSSL_LIB_CTX *libctx)
{
    unsigned char *secret = NULL;
    size_t secretlen = 0;
    EVP_PKEY_CTX *derivectx;

    /* Create an EVP_PKEY_CTX that contains peerA's private key */
    derivectx = EVP_PKEY_CTX_new_from_pkey(libctx, peerA->priv, NULL);
    if (derivectx == NULL)
        return 0;

    if (EVP_PKEY_derive_init(derivectx) <= 0)
        goto cleanup;
    /* Set up peerB's public key */
    if (EVP_PKEY_derive_set_peer(derivectx, peerBpub) <= 0)
        goto cleanup;

    /* Calculate the size of the secret and allocate space */
    if (EVP_PKEY_derive(derivectx, NULL, &secretlen) <= 0)
        goto cleanup;
    secret = (unsigned char *)OPENSSL_malloc(secretlen);
    if (secret == NULL)
        goto cleanup;

    /*
     * Derive the shared secret. In this example 32 bytes are generated.
     * For EC curves the secret size is related to the degree of the curve
     * which is 256 bits for P-256.
     */
    if (EVP_PKEY_derive(derivectx, secret, &secretlen) <= 0)
        goto cleanup;
    peerA->secret = secret;
    peerA->secretlen = secretlen;

    printf("Shared secret (%s):\n", peerA->name);
    BIO_dump_indent_fp(stdout, peerA->secret, peerA->secretlen, 2);
    putchar('\n');

    return 1;
cleanup:
    OPENSSL_free(secret);
    EVP_PKEY_CTX_free(derivectx);
    return 0;
}


int main() {
    OSSL_LIB_CTX *libctx = NULL;
    const char *sig_name = "SHA3-512";
    size_t sig_len = 0;
    unsigned char *sig_value = NULL;
    libctx = OSSL_LIB_CTX_new();
    const char *curvename = "P-256";
    EVP_PKEY *pkey;
    BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);

    printf("Input message for symmetric encryption (max 2048 characters)\n");
    int max_length = 2048;
    char str[max_length];
    fgets(str, max_length, stdin);

    // BEGIN SYMMETRIC ENCRYPTION

    char* TextBuffer;
    int n = strlen(str);
    TextBuffer = (char*)malloc(n * sizeof(char));

    for (int i = 0; i < n; ++i) {
            Poutbuf[i] = str[i];
            TextBuffer[i] = str[i];
        }

    // Encryption and outputting ciphertext


    printf("SYMMETRIC ENCRYPTION\n");

    printf("Plaintext: \n");
    for(int i; i<sizeof(Poutbuf); i++){
        printf("%c", Poutbuf[i]);
    }

    encrypt(TextBuffer, n);
    printf("ciphertext: \n");
    for(int i; i<sizeof(Coutbuf); i++){
        printf("%c", Coutbuf[i]);  
    }
    printf("\n");

    // Decryption and outputting plaintext
    decrypt(n);
    printf("Plaintext: \n");
    for(int i; i<sizeof(Poutbuf); i++){
        printf("%c", Poutbuf[i]);
    }
    printf("\n\n");

    // BEGIN MAC

    printf("HMAC after Encryption (on both original plaintext buffer and post encryption buffer: \n");
    MAC(1, n);
    MAC(0, n);
    
    // BEGIN ECDH

    printf("\n\n Elliptic Curve Diffie Hellman key exchange\n\n");

    PEER_DATA peer1 = {"peer 1", "P-256"};
    PEER_DATA peer2 = {"peer 2", "P-256"};

    // Generate 2 peers for key sharing
    create_peer(&peer1, libctx);
    create_peer(&peer2, libctx);

    // Generate shared secret key
    generate_secret(&peer1, peer2.pub, libctx);
    generate_secret(&peer2, peer1.pub, libctx);

    // Show derived keys are equal 
    if (peer1.secretlen != peer2.secretlen
            || CRYPTO_memcmp(peer1.secret, peer2.secret, peer1.secretlen) != 0) {
        fprintf(stderr, "Derived secrets do not match\n");
    } else {
        fprintf(stdout, "Derived secrets match\n");
    }
    
    // BEGIN DIGITAL SIGNATURE 

    printf("\n Begin digital signature:\n\n");
    
    pkey = do_ec_keygen();
    get_key_values(pkey);

    // Print out public and private keypair
    fprintf(stdout, "Private Key:\n");
    BIO_dump_indent_fp(stdout, out_privkey, out_pubkey_len, 2);
    fprintf(stdout, "Public Key:\n");
    BIO_dump_indent_fp(stdout, out_pubkey, out_pubkey_len, 2);


    // PRINT OUT DIG SIG
    demo_sign(libctx, sig_name, &sig_len, &sig_value, peer1.priv);
    demo_verify(libctx, sig_name, sig_len, sig_value, peer1.pub);

    printf("\n");
    
    // Free all used blocks
    EVP_PKEY_free(pkey);
    BIO_free(bp);
    destroy_peer(&peer2);
    destroy_peer(&peer1);


    return EXIT_SUCCESS;
}