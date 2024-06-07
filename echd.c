
// #########################################################################################################
// Refrenced ECDH demos in the standard download of openssl in consturction of functions
// ########################################################################################################

# include "header.h" // Include neccecary openssl libraries

// Struct object used to store information for a single Peer
typedef struct peer_data_st {
    const char *name;               /* name of peer */
    const char *curvename;          /* The shared curve name */
    EVP_PKEY *priv;                 /* private keypair */
    EVP_PKEY *pub;                  /* public key to send to other peer */
    unsigned char *secret;          /* allocated shared secret buffer */
    size_t secretlen;
} PEER_DATA;


 // The public key needs to be given to the other peer
 //The following function gets the public key from the private key and then builds an openssl EVP_KEY public key.

static int get_peer_public_key(PEER_DATA *peer, OSSL_LIB_CTX *libctx)
{
    // Variables
    int ret = 0;
    EVP_PKEY_CTX *ctx;
    OSSL_PARAM params[3];
    unsigned char pubkeydata[256];
    size_t pubkeylen;

    /* Gets the EC encoded public key data from the peers private key */
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

// This function uses peer dadta and generates a new key pair for ECC
static int create_peer(PEER_DATA *peer, OSSL_LIB_CTX *libctx)
{
    // Variables
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    // Parameter set
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)peer->curvename, 0);
    params[1] = OSSL_PARAM_construct_end();

    // ECC key generation happens here!
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
