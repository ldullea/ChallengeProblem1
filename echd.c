
// #########################################################################################################
// Refrenced ECDH demos in the standard download of openssl in consturction of functions
// #########################################################################################################

// #########################################################################################################
// Using Eliptic Curve Diffie-Helmen for Asymetric Key generation (low key size, efficient)
// #########################################################################################################

// This file has functions to retreive a peer's public key, generate a new key pair, generate a shared secret, and destroy keys.

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
 // The following function gets the public key from the private key and then builds an openssl EVP_KEY public key. 
static int get_peer_public_key(PEER_DATA *peer, OSSL_LIB_CTX *libctx)
{
    // Variables
    int ret = 0;
    EVP_PKEY_CTX *key;
    OSSL_PARAM params[3];
    unsigned char pubkeydata[256];
    size_t pubkeylen;

    /* Gets the EC encoded public key data from the peers private key */
    if (!EVP_PKEY_get_octet_string_param(peer->priv, OSSL_PKEY_PARAM_PUB_KEY,
                                         pubkeydata, sizeof(pubkeydata),
                                         &pubkeylen))
        return 0;  //fail

    /* Create a EC public key from the public key data */
    key = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    if (key == NULL)
        return 0;


    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)peer->curvename, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pubkeydata, pubkeylen);
    params[2] = OSSL_PARAM_construct_end();


    ret = EVP_PKEY_fromdata_init(key) > 0
          && (EVP_PKEY_fromdata(key, &peer->pub, EVP_PKEY_PUBLIC_KEY, params) > 0);

    EVP_PKEY_CTX_free(key);
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

// Function to destroy free up key data
static void destroy_peer(PEER_DATA *peer)
{
    EVP_PKEY_free(peer->priv);
    EVP_PKEY_free(peer->pub);
}

// Function generates a shared secret key between peerA and peerB
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

    // Set up peerB's public key
    if (EVP_PKEY_derive_set_peer(derivectx, peerBpub) <= 0)
        goto cleanup;

    // Calculate the size of the secret and allocate space
    if (EVP_PKEY_derive(derivectx, NULL, &secretlen) <= 0)
        goto cleanup;
    secret = (unsigned char *)OPENSSL_malloc(secretlen);
    if (secret == NULL)
        goto cleanup;

    
     // Derive the shared secret. 
     // Similarly to the openssl ex, 32 bytes are generated. The degree of the EC creates the secret size (which is 256b for P-256)

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

int gen_random()
{
    int rc = 0;
    unsigned long err = 0;
 
    OPENSSL_cpuid_setup();
    ENGINE_load_rdrand();

    ENGINE* eng = ENGINE_by_id("rdrand");
    err = ERR_get_error();

    if(NULL == eng) {
        fprintf(stderr, "ENGINE_load_rdrand failed, err = 0x%lx\n", err);
        abort(); /* failed */
    }

    rc = ENGINE_init(eng);
    err = ERR_get_error();

    if(0 == rc) {
        fprintf(stderr, "ENGINE_init failed, err = 0x%lx\n", err);
        abort(); /* failed */
    }
  
    rc = ENGINE_set_default(eng, ENGINE_METHOD_RAND);
    err = ERR_get_error();

    if(0 == rc) {
        fprintf(stderr, "ENGINE_set_default failed, err = 0x%lx\n", err);
        abort(); /* failed */
    }

   /* OK to proceed */
}

int main ()
{
    int rnum = gen_random();


    return 0;
}

/*

def __create_keypair(keysize):
    keypair = RSA.generate(keysize)
    private_key = RSA.import_key(keypair.export_key())
    public_key = RSA.import_key(keypair.publickey().export_key())
    return (public_key, private_key)

def main():
    AES_key = get_random_bytes(32)

    public_key, private_key = create_keypair()
    decrypted_key = encrypt_and_decrypt_challenge(public_key, private_key, AES_key)

    if decrypted_key == AES_key:
        print("Correct RSA!")
    else:
        print("Please try again")

if __name__ == '__main__':
    main()
*/