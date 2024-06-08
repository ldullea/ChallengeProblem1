
// #########################################################################################################
// Refrenced ECDH demos in the standard download of openssl in consturction of functions
// #########################################################################################################

// #########################################################################################################
// Using Eliptic Curve Diffie-Helmen for Asymetric Key generation (low key size, efficient)
// #########################################################################################################

// This file has functions to retreive a peer's public key, generate a new key pair, generate a shared secret, and destroy keys.

# include "header.h" // Include neccecary openssl libraries

// Struct object used to store information for a single Peer
typedef struct peer_data_st 
{
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

// This function uses peer data and generates a new key pair for ECC
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
    int num_bytes = 256; //define number of bytes to be used
    unsigned int rnum = 0;

    // initialize openssl rand buffer
    unsigned char buffer[num_bytes];

    // Generate random bytes
    RAND_bytes(buffer, num_bytes);

    // check RAND status
    if (RAND_status() != 1) {
        return -1; // fail
    }

    // Convert the random bytes to an integer
    for (int i = 0; i < num_bytes; ++i) 
    {
       rnum = (rnum << 8) | buffer[i];
    }
    printf("Code got here");
    printf("Random num: %u", rnum);
    printf("\n");

}

int main ()
{
    //Initialize a return value
    int ret_val = 1;

    unsigned int rnum = gen_random();

    // Initialise the 2 peers
    PEER_DATA peer1 = {"peer 1", "P-256"};
    PEER_DATA peer2 = {"peer 2", "P-256"};

    // setting libctx to null makes the library use default contex
    OSSL_LIB_CTX *libctx = NULL;

    // Each peer creates a keypair
    if (!create_peer(&peer1, libctx) || !create_peer(&peer2, libctx)) 
    {
        fprintf(stderr, "Create peer failed\n");
        goto cleanup;
    }

    if (!generate_secret(&peer1, peer2.pub, libctx) || !generate_secret(&peer2, peer1.pub, libctx)) 
    {
        fprintf(stderr, "Generate secrets failed\n");
        goto cleanup;
    }

    // or illustrative purposes demonstrate that the derived secrets are equal 
    if (peer1.secretlen != peer2.secretlen || CRYPTO_memcmp(peer1.secret, peer2.secret, peer1.secretlen) != 0) 
    {
        fprintf(stderr, "Derived secrets do not match\n");
        goto cleanup;
    } 
    else {
        fprintf(stdout, "Derived secrets match\n");
    }

    // Passed all tests, update return value
    ret_val = 0;

    cleanup:
    if (ret_val != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);
    destroy_peer(&peer2);
    destroy_peer(&peer1);
    return ret_val;
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