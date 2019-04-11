//apt install libssl-dev
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include "file.h"


#define MAX_SIGNATURE_LEN 2048

int main(void)
{
    int     ret;
    char    signature[MAX_SIGNATURE_LEN];
    size_t  sig_len = MAX_SIGNATURE_LEN;
    FILE    *fp;

    int     saltlen = 32;

    EVP_PKEY *priv_key = NULL;
    EVP_MD_CTX *md_ctx;
    EVP_PKEY_CTX *pkey_ctx;

    fp =  fopen("rsa_priv.pem", "rb");
    priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    memset(signature, 0, sizeof(signature));

    md_ctx = EVP_MD_CTX_create();

    EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, priv_key);

    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);

    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, saltlen);

    EVP_DigestSignUpdate(md_ctx, file_buf, file_len);

    EVP_DigestSignFinal(md_ctx, signature, &sig_len);

    fp = fopen("file.sig","wb");
    fwrite(signature, sig_len, 1, fp);
    fclose(fp);

    return 0;
}
