//apt install libssl-dev
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include "file.h"

#include <inttypes.h>
#include <sys/time.h>

EVP_PKEY *get_private_key(char* path)
{
    FILE    *fp = NULL; 
    char    key_path[1024];
    EVP_PKEY   *priv_key = NULL;

    memset(key_path, 0 ,sizeof(key_path));

    if(256 < strlen(path))
        strncpy(key_path, path, 256);
    else
        strncpy(key_path, path, strlen(path));

    if(NULL == (fp = fopen(key_path, "rb")))
    {
        printf( "open key error[%s]\n", key_path);
        return NULL;
    }

    if(NULL == (priv_key = PEM_read_PrivateKey(fp, NULL, NULL,NULL)))
    {
        printf( "read key error\n");
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    return priv_key;
}

#define MAX_SIGNATURE_LEN 2048

int main(void)
{
    int     ret;
    char    signature[MAX_SIGNATURE_LEN];
    size_t  sig_len;

    int     saltlen = 32;

    EVP_PKEY *priv_key = NULL;
    EVP_MD_CTX *md_ctx;
    EVP_PKEY_CTX *pkey_ctx;

    priv_key = get_private_key("rsa_priv.pem");

    memset(signature, 0, sizeof(signature));

    md_ctx = EVP_MD_CTX_create();
    EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, priv_key);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, saltlen);

    EVP_DigestSignUpdate(md_ctx, file_buf, file_len);

    EVP_DigestSignFinal(md_ctx, signature, &sig_len);

    printf("%d\n", sig_len);

    FILE *fp = fopen("file.sig","wb");
    fwrite(signature, sig_len, 1, fp);
    fclose(fp);

    return 0;
}
