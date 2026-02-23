#ifndef RSA_UTIL_H
#define RSA_UTIL_H

#include <memory>
#include <string>
#include <openssl/evp.h>
#include <openssl/sha.h>

enum RSA_KEY { PRIVATE, PUBLIC };

using ptr_evp_pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using ptr_evp_ctx  = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using ptr_bio      = std::unique_ptr<BIO, decltype(&BIO_free)>;

std::string sha256_sum(void *raw, size_t raw_sz);

ptr_evp_pkey PEM_read_key(enum RSA_KEY type_key, const std::string &key_in);

bool RSA_sign_data(const std::string &sig_data,
                   const std::string &key_priv,
                   std::string &sig_out);

bool RSA_verify_data(const std::string &key_pub,
                     const uint8_t *raw_data,
                     int sig_data_sz,
                     const uint8_t *sig_data,
                     int sig_hash_sz);

#endif // RSA_UTIL_H
