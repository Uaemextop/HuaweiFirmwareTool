#ifndef RSA_UTIL_H
#define RSA_UTIL_H

#include <cstdint>
#include <memory>
#include <string>
#include <openssl/bio.h>

using ptr_bio = std::unique_ptr<BIO, decltype(&BIO_free)>;

std::string sha256_sum(void *raw, size_t raw_sz);

bool RSA_sign_data(const std::string &sig_data,
                   const std::string &key_priv,
                   std::string &sig_out);

bool RSA_verify_data(const std::string &key_pub,
                     const uint8_t *raw_data,
                     int raw_data_sz,
                     const uint8_t *sig_data,
                     int sig_hash_sz);

#endif // RSA_UTIL_H
