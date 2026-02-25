#include "util.hpp"
#include "util_rsa.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>

enum RSA_KEY { PRIVATE, PUBLIC };

std::string
sha256_sum(void *raw, size_t raw_sz)
{
    uint8_t hash_raw[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, raw, raw_sz);
    EVP_DigestFinal_ex(ctx, hash_raw, &hash_len);
    EVP_MD_CTX_free(ctx);

    std::string hash_str(hash_len * 2, '\0');
    for (unsigned int i = 0; i < hash_len; ++i) {
        std::sprintf(&hash_str[i * 2], "%02hhx", hash_raw[i]);
    }
    return hash_str;
}

static std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>
PEM_read_key(RSA_KEY type_key, const std::string &key)
{
    ptr_bio bio(BIO_new_mem_buf(key.data(), key.size()), BIO_free);

    if (!bio.get()) {
        throw_err("!BIO_new_mem_buf()", "BIO mem");
    }

    EVP_PKEY *pkey = nullptr;

    if (type_key == RSA_KEY::PRIVATE) {
        pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
        if (!pkey) {
            throw_err("!PEM_read_bio_PrivateKey()", "Get Private key");
        }
    } else {
        pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
        if (!pkey) {
            throw_err("!PEM_read_bio_PUBKEY()", "Get Public key");
        }
    }

    return {pkey, EVP_PKEY_free};
}

bool
RSA_verify_data(const std::string &key_pub,
                const uint8_t *raw_data,
                int raw_data_sz,
                const uint8_t *sig_data,
                int sig_data_sz)
{
    auto pkey = PEM_read_key(RSA_KEY::PUBLIC, key_pub);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw_err("!EVP_MD_CTX_new()", "Verify");
    }

    bool result = (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey.get()) == 1 &&
                   EVP_DigestVerifyUpdate(ctx, raw_data, raw_data_sz) == 1 &&
                   EVP_DigestVerifyFinal(ctx, sig_data, sig_data_sz) == 1);

    EVP_MD_CTX_free(ctx);
    return result;
}

bool
RSA_sign_data(const std::string &sig_data,
              const std::string &key_priv,
              std::string &sig_buf)
{
    auto pkey = PEM_read_key(RSA_KEY::PRIVATE, key_priv);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw_err("!EVP_MD_CTX_new()", "Sign");
    }

    size_t sig_len = 0;
    bool result = false;

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey.get()) == 1 &&
        EVP_DigestSignUpdate(ctx, sig_data.data(), sig_data.size()) == 1 &&
        EVP_DigestSignFinal(ctx, nullptr, &sig_len) == 1) {
        sig_buf.resize(sig_len);
        if (EVP_DigestSignFinal(ctx, reinterpret_cast<uint8_t *>(sig_buf.data()), &sig_len) == 1) {
            sig_buf.resize(sig_len);
            result = true;
        }
    }

    EVP_MD_CTX_free(ctx);
    return result;
}
