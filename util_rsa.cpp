#include "util.hpp"
#include "util_rsa.hpp"
#include <openssl/pem.h>

std::string
sha256_sum(void *raw, size_t raw_sz)
{
    uint8_t hash_raw[SHA256_DIGEST_LENGTH];
    std::string hash_str(sizeof(hash_raw) * 2, '\0');

    SHA256(static_cast<uint8_t *>(raw), raw_sz, hash_raw);

    for (size_t i = 0; i < sizeof(hash_raw); ++i) {
        std::sprintf(&hash_str[i * 2], "%02hhx", hash_raw[i]);
    }
    return hash_str;
}

ptr_evp_pkey
PEM_read_key(enum RSA_KEY type_key, const std::string &key)
{
    ptr_bio bio(BIO_new_mem_buf(key.data(), key.size()), BIO_free);

    if (!bio.get()) {
        throw_err("!BIO_new_mem_buf()", "BIO mem");
    }

    EVP_PKEY *pkey = nullptr;

    if (type_key == RSA_KEY::PRIVATE) {
        pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    } else {
        pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    }

    if (!pkey) {
        if (type_key == RSA_KEY::PRIVATE) {
            throw_err("!PEM_read_bio_PrivateKey()", "Get Private key");
        } else {
            throw_err("!PEM_read_bio_PUBKEY()", "Get Public key");
        }
    }

    return ptr_evp_pkey(pkey, EVP_PKEY_free);
}

bool
RSA_verify_data(const std::string &key_pub,
                const uint8_t *raw_data,
                int raw_data_sz,
                const uint8_t *sig_data,
                int sig_data_sz)
{
    auto pkey = PEM_read_key(RSA_KEY::PUBLIC, key_pub);

    ptr_evp_ctx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx.get()) {
        throw_err("!EVP_MD_CTX_new()", "Verify context");
    }

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(),
                             nullptr, pkey.get()) != 1) {
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx.get(), raw_data, raw_data_sz) != 1) {
        return false;
    }

    if (EVP_DigestVerifyFinal(ctx.get(), sig_data, sig_data_sz) != 1) {
        return false;
    }

    return true;
}

bool
RSA_sign_data(const std::string &sig_data,
              const std::string &key_priv,
              std::string &sig_buf)
{
    auto pkey = PEM_read_key(RSA_KEY::PRIVATE, key_priv);

    ptr_evp_ctx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx.get()) {
        throw_err("!EVP_MD_CTX_new()", "Sign context");
    }

    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(),
                           nullptr, pkey.get()) != 1) {
        return false;
    }

    if (EVP_DigestSignUpdate(ctx.get(), sig_data.data(), sig_data.size()) != 1) {
        return false;
    }

    // First call with nullptr gets required buffer size
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) != 1) {
        return false;
    }

    sig_buf.resize(sig_len);

    if (EVP_DigestSignFinal(ctx.get(),
                            reinterpret_cast<uint8_t *>(sig_buf.data()),
                            &sig_len) != 1) {
        return false;
    }

    // Trim to actual signature length (may be smaller than allocated)
    sig_buf.resize(sig_len);
    return true;
}
