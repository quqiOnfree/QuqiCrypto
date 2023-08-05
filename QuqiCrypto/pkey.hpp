#ifndef RSA_HPP
#define RSA_HPP

#define QUQICRYPTO_NAMESPACE_BEGIN namespace qcrypto {
#define QUQICRYPTO_NAMESPACE_END }
#define PKEY_NAMESPACE_BEGIN namespace pkey {
#define PKEY_NAMESPACE_END }

#include <string>
#include <mutex>
#include <memory>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

QUQICRYPTO_NAMESPACE_BEGIN

class PEM;

PKEY_NAMESPACE_BEGIN

class PublicKey;

class PrivateKey
{
public:
    PrivateKey() : shared_pkey_(EVP_PKEY_new(), [](EVP_PKEY* pkey) {EVP_PKEY_free(pkey); }) {}
    PrivateKey(const PrivateKey& p)
    {
        shared_pkey_ = p.shared_pkey_;
    }
    PrivateKey(PrivateKey&& p) noexcept
    {
        shared_pkey_ = std::move(p.shared_pkey_);
    }
    ~PrivateKey() = default;

    static PrivateKey generateRSA(int bits)
    {
        return { EVP_RSA_gen(bits) };
    }

    PrivateKey& operator=(const PrivateKey& p)
    {
        if (this == &p)
            return *this;

        shared_pkey_ = p.shared_pkey_;

        return *this;
    }

    PrivateKey& operator=(PrivateKey&& p) noexcept
    {
        if (this == &p)
            return *this;

        shared_pkey_ = std::move(p.shared_pkey_);

        return *this;
    }

    friend class PublicKey;
    friend class PEM;
    friend bool decrypt(const std::string& in, std::string& out, const PrivateKey& priKey);

protected:
    PrivateKey(EVP_PKEY* pkey)
    {
        shared_pkey_ = std::shared_ptr<EVP_PKEY>(pkey, [](EVP_PKEY* pkey) {EVP_PKEY_free(pkey); });
    }

    std::shared_ptr<EVP_PKEY> shared_pkey_;
};

class PublicKey
{
public:
    PublicKey() : shared_pkey_(EVP_PKEY_new(), [](EVP_PKEY* pkey) {EVP_PKEY_free(pkey); }) {}
    PublicKey(const PublicKey& p)
    {
        shared_pkey_ = p.shared_pkey_;
    }
    PublicKey(PublicKey&& p) noexcept
    {
        shared_pkey_ = std::move(p.shared_pkey_);
    }
    PublicKey(const PrivateKey& p)
    {
        shared_pkey_ = p.shared_pkey_;
    }
    PublicKey(PrivateKey&& p) noexcept
    {
        shared_pkey_ = std::move(p.shared_pkey_);
    }
    ~PublicKey() = default;

    PublicKey& operator=(const PublicKey& p)
    {
        if (this == &p)
            return *this;

        shared_pkey_ = p.shared_pkey_;

        return *this;
    }

    PublicKey& operator=(PublicKey&& p) noexcept
    {
        if (this == &p)
            return *this;

        shared_pkey_ = std::move(p.shared_pkey_);

        return *this;
    }

    friend class PEM;
    friend bool encrypt(const std::string& in, std::string& out, const PublicKey& pubKey);

protected:
    PublicKey(EVP_PKEY* pkey)
    {
        shared_pkey_ = std::shared_ptr<EVP_PKEY>(pkey, [](EVP_PKEY* pkey) {EVP_PKEY_free(pkey); });
    }

    std::shared_ptr<EVP_PKEY> shared_pkey_;
};

bool encrypt(const std::string& in, std::string& out, const PublicKey& pubKey)
{
    std::shared_ptr<EVP_PKEY_CTX> shared_ctx(EVP_PKEY_CTX_new(pubKey.shared_pkey_.get(), nullptr),
        [](EVP_PKEY_CTX* ctx) {EVP_PKEY_CTX_free(ctx); });
    EVP_PKEY_encrypt_init(shared_ctx.get());

    size_t outl = 8192;
    EVP_PKEY_encrypt(shared_ctx.get(), nullptr, &outl, (const unsigned char*)in.c_str(), in.size());
    
    out.resize(outl);
    int code = EVP_PKEY_encrypt(shared_ctx.get(), (unsigned char*)out.data(),
        &outl, (const unsigned char*)in.c_str(), in.size());
    if (!code)
    {
        return false;
    }

    out.resize(outl);

    return true;
}

bool decrypt(const std::string& in, std::string& out, const PrivateKey& priKey)
{
    std::shared_ptr<EVP_PKEY_CTX> shared_ctx(EVP_PKEY_CTX_new(priKey.shared_pkey_.get(), nullptr),
        [](EVP_PKEY_CTX* ctx) {EVP_PKEY_CTX_free(ctx); });
    EVP_PKEY_decrypt_init(shared_ctx.get());

    size_t outl = 8192;
    EVP_PKEY_decrypt(shared_ctx.get(), nullptr, &outl, (const unsigned char*)in.c_str(), in.size());

    out.resize(outl);
    if (!EVP_PKEY_decrypt(shared_ctx.get(), (unsigned char*)out.data(),
        &outl, (const unsigned char*)in.c_str(), in.size()))
    {
        return false;
    }

    out.resize(outl);

    return true;
}

PKEY_NAMESPACE_END

class PEM
{
public:
    PEM() = default;
    ~PEM() = default;

    static bool PEMReadPublicKey(const std::string pemData, pkey::PublicKey& key)
    {
        std::shared_ptr<BIO> shared_bio(BIO_new(BIO_s_mem()), [](BIO* bio) {BIO_vfree(bio); });

        BIO_write(shared_bio.get(), (const char*)pemData.c_str(), pemData.size());

        auto pointer = key.shared_pkey_.get();
        if (!PEM_read_bio_PUBKEY(shared_bio.get(), &pointer, nullptr, nullptr))
        {
            return false;
        }

        return true;
    }

    static bool PEMReadPrivateKey(const std::string pemData, pkey::PrivateKey& key)
    {
        std::shared_ptr<BIO> shared_bio(BIO_new(BIO_s_mem()), [](BIO* bio) {BIO_vfree(bio); });

        BIO_write(shared_bio.get(), (const char*)pemData.c_str(), pemData.size());

        auto pointer = key.shared_pkey_.get();
        if (!PEM_read_bio_PrivateKey(shared_bio.get(), &pointer, nullptr, nullptr))
        {
            return false;
        }
        return true;
    }

    static bool PEMWritePublicKey(const pkey::PublicKey& key, std::string& pemData)
    {
        std::shared_ptr<BIO> shared_bio(BIO_new(BIO_s_mem()), [](BIO* bio) {BIO_vfree(bio); });

        if (PEM_write_bio_PUBKEY(shared_bio.get(), key.shared_pkey_.get()) == -1)
        {
            return false;
        }

        constexpr int bufferSize = 512;
        size_t size = bufferSize;
        int code = 0;
        size_t j = 0;
        for (int i = 0; ; i++)
        {
            pemData.resize(size);
            code = BIO_read(shared_bio.get(), (char*)pemData.data() + j, bufferSize);
            if (code == -1)
            {
                return false;
            }
            else if (code < bufferSize)
                break;
            size += bufferSize;
            j += bufferSize;
        }
        pemData.resize(j + code);

        return true;
    }

    static bool PEMWritePrivateKey(const pkey::PrivateKey& key, std::string& pemData)
    {
        std::shared_ptr<BIO> shared_bio(BIO_new(BIO_s_mem()), [](BIO* bio) {BIO_vfree(bio); });

        if (PEM_write_bio_PrivateKey(shared_bio.get(), key.shared_pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr) == -1)
        {
            return false;
        }

        constexpr int bufferSize = 512;
        size_t size = bufferSize;
        int code = 0;
        size_t j = 0;
        for (int i = 0; ; i++)
        {
            pemData.resize(size);
            code = BIO_read(shared_bio.get(), (char*)pemData.data() + j, bufferSize);
            if (code == -1)
            {
                return false;
            }
            else if (code < bufferSize)
                break;
            size += bufferSize;
            j += bufferSize;
        }
        pemData.resize(j + code);

        return true;
    }
};

QUQICRYPTO_NAMESPACE_END

#endif // !RSA_HPP
