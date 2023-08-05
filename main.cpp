// QuqiCrypto.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#include "QuqiCrypto.hpp"

int main()
{
    qcrypto::AES<qcrypto::AESMode::CBC_256> aes;

    std::string out, out2;
    aes.encrypt("你好", out, "11111111111111111111111111111111", "1111111111111111", true);
    aes.encrypt(out, out2, "11111111111111111111111111111111", "1111111111111111", false);
    std::cout << out << " " << out2 << '\n';

    /*qcrypto::Base64 base64;

    std::string out, out2;
    base64.encrypt("ajksfhfafjklsjkldabshjdgwhjkagvhjksgdhjgwavsgfhgwahusbvdhwa", out, true);
    base64.encrypt(out, out2, false);
    std::cout << out << " " << out2 << '\n';*/





    /*EVP_PKEY* pkey = EVP_RSA_gen(2048);
    EVP_PKEY* pk2 = EVP_PKEY_new();
    EVP_PKEY_copy_parameters(pk2, pkey);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pk2, nullptr);

    EVP_PKEY_encrypt_init(ctx);
    unsigned char out[2048]{ 0 };
    size_t len = 0;
    EVP_PKEY_encrypt(ctx, out, &len, (unsigned char*)"你好", 6);

    EVP_PKEY_decrypt_init(ctx);

    EVP_PKEY_decrypt(ctx, out, &len, out, len);*/



    /*EVP_PKEY* pkey = EVP_RSA_gen(2048);

    auto bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

    char out[2048]{ 0 };
    BIO_read(bio, out, 2048);
    std::cout << out << '\n';

    PEM_read_bio_PrivateKey(bio, &pkey, nullptr, nullptr);*/



    //EVP_PKEY_free(pkey);

    /*auto pk = qcrypto::pkey::PrivateKey::generateRSA(2048);
    std::string data;

    qcrypto::pkey::encrypt("你好", data, qcrypto::pkey::PublicKey(pk));
    qcrypto::pkey::decrypt(data, data, pk);
    std::cout << data;*/

    return 0;
}