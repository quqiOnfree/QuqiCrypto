// QuqiCrypto.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#include "QuqiCrypto.hpp"

int main()
{
    auto get = qcrypto::pkey::KeyGenerator::generateRSA(2048);
    qcrypto::pkey::PublicKey pubkey = get;

    std::string data = "你好", out1, out2, signature;

    qcrypto::pkey::encrypt(data, out1, pubkey);
    qcrypto::pkey::signature(data, signature, get, qcrypto::MDMode::sha256);
    qcrypto::pkey::decrypt(out1, out2, get);
    qcrypto::pkey::verify(out2, signature, pubkey, qcrypto::MDMode::sha256);

    return 0;
}