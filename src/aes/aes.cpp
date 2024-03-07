/*
 * aes.cpp
 *
 * This file contains the implementation of Gestalts AES security functions.
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-03-07
 */

#include <gestalt/aes.h>

std::string aes_encrypt_ecb(std::string msg, std::string key) 
{
    return encrypt_ecb<AES>(msg, key, &AES::encryptBlock);
}

std::string aes_decrypt_ecb(std::string msg, std::string key)
{
    return decrypt_ecb<AES>(msg, key, &AES::decryptBlock);
}

std::string aes_encrypt_cbc(std::string msg, std::string iv, std::string key)
{
	return encrypt_cbc<AES>(msg, key, iv, &AES::encryptBlock);
}

std::string aes_decrypt_cbc(std::string msg, std::string iv, std::string key)
{
	return decrypt_cbc<AES>(msg, key, iv, &AES::decryptBlock);
}