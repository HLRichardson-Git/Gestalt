/*
 * lib.cpp
 *
 * This file contains the implementation of Gestalts security functions.
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-02-24
 */

#include "lib.h"

void Message::aes_encrypt_ecb(std::string key)
{	
	encrypt_ecb<AES>(msg, key, &AES::encryptBlock);
}

void Message::aes_decrypt_ecb(std::string key)
{
	decrypt_ecb<AES>(msg, key, &AES::decryptBlock);
}

void Message::aes_encrypt_cbc(std::string key)
{
	encrypt_cbc<AES>(msg, key, nonce, &AES::encryptBlock);
}

void Message::aes_decrypt_cbc(std::string key)
{
	decrypt_cbc<AES>(msg, key, nonce, &AES::decryptBlock);
}