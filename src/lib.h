#pragma once

#include <iostream>

// Internal Dependencies
//#include "DES Source Files/DES.h"
#include "aes/aes.h"

enum Algorithm {
	NONE,
	DES,
	AES_ECB,
	AES_CBC,
};

struct Message {
	std::vector<unsigned char> msg;
	Algorithm algorithm;
	std::vector<unsigned char> nonce;
	std::vector<unsigned char> digest;

	Message() = default;

	Message(const std::vector<unsigned char>& message,
		Algorithm algo = Algorithm::NONE,
		const std::vector<unsigned char>& nonceValue = std::vector<unsigned char>(),
		const std::vector<unsigned char>& messageDigest = std::vector<unsigned char>())
		: msg(message), algorithm(algo), nonce(nonceValue), digest(messageDigest)
	{}

	void aes_encrypt_ecb(std::string key);
	void aes_decrypt_ecb(std::string key);
	void aes_encrypt_cbc(std::string key);
	void aes_decrypt_cbc(std::string key);
};