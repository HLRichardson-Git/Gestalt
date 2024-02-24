/*
 * lib.h
 *
 * This file contains the definitions of Gestalts security functions, and its central Message structure.
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-02-24
 */

#pragma once

#include <iostream>
#include <iomanip>
#include <string>

#include "modes/modes.h"

enum Algorithm {
	NONE,
	DES,
	AES_ECB,
	AES_CBC,
};

struct Message {
	std::string msg;
	Algorithm algorithm;
	std::string nonce;
	std::string digest;

	Message() = default;

	Message(std::string message = "",
		Algorithm algo = Algorithm::NONE,
		std::string nonceValue = "",
		const std::string messageDigest = "")
		: msg(message), algorithm(algo), nonce(nonceValue), digest(messageDigest)
	{}

	void aes_encrypt_ecb(std::string key);
	void aes_decrypt_ecb(std::string key);
	void aes_encrypt_cbc(std::string key);
	void aes_decrypt_cbc(std::string key);
};