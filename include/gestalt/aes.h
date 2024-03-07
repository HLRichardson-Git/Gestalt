/*
 * aes.h
 *
 * This file contains the definitions of Gestalts AES security functions.
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-03-07
 */

#pragma once

#include <string>
#include "../src/modes/modes.h"

std::string aes_encrypt_ecb(std::string msg, std::string key);
std::string aes_decrypt_ecb(std::string msg, std::string key);

std::string aes_encrypt_cbc(std::string msg, std::string iv, std::string key);
std::string aes_decrypt_cbc(std::string msg, std::string iv, std::string key);