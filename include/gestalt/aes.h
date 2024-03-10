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

std::string aesEncryptECB(std::string msg, std::string key);
std::string aesDecryptECB(std::string msg, std::string key);

std::string aesEncryptCBC(std::string msg, std::string iv, std::string key);
std::string aesDecryptCBC(std::string msg, std::string iv, std::string key);