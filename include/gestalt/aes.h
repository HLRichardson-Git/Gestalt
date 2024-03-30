/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * aes.h
 *
 * This file contains the definitions of Gestalts AES security functions.
 */

#pragma once

#include <string>

std::string aesEncryptECB(std::string msg, std::string key);
std::string aesDecryptECB(std::string msg, std::string key);

std::string aesEncryptCBC(std::string msg, std::string iv, std::string key);
std::string aesDecryptCBC(std::string msg, std::string iv, std::string key);