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

std::string encryptAESECB(const std::string& msg, std::string key);
std::string decryptAESECB(const std::string& hexMsg, std::string key);

std::string encryptAESCBC(const std::string& msg, std::string iv, std::string key);
std::string decryptAESCBC(const std::string& hexMsg, std::string iv, std::string key);