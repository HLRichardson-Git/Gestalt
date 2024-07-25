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

std::string encryptAESECB(std::string msg, std::string key);
std::string decryptAESECB(std::string msg, std::string key);

std::string encryptAESCBC(std::string msg, std::string iv, std::string key);
std::string decryptAESCBC(std::string msg, std::string iv, std::string key);