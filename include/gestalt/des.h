/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * des.h
 *
 * This file contains the definitions of Gestalts DES security functions.
 */

#pragma once

std::string desEncryptECB(const std::string& plaintext, const std::string& hexKey);
std::string desDecryptECB(const std::string& ciphertext, const std::string& hexKey);

std::string desEncryptCBC(const std::string& plaintext, const std::string& iv, const std::string& hexKey);
std::string desDecryptCBC(const std::string& ciphertext, const std::string& iv, const std::string& hexKey);