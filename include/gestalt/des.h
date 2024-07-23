/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * des.h
 *
 * This file contains the definitions of Gestalts DES & 3DES security functions.
 */

#pragma once

std::string desEncryptECB(const std::string& plaintext, const std::string& key);
std::string desDecryptECB(const std::string& ciphertext, const std::string& key);
std::string des3EncryptECB(
    const std::string& plaintext, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
);
std::string des3DecryptECB(
    const std::string& ciphertext, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
);

std::string desEncryptCBC(const std::string& plaintext, const std::string& iv, const std::string& key);
std::string desDecryptCBC(const std::string& ciphertext, const std::string& iv, const std::string& key);
std::string des3EncryptCBC(
    const std::string& plaintext,
    const std::string& iv, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
);
std::string des3DecryptCBC(
    const std::string& ciphertext,
    const std::string& iv, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
);