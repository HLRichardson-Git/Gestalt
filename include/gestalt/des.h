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

std::string encryptDESECB(const std::string& plaintext, const std::string& key);
std::string decryptDESECB(const std::string& ciphertext, const std::string& key);
std::string encrypt3DESECB(
    const std::string& plaintext, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
);
std::string decrypt3DESECB(
    const std::string& ciphertext, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
);

std::string encryptDESCBC(const std::string& plaintext, const std::string& iv, const std::string& key);
std::string decryptDESCBC(const std::string& ciphertext, const std::string& iv, const std::string& key);
std::string encrypt3DESCBC(
    const std::string& plaintext,
    const std::string& iv, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
);
std::string decrypt3DESCBC(
    const std::string& ciphertext,
    const std::string& iv, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
);