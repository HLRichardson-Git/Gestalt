/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * gcm.h
 *
 * This file contains the structs for gcm.
 */

#pragma once

#include <array>
#include <cstdint>

#include <gestalt/secure_bytes.h>

struct GCMEncryptResult {
    SecureBytes ciphertext;
    SecureBytes tag;
};

struct GCMDecryptResult {
    SecureBytes plaintext;
    bool authenticated;
};

// Internal GCM primitives, exposed for testing.
void ghashMultiply(std::array<uint8_t, 16>& X, const std::array<uint8_t, 16>& H);
std::array<uint8_t, 16> ghash(const std::array<uint8_t, 16>& H, const SecureBytes& aad, const SecureBytes& data);
void inc32(std::array<uint8_t, 16>& ctr);