/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * chachaPoly1305.h
 *
 * Result structs and declarations for the ChaCha20-Poly1305 AEAD construction
 * defined in RFC 8439 §2.8.
 */

#pragma once

#include <gestalt/secure_bytes.h>

struct ChaCha20Poly1305EncryptResult {
    SecureBytes ciphertext;
    SecureBytes tag;
};

struct ChaCha20Poly1305DecryptResult {
    SecureBytes plaintext;
    bool authenticated;
};
