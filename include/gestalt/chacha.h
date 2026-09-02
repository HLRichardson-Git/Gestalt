/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * chacha.h
 *
 * This file contains the definitions of Gestalts ChaCha security functions.
 */

#pragma once

#include <gestalt/secure_bytes.h>
#include "chacha/chachaPoly1305.h"

SecureBytes encryptChaCha20(const SecureBytes& plaintext, const SecureBytes& key, const SecureBytes& nonce, const uint32_t& counter = 1);
SecureBytes decryptChaCha20(const SecureBytes& ciphertext, const SecureBytes& key, const SecureBytes& nonce, const uint32_t& counter = 1);

ChaCha20Poly1305EncryptResult encryptChaCha20Poly1305(const SecureBytes& plaintext, const SecureBytes& key, const SecureBytes& nonce, const SecureBytes& aad = SecureBytes{});
ChaCha20Poly1305DecryptResult decryptChaCha20Poly1305(const SecureBytes& ciphertext, const SecureBytes& key, const SecureBytes& nonce, const SecureBytes& tag, const SecureBytes& aad = SecureBytes{});
