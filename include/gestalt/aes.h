/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * aes.h
 *
 * This file contains the definitions of Gestalts AES security functions.
 */

#pragma once

#include <gestalt/secure_bytes.h>
#include "modes/gcm/gcm.h"

SecureBytes encryptAESECB(const SecureBytes& plaintext, const SecureBytes& key);
SecureBytes decryptAESECB(const SecureBytes& ciphertext, const SecureBytes& key);

SecureBytes encryptAESCBC(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key);
SecureBytes decryptAESCBC(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key);

SecureBytes encryptAESCFB(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key);
SecureBytes decryptAESCFB(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key);

SecureBytes encryptAESCTR(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key);
SecureBytes decryptAESCTR(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key);

GCMEncryptResult encryptAESGCM(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key, const SecureBytes& aad = SecureBytes{}, size_t tagLen = 16);
GCMDecryptResult decryptAESGCM(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key, const SecureBytes& tag, const SecureBytes& aad = SecureBytes{});
