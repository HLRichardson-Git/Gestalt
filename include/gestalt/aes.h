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

[[deprecated("AES-ECB does not hide data patterns; identical plaintext blocks produce identical ciphertext. Use AES-GCM instead.")]]
SecureBytes encryptAESECB(const SecureBytes& plaintext, const SecureBytes& key);
[[deprecated("AES-ECB does not hide data patterns; identical plaintext blocks produce identical ciphertext. Use AES-GCM instead.")]]
SecureBytes decryptAESECB(const SecureBytes& ciphertext, const SecureBytes& key);

[[deprecated("AES-CBC lacks authentication and is susceptible to padding oracle attacks; prefer AES-GCM.")]]
SecureBytes encryptAESCBC(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key);
[[deprecated("AES-CBC lacks authentication and is susceptible to padding oracle attacks; prefer AES-GCM.")]]
SecureBytes decryptAESCBC(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key);

SecureBytes encryptAESCTR(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key);
SecureBytes decryptAESCTR(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key);

GCMEncryptResult encryptAESGCM(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key, const SecureBytes& aad = SecureBytes{}, size_t tagLen = 16);
GCMDecryptResult decryptAESGCM(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key, const SecureBytes& tag, const SecureBytes& aad = SecureBytes{});
