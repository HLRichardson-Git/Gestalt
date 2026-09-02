/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * chachaPoly1305.cpp
 *
 * ChaCha20-Poly1305 AEAD construction per RFC 8439 §2.8.
 */

#include "chachaPoly1305.h"
#include "../poly1305/poly1305.h"
#include <gestalt/chacha.h>

#include <cstdint>

// Appends 0–15 zero bytes so (out.size() % 16 == 0) after the call.
static void appendPad16(SecureBytes& out, const SecureBytes& data) {
    size_t rem = data.size() % 16;
    if (rem != 0)
        out.append(SecureBytes(16 - rem));
}

// Appends a 64-bit value as 8 little-endian bytes.
static void appendLE64(SecureBytes& out, uint64_t v) {
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i)
        buf[i] = static_cast<uint8_t>(v >> (8 * i));
    out.append(SecureBytes(buf, buf + 8));
}

/*
 * ChaCha20-Poly1305 authenticated encryption per RFC 8439 §2.8.
 *
 * key   must be 32 bytes.
 * nonce must be 12 bytes.
 * aad   may be empty.
 *
 * Returns the ciphertext and a 16-byte authentication tag.
 */
ChaCha20Poly1305EncryptResult encryptChaCha20Poly1305(
    const SecureBytes& plaintext,
    const SecureBytes& key,
    const SecureBytes& nonce,
    const SecureBytes& aad)
{
    SecureBytes otk        = poly1305_key_gen(key, nonce);
    SecureBytes ciphertext = encryptChaCha20(plaintext, key, nonce, 1);

    SecureBytes mac_data;
    mac_data.append(aad);        appendPad16(mac_data, aad);
    mac_data.append(ciphertext); appendPad16(mac_data, ciphertext);
    appendLE64(mac_data, static_cast<uint64_t>(aad.size()));
    appendLE64(mac_data, static_cast<uint64_t>(ciphertext.size()));

    return { ciphertext, poly1305_mac(mac_data, otk) };
}

/*
 * ChaCha20-Poly1305 authenticated decryption per RFC 8439 §2.8.
 *
 * Verifies the tag before decrypting. Returns authenticated=false and an empty
 * plaintext if the tag does not match; the caller must not use the plaintext
 * when authenticated is false.
 */
ChaCha20Poly1305DecryptResult decryptChaCha20Poly1305(
    const SecureBytes& ciphertext,
    const SecureBytes& key,
    const SecureBytes& nonce,
    const SecureBytes& tag,
    const SecureBytes& aad)
{
    SecureBytes otk = poly1305_key_gen(key, nonce);

    SecureBytes mac_data;
    mac_data.append(aad);        appendPad16(mac_data, aad);
    mac_data.append(ciphertext); appendPad16(mac_data, ciphertext);
    appendLE64(mac_data, static_cast<uint64_t>(aad.size()));
    appendLE64(mac_data, static_cast<uint64_t>(ciphertext.size()));

    SecureBytes expected_tag = poly1305_mac(mac_data, otk);
    if (expected_tag != tag)
        return { SecureBytes{}, false };

    return { encryptChaCha20(ciphertext, key, nonce, 1), true };
}
