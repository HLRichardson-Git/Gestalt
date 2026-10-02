/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * poly1305.h
 *
 * This file contains the definitions of Gestalts poly1305 security functions.
 */

#pragma once

#include <gestalt/secure_bytes.h>

SecureBytes poly1305_mac(const SecureBytes& message, const SecureBytes& key);
SecureBytes poly1305_key_gen(const SecureBytes& key, const SecureBytes& nonce);
