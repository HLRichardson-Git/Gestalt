/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha2.h
 *
 * This file contains the definitions of Gestalts SHA2 security functions.
 */

#pragma once

#include <gestalt/secure_bytes.h>

SecureBytes hashSHA224(const SecureBytes& in);
SecureBytes hashSHA256(const SecureBytes& in);
SecureBytes hashSHA384(const SecureBytes& in);
SecureBytes hashSHA512(const SecureBytes& in);
SecureBytes hashSHA512_224(const SecureBytes& in);
SecureBytes hashSHA512_256(const SecureBytes& in);