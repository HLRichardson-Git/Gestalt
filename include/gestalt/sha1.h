/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha1.h
 *
 * This file contains the definitions of Gestalts SHA1 security functions.
 */

#pragma once

#include <gestalt/secure_bytes.h>

SecureBytes hashSHA1(const SecureBytes& in);