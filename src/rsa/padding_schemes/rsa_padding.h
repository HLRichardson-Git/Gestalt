/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa_padding.h
 *
 */

# pragma once

const unsigned int SHA256_LENGTH = 32; // Hard coded hash len for sha2-256 for now

std::string MGF1(const std::string& seed, int maskLen);