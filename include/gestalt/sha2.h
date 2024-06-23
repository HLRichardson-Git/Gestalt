/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha2.h
 *
 * This file contains the definitions of Gestalts SHA2 security functions.
 */

#pragma once

#include <string>

std::string hashSHA224(std::string& in);
std::string hashSHA256(std::string& in);
std::string hashSHA384(std::string& in);
std::string hashSHA512(std::string& in);
std::string hashSHA512_224(std::string& in);
std::string hashSHA512_256(std::string& in);