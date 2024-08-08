/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * vectors_aes.cpp
 *
 * This file contains the vectors used to test AES.
 */

#pragma once

const std::string key128 = "10a58869d74be5a374cf867cfb473859";
const std::string key192 = "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd";
const std::string key256 = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558";
const std::string plaintext = "Hello, Gestalt!";
const std::string nonce = "01020304050607080910111213141516";
const std::string multiBlockPT = 
    "Everything that lives is designed to end. We are perpetually trapped in a never-ending spiral of life and death. "
	"Is this a curse? Or some kind of punishment? I often think about the god who blessed us with this "
	"cryptic puzzle...and wonder if we'll ever get the chance to kill him.";