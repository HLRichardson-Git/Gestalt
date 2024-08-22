/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * oaep.h
 *
 */

# pragma once

std::string applyOAEP_Padding(const std::string& input, const std::string& label, unsigned int k);
std::string applyOAEP_Padding(const std::string& input, unsigned int k);