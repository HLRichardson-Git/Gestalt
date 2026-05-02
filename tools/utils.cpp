/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * utils.cpp
 *
 * This file contains the implementation of utility functions declared in utils.h.
 * These functions include conversions between hexadecimal strings and byte arrays,
 * generation of random data, and XOR operations on byte arrays.
 */

#include "utils.h"

#include <iomanip>
#include <sstream>
#include <bitset>

std::string base64Encode(const std::vector<uint8_t>& data) {
    static constexpr char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < data.size()) {
        uint32_t triple =
            (data[i] << 16) |
            (data[i + 1] << 8) |
            (data[i + 2]);

        out.push_back(table[(triple >> 18) & 0x3F]);
        out.push_back(table[(triple >> 12) & 0x3F]);
        out.push_back(table[(triple >> 6) & 0x3F]);
        out.push_back(table[triple & 0x3F]);

        i += 3;
    }

    // Handle remainder
    if (i < data.size()) {
        uint32_t triple = data[i] << 16;
        out.push_back(table[(triple >> 18) & 0x3F]);

        if (i + 1 < data.size()) {
            triple |= data[i + 1] << 8;
            out.push_back(table[(triple >> 12) & 0x3F]);
            out.push_back(table[(triple >> 6) & 0x3F]);
            out.push_back('=');
        } else {
            out.push_back(table[(triple >> 12) & 0x3F]);
            out.push_back('=');
            out.push_back('=');
        }
    }

    return out;
}

std::vector<uint8_t> base64Decode(const std::string& s) {
    auto decodeChar = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        if (c == '=') return -1;
        throw std::runtime_error("Invalid Base64 character");
    };

    std::vector<uint8_t> out;
    out.reserve((s.size() * 3) / 4);

    for (size_t i = 0; i < s.size();) {
        int c1 = decodeChar(s[i++]);
        int c2 = decodeChar(s[i++]);
        int c3 = decodeChar(s[i++]);
        int c4 = decodeChar(s[i++]);

        if (c1 < 0 || c2 < 0)
            break; // invalid padding position

        uint32_t triple = (c1 << 18) | (c2 << 12);

        out.push_back((triple >> 16) & 0xFF);

        if (c3 >= 0) {
            triple |= (c3 << 6);
            out.push_back((triple >> 8) & 0xFF);
        }

        if (c4 >= 0) {
            triple |= c4;
            out.push_back(triple & 0xFF);
        }
    }

    return out;
}

std::string bytesToHex(const std::string& bytes) {
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (char c : bytes) {
        hexStream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
    }
    return hexStream.str();
}

std::string printIntToBinary(uint64_t in) {
    return std::bitset<64>(in).to_string();
}

std::string printIntToBinary(uint32_t in) {
    return std::bitset<32>(in).to_string();
}
