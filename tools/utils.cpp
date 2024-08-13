/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
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

#include <iostream>
#include <iomanip>
#include <sstream>
#include <random>
#include <thread>
#include <bitset>

bool isHex(std::string in) {
    if (in.substr(0, 2) == "0x")
        return true;
    return false;
}

std::string trimHexStr(const std::string& hex) {
    return hex.substr(2, hex.length());
}

std::string hexToBytes(std::string hex) {
    std::string res;
    res.reserve(hex.size() / 2);
    for (int i = 0; i < hex.size(); i += 2)
    {
        std::istringstream iss(hex.substr(i, 2));
        int temp;
        iss >> std::hex >> temp;
        res += static_cast<char>(temp);
    }
    return res;
}

std::vector<unsigned char> hexStringToBytesVec(const std::string& hexStr)
{
    std::vector<unsigned char> result(hexStr.size() / 2);

    for (size_t i = 0; i < result.size(); ++i) {
        std::string hexByte = hexStr.substr(i * 2, 2);
        result[i] = static_cast<unsigned char>(std::stoi(hexByte, nullptr, 16));
    }

    return result;
}

// Function to convert a hex string to an unsigned char array
void hexStringToBytes(const std::string& hexString, unsigned char* output) {
    size_t len = hexString.length();
    if (len % 2 != 0) {
        std::cout << "Hex string length should be even." << std::endl;
        return;
    }

    for (size_t i = 0; i < len; i += 2) {
        std::string byteString = hexString.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
        output[i / 2] = byte;
    }
}

std::string convertToHex(const std::string& input) {
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    
    // Iterate over each character in the input string
    for (char c : input) {
        // Convert the character to its hexadecimal representation
        hexStream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
    }
    
    // Return the hexadecimal representation as a string
    return hexStream.str();
}

std::string decimalToBinary(int num)
{
    if (num == 0) return "0"; // Special case: 0

    std::string str;
    while (num > 0) {
        str = (num % 2 == 0 ? "0" : "1") + str; // Append the least significant bit to the left
        num /= 2; // Divide by 2 to move to the next bit
    }
    return str;
}

int hexStringToInt(const std::string& hexString) {
    // Initialize an output stream
    std::stringstream ss;
    
    // Convert the hex string to an integer using stringstream
    ss << std::hex << hexString;
    
    // Initialize an integer to store the result
    int result;
    
    // Read the integer value from the stringstream
    ss >> result;
    
    // Return the integer value
    return result;
}

// Function to convert hexadecimal string to binary string
std::string hexToBinary(const std::string& hex) {
    std::string binary;
    for (char c : hex) {
        switch (c) {
            case '0': binary.append("0000"); break;
            case '1': binary.append("0001"); break;
            case '2': binary.append("0010"); break;
            case '3': binary.append("0011"); break;
            case '4': binary.append("0100"); break;
            case '5': binary.append("0101"); break;
            case '6': binary.append("0110"); break;
            case '7': binary.append("0111"); break;
            case '8': binary.append("1000"); break;
            case '9': binary.append("1001"); break;
            case 'A': case 'a': binary.append("1010"); break;
            case 'B': case 'b': binary.append("1011"); break;
            case 'C': case 'c': binary.append("1100"); break;
            case 'D': case 'd': binary.append("1101"); break;
            case 'E': case 'e': binary.append("1110"); break;
            case 'F': case 'f': binary.append("1111"); break;
        }
    }
    return binary;
}

std::string generateRandomHexData(size_t numBytes) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::ostringstream oss;
    for (size_t i = 0; i < numBytes; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(dis(gen));
    }

    return oss.str();
}

std::string generateRandomData(size_t sizeInMB) {
    size_t sizeInBytes = sizeInMB * 1024 * 1024; // Convert MB to bytes
    std::string data(sizeInBytes, '\0'); // Initialize string with required size

    // Use the number of available threads for parallelization
    unsigned int numThreads = std::thread::hardware_concurrency();
    size_t chunkSize = sizeInBytes / numThreads;

    // Define a lambda function to generate random data for a portion of the array
    auto fillRandomData = [&](size_t start, size_t end) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);

        for (size_t i = start; i < end; ++i) {
            data[i] = static_cast<char>(distrib(gen)); // Access string elements directly
        }
    };

    // Create threads to fill the string concurrently
    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < numThreads - 1; ++i) {
        threads.emplace_back(fillRandomData, i * chunkSize, (i + 1) * chunkSize);
    }

    // Fill the last portion of the string in the main thread
    fillRandomData((numThreads - 1) * chunkSize, sizeInBytes);

    // Join all threads to wait for their completion
    for (auto& thread : threads) {
        thread.join();
    }

    return data;
}

void xorBlock(unsigned char* a, const std::string& b, size_t blockIndex) {
    std::vector<unsigned char> bytesIV = hexStringToBytesVec(b);
    for (int i = 0; i < 16; i++) {
        a[blockIndex + i] ^= bytesIV[i];
    }
}

std::string printIntToBinary(uint64_t in) {
    return std::bitset<64>(in).to_string();
}

std::string printIntToBinary(uint32_t in) {
    return std::bitset<32>(in).to_string();
}

std::string toHex(const unsigned char* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string fromHex(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even length");
    }

    std::string binary;
    binary.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16));
        binary.push_back(byte);
    }

    return binary;
}

unsigned int xorHexStrings(const std::string& hexStr1, const std::string& hexStr2) {
    unsigned int num1;
    std::stringstream ss1;
    ss1 << std::hex << hexStr1;
    ss1 >> num1;

    unsigned int num2;
    std::stringstream ss2;
    ss2 << std::hex << hexStr2;
    ss2 >> num2;

    unsigned int result = num1 ^ num2;

    return result;
}