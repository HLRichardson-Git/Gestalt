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
std::string hexToBinary(const std::string& hexStr) {
    std::string binStr;
    for (char c : hexStr) {
        switch (c) {
        case '0':
            binStr += "0000";
            break;
        case '1':
            binStr += "0001";
            break;
        case '2':
            binStr += "0010";
            break;
        case '3':
            binStr += "0011";
            break;
        case '4':
            binStr += "0100";
            break;
        case '5':
            binStr += "0101";
            break;
        case '6':
            binStr += "0110";
            break;
        case '7':
            binStr += "0111";
            break;
        case '8':
            binStr += "1000";
            break;
        case '9':
            binStr += "1001";
            break;
        case 'A':
        case 'a':
            binStr += "1010";
            break;
        case 'B':
        case 'b':
            binStr += "1011";
            break;
        case 'C':
        case 'c':
            binStr += "1100";
            break;
        case 'D':
        case 'd':
            binStr += "1101";
            break;
        case 'E':
        case 'e':
            binStr += "1110";
            break;
        case 'F':
        case 'f':
            binStr += "1111";
            break;
        case '.':
            binStr += ".";
            break;
        default:
                std::cerr << "Invalid hexadecimal character: " << c << std::endl;
                return "";
        }
    }
    return binStr;
}

// Function to convert binary string to integer
int binaryToInt(const std::string& binStr) {
    int result = 0;
    for (char c : binStr) {
        result = result * 2 + (c - '0');
    }
    return result;
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
    for (int i = 0; i < 16; i++) {
        a[blockIndex + i] ^= b[i];
    }
}