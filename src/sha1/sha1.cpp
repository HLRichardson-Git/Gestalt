/*
 * sha1.cpp
 *
 * This file contains the implementation of Gestalts SHA1 security functions.
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-03-15
 */

#include <gestalt/sha1.h>
#include "sha1Core.h"

std::string hashSHA1(std::string in) {
    SHA1 SHA1object;
    return SHA1object.hash(in);
}