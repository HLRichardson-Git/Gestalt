/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecc.cpp
 *
 * This file contains the implementation of Gestalts ECC security functions.
 */

#include <math.h>
#include <random>
#include <tuple>
#include <iostream>
#include <string>
#include <sstream>
#include <gmp.h>

#include "ecc.h"

/*InfInt ECC::hexStringToInteger(const std::string& hexString) {
    InfInt result;
    for (char c : hexString) {
        result *= 16;
        if (c >= '0' && c <= '9') {
            result += (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            result += (c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            result += (c - 'A' + 10);
        } else {
            // Invalid character in hex string
            throw std::invalid_argument("Invalid hexadecimal character");
        }
    }
    return result;
}*/

// Function to add two points
Point ECC::addPoints(Point P, Point Q) {
    Point T;
    mpz_inits(T.x, T.y, NULL);

    mpz_t s;
    mpz_init(s);

    /* s = (y1 - y2) / (x1 - x2) */
    mpz_sub(T.x, P.y, Q.y);
    mpz_sub(T.y, P.x, Q.x);
    mpz_invert(T.y, T.y, curve.p);
    mpz_mul(s, T.x, T.y);
    mpz_mod(s, s, curve.p);

    /* rx = s^2 - (x1 + x2) */
    mpz_mul(T.x, s, s);
    mpz_sub(T.x, T.x, P.x);
    mpz_sub(T.x, T.x, Q.x);

    /* ry = s(x1 - rx) - y1 */
    mpz_sub(T.y, P.x, T.x);
     mpz_mul(T.y, s, T.y);
    mpz_sub(T.y, T.y, P.y);

    /* We assign the destination parameters in the end to allow them to
     be identical to the inputs. */
    Point R;
    mpz_inits(R.x, R.y, NULL);
    mpz_mod(R.x, T.x, curve.p);
    mpz_mod(R.y, T.y, curve.p);

    return R;

    /*Point T;
    mpz_inits(T.x, T.y, NULL);

    // Calculate deltaX and deltaY
    mpz_t deltaX, deltaY;
    mpz_inits(deltaX, deltaY, NULL);
    mpz_sub(deltaX, Q.x, P.x);
    mpz_sub(deltaY, Q.y, P.y);

    // Calculate invDeltaX
    mpz_t invDeltaX;
    mpz_init(invDeltaX);
    int invDeltaX_success = mpz_invert(invDeltaX, deltaX, curve.p);
    if (!invDeltaX_success) {
        // Handle case where modular inverse doesn't exist
        std::cerr << "Modular inverse does not exist." << std::endl;
        mpz_clears(T.x, T.y, deltaX, deltaY, invDeltaX, NULL);
        return T;
    }

    // Calculate slope
    mpz_t slope;
    mpz_init(slope);
    mpz_mul(slope, deltaY, invDeltaX);
    mpz_mod(slope, slope, curve.p);

    // Calculate x3
    mpz_t x3;
    mpz_init(x3);
    mpz_t slope_squared;
    mpz_init(slope_squared);
    mpz_mul(slope_squared, slope, slope);
    mpz_sub(x3, slope_squared, P.x);
    mpz_sub(x3, x3, Q.x);
    mpz_mod(x3, x3, curve.p);

    // Calculate y3
    mpz_t y3;
    mpz_init(y3);
    mpz_t temp;
    mpz_init(temp);
    mpz_sub(temp, P.x, x3);
    mpz_mul(y3, slope, temp);
    mpz_sub(y3, y3, P.y);
    mpz_mod(y3, y3, curve.p);

    // Assign calculated values to T
    mpz_set(T.x, x3);
    mpz_set(T.y, y3);

    // Clear temporary variables
    mpz_clears(deltaX, deltaY, invDeltaX, slope, x3, y3, slope_squared, temp, NULL);

    return T;*/

    /*Point T = {-1, -1}; // Initialize T to an invalid point
    InfInt deltaX = mod(Q.x - P.x, curve.p);
    InfInt deltaY = mod(Q.y - P.y, curve.p);
    InfInt invDeltaX = modInverse(deltaX, curve.p);

    if (invDeltaX == -1) {
        // Handle case where modular inverse doesn't exist
        std::cerr << "Modular inverse does not exist." << std::endl;
        return T;
    }

    InfInt slope = mod(deltaY * invDeltaX, curve.p);
    InfInt x3 = mod(slope * slope - P.x - Q.x, curve.p);
    InfInt y3 = mod(slope * (P.x - x3) - P.y, curve.p);

    T.x = x3;
    T.y = y3;

    return T;*/
}

// Function to double a point
Point ECC::doublePoint(Point P) {
    Point T;
    mpz_inits(T.x, T.y, NULL);
    
    mpz_t s;
    mpz_init(s);

      /* s = (3x^2 + a) / 2y */
    mpz_mul(T.x, P.x, P.x);
    mpz_mod(T.x, T.x, curve.p);
    mpz_mul_ui(T.x, T.x, 3);
    mpz_add(T.x, T.x, curve.a);
    mpz_mod(T.x, T.x, curve.p);

    mpz_mul_ui(T.y, P.y, 2);
    mpz_invert(T.y, T.y, curve.p);

    mpz_mul(s, T.x, T.y);
    mpz_mod(s, s, curve.p);

    /* rx = s^2 - 2x */
    mpz_mul(T.x, s, s);
    mpz_mul_ui(T.y, P.x, 2);
    mpz_sub(T.x, T.x, T.y);

    /* ry = s(x - rx) - y */
    mpz_sub(T.y, P.x, T.x);
    mpz_mul(T.y, s, T.y);
    mpz_sub(T.y, T.y, P.y);

    /* We assign the destination parameters in the end to allow them to
        be identical to the inputs. */
    Point R;
    mpz_inits(R.x, R.y, NULL);
    mpz_mod(R.x, T.x, curve.p);
    mpz_mod(R.y, T.y, curve.p);  

    return R;

    /*Point T;
    std::cout << "got here: Point T;" << std::endl;
    // Calculate s = (3 * P.x * P.x + curve.a) * (2 * P.y)^(-1) mod curve.p
    mpz_t s, tmp;
    mpz_inits(s, tmp, NULL);
    std::cout << "got here: mpz_t s, tmp; mpz_inits(s, tmp, NULL);" << std::endl;
    // Calculate 3 * P.x * P.x
    mpz_mul(tmp, P.x, P.x);
    mpz_mul_ui(tmp, tmp, 3);
    std::cout << "got here:     mpz_mul(tmp, P.x, P.x); mpz_mul_ui(tmp, tmp, 3);" << std::endl;
    // Add curve.a to 3 * P.x * P.x
    mpz_add(s, tmp, curve.a);
    std::cout << "got here: mpz_add(s, tmp, curve.a);" << std::endl;
    // Calculate 2 * P.y
    mpz_mul_ui(tmp, P.y, 2);
    std::cout << "got here: mpz_mul_ui(tmp, P.y, 2);" << std::endl;
    // Calculate the modular inverse of 2 * P.y
    mpz_invert(tmp, tmp, curve.p);
    std::cout << "got here: mpz_invert(tmp, tmp, curve.p);" << std::endl;
    // Multiply s by the modular inverse of 2 * P.y
    mpz_mul(s, s, tmp);
    std::cout << "got here: mpz_mul(s, s, tmp);" << std::endl;
    // Calculate s^2
    mpz_mul(tmp, s, s);
    std::cout << "got here: mpz_mul(tmp, s, s);" << std::endl;
    // Calculate x coordinate of the result
    mpz_sub(T.x, tmp, P.x);
    mpz_sub(T.x, T.x, P.x);
    std::cout << "got here: mpz_sub(T.x, tmp, P.x); mpz_sub(T.x, T.x, P.x);" << std::endl;
    // Calculate y coordinate of the result
    mpz_sub(tmp, P.x, T.x);
    mpz_mul(T.y, s, tmp);
    mpz_sub(T.y, T.y, P.y);
    std::cout << "got here: mpz_sub(tmp, P.x, T.x); mpz_mul(T.y, s, tmp); mpz_sub(T.y, T.y, P.y);" << std::endl;
    // Take the result modulo curve.p
    mpz_mod(T.x, T.x, curve.p);
    mpz_mod(T.y, T.y, curve.p);
    std::cout << "got here: mpz_mod(T.x, T.x, curve.p); mpz_mod(T.y, T.y, curve.p);" << std::endl;
    // Clear temporary variables
    mpz_clears(s, tmp, NULL);
    std::cout << "got here: mpz_clears(s, tmp, NULL);" << std::endl;
    return T;*/

    /*Point T;

    InfInt s = mod((InfInt)3 * P.x * P.x + curve.a, curve.p) * mod(modInverse((InfInt)2 * P.y, curve.p), curve.p);

    T.x = mod(((s * s) - P.x - P.x), curve.p);
    T.y = mod((s * (P.x - T.x) - P.y), curve.p);

    return T;*/
}
/*
// Clear memory allocated for a point
void ECC::clear_point(Point point) {
    mpz_clears(point.x, point.y, NULL);
}

// Constant time way to swap two points based on parameter
void ECC::cswap(Point &a, Point &b, int swap) {
    mpz_t temp;
    mpz_inits(temp, NULL);
    mpz_set(temp, a.x);
    if (swap) {
        mpz_set(a.x, b.x);
        mpz_set(b.x, temp);
    }
    mpz_set(temp, a.y);
    if (swap) {
        mpz_set(a.y, b.y);
        mpz_set(b.y, temp);
    }
    mpz_clear(temp);
}

// Ladder step function
void ECC::ladder_step(Point &x2y2, Point &x3y3, const mpz_t a24, const mpz_t x1) {
    mpz_t T1, T2, T3, T4, T5, T6;
    mpz_inits(T1, T2, T3, T4, T5, T6, NULL);

    // Temporary variables
    mpz_add(T1, x2y2.x, x2y2.y);
    mpz_sub(T2, x2y2.x, x2y2.y);
    mpz_add(T3, x3y3.x, x3y3.y);
    mpz_sub(T4, x3y3.x, x3y3.y);
    mpz_mul(T5, T1, T4);
    mpz_mul(T6, T2, T3);
    mpz_mul(T2, T2, T3);
    mpz_mul(T1, T1, T4);
    mpz_add(T1, T1, T2);
    mpz_sub(T2, T1, T2);
    mpz_mul(x3y3.x, T5, T6);
    mpz_mul(T2, T2, x1);
    mpz_mul(x2y2.x, T5, T6);
    mpz_sub(T5, T5, T6);
    mpz_mul(T1, a24, T5);
    mpz_add(T6, T6, T1);
    mpz_mul(x2y2.y, T5, T6);

    mpz_clears(T1, T2, T3, T4, T5, T6, NULL);
}

// Montgomery ladder algorithm
Point ECC::scalarMultiplyPoints(const mpz_t scalar, Point P) {
    Point x1, x2, y2, x3, y3, temp;
    mpz_inits(temp.x, temp.y, NULL);
    std::cout << "Got here" << std::endl;
    // Initialize points
    mpz_init_set(x1.x, P.x);
    std::cout << "Got here: mpz_set(x1.x, P.x);" << std::endl;
    mpz_init_set(x1.y, P.y);
    std::cout << "Got here: mpz_set(x1.y, P.y);" << std::endl;
    mpz_init_set(x2.x, x1.x);
    std::cout << "Got here: mpz_set(x2.x, x1.x);" << std::endl;
    mpz_init_set(x2.y, x1.y);
    std::cout << "Got here: mpz_set(x2.y, x1.y);" << std::endl;
    mpz_init_set_ui(y2.x, 1);
    std::cout << "Got here: mpz_set_ui(y2.x, 1);" << std::endl;
    mpz_init_set_ui(y2.y, 0);
    std::cout << "Got here: mpz_set_ui(y2.y, 0);" << std::endl;
    mpz_init_set(x3.x, x1.x);
    std::cout << "Got here: mpz_set(x3.x, x1.x);" << std::endl;
    mpz_init_set(x3.y, x1.y);
    std::cout << "Got here: mpz_set(x3.y, x1.y);" << std::endl;
    mpz_init_set_ui(y3.x, 1);
    std::cout << "Got here: mpz_set_ui(y3.x, 1);" << std::endl;
    mpz_init_set_ui(y3.y, 1);
    std::cout << "Got here: mpz_set_ui(y3.y, 1);" << std::endl;

    int prevbit = 0;
    int bit;

    mpz_t a24;
    mpz_inits(a24, NULL);
    mpz_add_ui(a24, curve.a, 2);
    mpz_tdiv_q_ui(a24, a24, 4);

    std::cout << "Got here" << std::endl;

    // Loop through bits of the scalar in descending order
    for (int i = mpz_sizeinbase(scalar, 2) - 1; i >= 0; i--) {
        bit = mpz_tstbit(scalar, i) ^ prevbit;
        prevbit = mpz_tstbit(scalar, i);

        // Swap points based on the bit value
        cswap(x2, x3, bit);
        cswap(y2, y3, bit);
        std::cout << "Got here after swap  i = " << i << std::endl;
        // Ladder step
        ladder_step(x2, x3, a24, x1.x);
        std::cout << "Got here after ladder  i = " << i << std::endl;
    }

    // Finalize result
    std::cout << "Got here" << std::endl;
    Point R;
    mpz_init_set(R.x, x2.x);
    mpz_init_set(R.y, x2.y);

    // Clear temporary memory
    clear_point(x1);
    clear_point(x2);
    clear_point(y2);
    clear_point(x3);
    clear_point(y3);
    clear_point(temp);

    return R;
}*/

// Implementation of the double-and-add algoirthm
Point ECC::scalarMultiplyPoints(const mpz_t& k, Point P) {
    Point T = P;

    /*std::cout << "P.x = ";
    mpz_out_str(stdout, 16, P.x);
    std::cout << std::endl;
    std::cout << "P.y = ";
    mpz_out_str(stdout, 16, P.y);
    std::cout << std::endl;

    std::cout << "Scalar k in binary: ";
    mpz_out_str(stdout, 2, k);
    std::cout << std::endl;*/

    //std::cout << "mpz_sizeinbase(k, 2) - 1 = " << mpz_sizeinbase(k, 2) - 2 << std::endl;
    // Perform scalar multiplication using the double-and-add algorithm
    for (int i = mpz_sizeinbase(k, 2) - 2; i >= 0; --i) {
        // Double the point
        //std::cout << "Doubling T:" << std::endl;

        T = doublePoint(T);

        /*std::cout << "  Result T after doubling:" << std::endl;
        std::cout << "    x = ";
        mpz_out_str(stdout, 16, T.x);
        std::cout << std::endl;
        std::cout << "    y = ";
        mpz_out_str(stdout, 16, T.y);
        std::cout << std::endl;*/

        // If the current bit of the scalar is 1, add the base point
        if (mpz_tstbit(k, i)) {
            //std::cout << "Adding base point P at bit " << i << ":" << std::endl;

            T = addPoints(T, P);

            /*std::cout << "  Result T after addition:" << std::endl;
            std::cout << "    x = ";
            mpz_out_str(stdout, 16, T.x);
            std::cout << std::endl;
            std::cout << "    y = ";
            mpz_out_str(stdout, 16, T.y);
            std::cout << std::endl;*/
        }
    }

    return T;
    /*// Base case: if k == 0, return the point at infinity
    if (mpz_cmp_ui(k, 0) == 0)
        return {0, 0};

    // Initialize the result point to the point at infinity
    Point T = {0, 0};

    // Temporary variables
    mpz_t bit;
    mpz_init(bit);

    // Determine bit length of k
    int bit_length = (int)mpz_sizeinbase(k, 2);

    // Loop over each bit of k, from most significant to least significant
    for (int i = bit_length ; i >= 0; i--) {
        // Double the point T
        T = doublePoint(T);

        // Extract the i-th bit of k
        //mpz_setbit(bit, i);
        //if (mpz_cmp(k, bit) >= 0) {
        if (mpz_tstbit(k, i)) {
            // If the i-th bit of k is set, add P to T
            T = addPoints(T, P);
            // Subtract 2^i from k
            //mpz_sub(k, k, bit);
        }
    }

    // Clear temporary variables
    //mpz_clear(bit);

    return T;*/
    
    /*// Base case: if k == 0, return the point at infinity
    if (mpz_cmp_ui(k, 0) == 0)
        return {0, 0};

    // Base case: if k == 1, return the point P
    if (mpz_cmp_ui(k, 1) == 0)
        return P;

    // Temporary variables
    Point T;
    mpz_t k_tmp;
    mpz_init(k_tmp);
    mpz_set(k_tmp, k);

    // Initialize the result point to the point at infinity
    T = {0, 0};

    // Loop until k > 0
    while (mpz_cmp_ui(k_tmp, 0) > 0) {
        // If k is odd, add P to the result
        if (mpz_odd_p(k_tmp))
            T = addPoints(T, P);

        // Divide k by 2
        mpz_tdiv_q_ui(k_tmp, k_tmp, 2);

        // Double the point P
        P = doublePoint(P);
    }

    // Clear temporary variable
    mpz_clear(k_tmp);

    return T;*/

    /*if (k == 0)
        return {0, 0};
    else if (k == 1) {
        return P;
    }
    else if (k % 2 == 1)
        return addPoints(P, scalarMultiplyPoints(k - 1, P));
    else
        return scalarMultiplyPoints(k / 2, doublePoint(P));*/
}

// Function to generate random numbers
void ECC::getRandomNumber(const mpz_t min, const mpz_t max, mpz_t& result) {
    // Initialize GMP random state
    gmp_randstate_t state;
    gmp_randinit_default(state);

    // Calculate the range
    mpz_t range;
    mpz_init(range);
    mpz_sub(range, max, min);

    // Generate a random number within the range
    mpz_urandomm(result, state, range);

    // Add the minimum value to the random number to shift it into the desired range
    mpz_add(result, result, min);

    // Clear temporary variables and random state
    mpz_clear(range);
    gmp_randclear(state);
}
/*InfInt ECC::getRandomNumber(const InfInt min, const InfInt max) {
    InfInt range = max - min + 1;
    if (range <= 0) {
        throw std::invalid_argument("Invalid range: min must be less than or equal to max.");
    }

    // Determine the number of digits needed to represent the range
    size_t numDigits = range.numberOfDigits();

    // Generate random digits
    std::string randomString;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> digitDistribution(0, 9);
    for (size_t i = 0; i < numDigits; ++i) {
        int digit = digitDistribution(gen);
        randomString += std::to_string(digit);
    }

    // Convert the random digits string to an InfInt value
    InfInt result(randomString);

    // Ensure the result is within the specified range [min, max]
    result %= range;
    result += min;

    return result;
}*/

// Function to complete the extended euclidean algorithm
/*InfInt ECC::extendedEuclidean(InfInt num, InfInt n) {
    InfInt a = mod(num, n);
    InfInt b = n;
    InfInt x = 0, y = 1, u = 1, v = 0;

    while (a != 0) {
        InfInt q = b / a;
        InfInt r = b % a;
        InfInt m = x - u * q;
        InfInt n = y - v * q;
        b = a; a = r;
        x = u; y = v;
        u = m; v = n;
    }
    const InfInt gcd = b;

    if (gcd != 1) {
        std::cerr << "Modular inverse does not exist." << std::endl;
        return -1; // Modular inverse does not exist
    }

    return mod(x, n);
}

// Function to compute the floored division
InfInt ECC::mod(InfInt a, InfInt n) {
    return ((a % n) + n) % n;
}

// Function to compute the modular multiplicative inverse
InfInt ECC::modInverse(InfInt a, InfInt m) {

    return extendedEuclidean(a, m);
}*/