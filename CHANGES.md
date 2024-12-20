Gestalt CHANGES
===============

This is a general breakdown of significant changes.

For a full list of changes, see the [git commit log][log] and pick the
appropriate release branch.

  [log]: https://github.com/HLRichardson-Git/Gestalt/commits/

Gestalt Releases
----------------

 - [Gestalt 0.7](#gestalt-07)
 - [Gestalt 0.6](#gestalt-06)
 - [Gestalt 0.5](#gestalt-05)
 - [Gestalt 0.4](#gestalt-04)
 - [Gestalt 0.3](#gestalt-03)
 - [Gestalt 0.2](#gestalt-02)
 - [Gestalt 0.1](#gestalt-01)

 Gestalt 0.7
-----------

### Changes between 0.6.2 and 0.7 [12 Nov 2024]

 * Adds RSA Key Generation with provable or probable primes with key sizes of 1024 to 15360.
 * Adds RSA key encryption with Raw or OAEP padding schemes.
 * Adds RSA message Signing Scheme with Raw or PSS padding schemes.
 * Refactors the `BigInt` class outside of ECC to its own file in `tools/bigint/bigint.h` to be used anywhere.
 * Refactors the hash utilities in ECC to its own file in `tools/hash_utils/hash_utils.h` to be used anywhere.

 Gestalt 0.6
-----------

### Changes between 0.6.1 and 0.6.2 [3 Nov 2024]

 * Adds `peerPublicKey` as parameter for ECDSA signature verification
 * Adds `ECDSAPublicKey` and `ECDHPublicKey` to be used for ECC public keys in place of old `Point` class
 * Adds `HashAlgorithm` enum as parameter to ECDSA signature generation/ verification to select hash to be used
 * Refactors ECDH to force user to pass `ECDHPublicKey` as parameter to compute shared secret for simplicity
 * Implements CI/CD GitHub action workflow to run unit tests on push/PR to main or release branches

### Changes between 0.6 and 0.6.1 [8 Aug 2024]

 * Refactors unit tests
 * Removes block cipher modes of operation general templates
 * Adds tailored block cipher modes of operation for each block cipher
 * Improves performance of AES functions

### Changes between 0.5 and 0.6 [24 Jul 2024]

 * Adds DES-ECB/CBC
 * Adds 3DES-ECB/CBC
 * Fixes AES-CBC
 * Improves testing for AES

 Gestalt 0.5
-----------

### Changes between 0.4 and 0.5 [13 Jul 2024]

 * Adds SHA2
 * Adds HMAC-SHA1
 * Adds HMAC-SHA2
 * Improves documentation

 Gestalt 0.4
-----------

### Changes between 0.4 and 0.4.1 [06 Jun 2024]

 * Fixed bug in ecc.cpp for function isValidKeyPair that wasn't detecting an identity
      point condition correctly.
 * Fixed issue where ecdsa.h and ecdh.h were not included in gestalt.h
 * Added build options to allow users the option to handle their own dependencies.
 * Fixed bug in eccObjects.h that caused BigInt initialization to not work properly.

### Changes between 0.3 and 0.4 [27 May 2024]

 * Implemented the ECDSA signing algorithm, providing users with the ability to 
      sign and verify messages.
 * Implemented the ECDH shared secret computation algorithm, providing users with 
      the ability to compute shared secrets on a insecure channel.
 * Ensured backward compatibility with existing library functionality and 
       usage patterns.
 * Updated documentation to include information on utilizing ECDSA and ECDH.

 Gestalt 0.3
-----------

### Changes between 0.3 and 0.3.1 [30 Mar 2024]

 * Fixed bug that caused large inputs for SHA-1 to take longer than expected.
 * Fixed bug in aes that caused rotWord function in the key expansion to go
      outside an arrays indices.
 * Addressed cppcheck static analyzer suggestions in Gestalt.
 * Improved Gestalts copyright and license, introducing an AUTHORS file. 

### Changes between 0.2 and 0.3 [17 Mar 2024]

 * Implemented the SHA1 hashing algorithm, providing users with the ability to 
       calculate SHA1 hashes of data.
 * Ensured backward compatibility with existing library functionality and 
       usage patterns.
 * Updated documentation to include information on utilizing the SHA1 hashing 
       feature.

Gestalt 0.2
-----------

### Changes between 0.1.1 and 0.2 [10 Mar 2024]

 * Major change to the library functionality from a one include class based
       library to seperated includes to seperate functionality so users only
       include what they need.
 * Files changes in src/aes/ from aes.h -> aesCore.h, aes.cpp -> aesCore.cpp,
       as to make the functionality change above aes.h and aes.cpp now define
       the front-end functions a user would use.
 * Improved AES testing, by making internal functions private, and adding
       friend class for testing purposes.
 * Changed CMake to download GoogleTest at build time, so developers don't
       need a local copy of GoogleTest.
 * Improved documentation.

Gestalt 0.1
-----------

### Changes between 0.1.0 and 0.1.1 [24 Feb 2024]

 * Added generalized block cipher modes of operation functions.
 * Improved documentation.

### Changes between 0.0.0 and 0.1.0 [8 Feb 2024]

 * Gestalt entered pre-release with AES-ECB/CBC.
