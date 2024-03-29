Gestalt CHANGES
===============

This is a detailed breakdown of significant changes.

For a full list of changes, see the [git commit log][log] and pick the
appropriate release branch.

  [log]: https://github.com/HLRichardson-Git/Gestalt/commits/

Gestalt Releases
----------------

 - [Gestalt 0.3](#gestalt-0.3)
 - [Gestalt 0.2](#gestalt-0.2)
 - [Gestalt 0.1.1](#gestalt-0.1.1)
 - [Gestalt 0.1](#gestalt-0.1)

 Gestalt 0.3
-----------

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

Gestalt 0.1.1
-----------

### Changes between 0.1.0 and 0.1.1 [24 Feb 2024]

 * Added generalized block cipher modes of operation functions.
 * Improved documentation.

Gestalt 0.1
-----------

### Changes between 0.0.0 and 0.1.0 [8 Feb 2024]

 * Gestalt entered pre-release with AES-ECB/CBC.
