/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * des.h
 *
 * This file contains the definitions of Gestalts DES & 3DES security functions.
 */

#pragma once

#include <gestalt/secure_bytes.h>

[[deprecated("3DES is disallowed per NIST SP 800-131A Rev. 2 (2023); use AES instead.")]]
SecureBytes encrypt3DESECB(
    const SecureBytes& plaintext,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
);
[[deprecated("3DES is disallowed per NIST SP 800-131A Rev. 2 (2023); use AES instead.")]]
SecureBytes decrypt3DESECB(
    const SecureBytes& ciphertext,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
);

[[deprecated("3DES is disallowed per NIST SP 800-131A Rev. 2 (2023); use AES instead.")]]
SecureBytes encrypt3DESCBC(
    const SecureBytes& plaintext,
    const SecureBytes& iv,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
);
[[deprecated("3DES is disallowed per NIST SP 800-131A Rev. 2 (2023); use AES instead.")]]
SecureBytes decrypt3DESCBC(
    const SecureBytes& ciphertext,
    const SecureBytes& iv,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
);

[[deprecated("3DES is disallowed per NIST SP 800-131A Rev. 2 (2023); use AES instead.")]]
SecureBytes encrypt3DESCTR(
    const SecureBytes& plaintext,
    const SecureBytes& iv,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
);
[[deprecated("3DES is disallowed per NIST SP 800-131A Rev. 2 (2023); use AES instead.")]]
SecureBytes decrypt3DESCTR(
    const SecureBytes& ciphertext,
    const SecureBytes& iv,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
);
