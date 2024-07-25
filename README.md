<a id="readme-top"></a>
<p align="center">
  <img width="500" height="150" src="images/banner.png">
</p>

Welcome to the Gestalt
======================

Gestalt is a user-friendly cryptography library designed for developers who want to seamlessly integrate cryptographic algorithms into their projects. 

Our goal is to provide a straightforward and intuitive interface for implementing essential cryptographic operations without the hassle associated with more complex libraries.

## Table of Contents

 - [Building Gestalt](#building-gestalt)
   - [CMake](#cmake)
 - [Supported Algorithms](#supported-algorithms)
 - [Documentation](#documentation)
 - [Usage](#usage)
 - [Contributing](#contributing)
 - [Roadmap](#roadmap)
 - [License](#license)
 - [Contact](#contact)
 - [Legalities](#legalities)



## Building Gestalt

To get started, check out our [website](https://gestaltcrypto.github.io/) and [examples](https://gestaltcrypto.github.io/). Whether you're an experienced developer or new to cryptography, Gestalt is here to make cryptography accessible and hassle-free.

### CMake

You can include Gestalt in your CMake project by using 'FetchContent`:

1. **Include `FetchContent` in your `CMakeLists.txt`**:

    ```cmake
    cmake_minimum_required(VERSION 3.16.3)
    project(Project)

    include(FetchContent)

    FetchContent_Declare(
      Gestalt
      GIT_REPOSITORY https://github.com/HLRichardson-Git/Gestalt.git
      GIT_TAG main
    )

    FetchContent_MakeAvailable(Gestalt)
    add_executable(${PROJECT_NAME} main.cpp)
    target_link_libraries (${PROJECT_NAME} PRIVATE Gestalt)
    ```

2. **Build your project**:

    ```sh
    mkdir build
    cd build
    cmake ..
    cmake --build .
    ```

3. **Run the tests** (optional but recommended):

    ```sh
    ./_deps/gestalt-build/tests/Debug/tests.exe
    ```

By using the `FetchContent` module, Gestalt and its dependencies will be automatically downloaded and made available to your project. You can then link against it as shown in the example above.
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Supported Algorithms

To see more about the supported algorithms check out our [website](https://gestaltcrypto.github.io/) and [examples](https://gestaltcrypto.github.io/).

| Algorithm        | Type                 | Description                                                            |
|------------------|----------------------|------------------------------------------------------------------------|
| AES          | Symmetric Encryption | Advanced Encryption Standard                         |
| DES/3DES          | Symmetric Encryption | Data Encryption Standard                         |
| SHA-1          | Hash Function        | Secure Hash Algorithm                              |
| SHA-2          | Hash Function        | Secure Hash Algorithm                              |
| HMAC-SHA1      | Message Authentication Code | HMAC using SHA-1                                                   |
| HMAC-SHA2      | Message Authentication Code | HMAC using SHA-2                                                    |
| ECDSA              | Asymmetric Encryption| Elliptic Curve Signature Algorithm                                            |
| ECDH              | Asymmetric Encryption| Elliptic Curve Shared Secret computation                                            |

*More algorithms are being implemented very often, see [open issues](https://github.com/HLRichardson-Git/Gestalt/issues) to see algorithms in devlopment*
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Documentation

If you want to read more about using Gestalt the best place to start is the Gestalt website ["Getting Started"](https://gestaltcrypto.github.io/) page. You can also find a few examples under [Usage](#usage), or for more detailed examples check out Gestalts website ["Examples"](https://gestaltcrypto.github.io/) page.
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

Using Gestalt is meant to be as simple as possible for developers to quickly use cryptography algorithms. Here are just a couple of examples of using Gestalt:

### Example using AES CBC with 128-bit key:

```cpp
#include <gestalt/aes.h>
#include <iostream>

int main() {
    std::string key = "10a58869d74be5a374cf867cfb473859"; // 128-bit key
    std::string iv  = "123456789abcdef123456789abcdef12";
    std::string message = "Hello, Gestalt!";
    std::string ciphertext = encryptAESCBC(message, iv, key);

    std::cout << "AES-CBC-128: " << ciphertext << std::endl;

    return 0;
}
```

### Example using SHA2-256:

```cpp
#include <gestalt/sha2.h>
#include <iostream>

int main() {
    std::string message = "Hello, Gestalt!";
    std::string hash = hashSHA256(message);

    std::cout << "SHA2-256: " << hash << std::endl;

    return 0;
}
```

### Example using ECDSA with P-256 and SHA2-256:

```cpp
#include <gestalt/ecdsa.h>
#include <gestalt/sha2.h>
#include <iostream>

int main() {
    std::string privateKey = "0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    ECDSA ecdsa(StandardCurve::P256, privateKey);

    std::string message = "Hello, Gestalt!";
    std::string messageHash = hashSHA256(message);

    Signature signature = ecdsa.signMessage(messageHash);
    bool signatureStatus = ecdsa.verifySignature(messageHash, signature);

    if (signatureStatus) std::cout << "Valid!" << std::endl;

    return 0;
}
```

For more examples, check out our [examples](https://gestaltcrypto.github.io/).
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contributing

First off, thank you to anyone who takes the time to contribute to Gestalt! Contributors are what will make Gestalt even better, so any contributions are **greatly appreciated!**

Gestalt adheres to the contributor-maintained [code of conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [hunter@hunterrichardson.net]()

If you have a suggestion that would make Gestalt better, feel free to open an issue and one of the maintainers will try to respond promptly. Remember to give Gestalt a star, it keeps us very motivated!

Make sure you read through [CONTRIBUTING](CONTRIBUTING.md) before contributing. Here are the steps to follow if you want to contribute:

1. Fork Gestalt
2. Create your own branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

**Note:** *It is planned to create a [Gestalt Organization](https://github.com/GestaltCrypto)*
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Roadmap

- [ ] Add all FIPS-approved algorithms
- [ ] Refactor for multiple build environments
- [ ] Update all documentation to be current
- [ ] Prepare for the 1.0 launch
- [ ] Implement Non-Approved FIPS algorithms

See the [open issues](https://github.com/HLRichardson-Git/Gestalt/issues) for a full list of proposed features (and known issues).
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

Gestalt is licensed under the MIT License, which means that
you are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.

See the [LICENSE](LICENSE) file for more details.
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contact

Hunter Richardson - [hunter@hunterrichardson.net]()

Gestalt: https://github.com/HLRichardson-Git/Gestalt
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Legalities

A number of nations restrict the use or export of cryptography. If you are
potentially subject to such restrictions, you should seek legal advice before
attempting to develop or distribute cryptographic code.
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Acknowledgments

A special thanks to the following people and resources that make Gestalt better:

* [Gestalt Contributors](AUTHORS.md)
* [NIST](https://csrc.nist.gov/publications/fips)
* [GoogleTest](https://github.com/google/googletest)
* [GMP](https://gmplib.org/)

## Copyright

Copyright (c) 2023-2024 The Gestalt Project Authors.

All rights reserved.
<p align="right">(<a href="#readme-top">back to top</a>)</p>