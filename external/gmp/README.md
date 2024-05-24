# GMP & MPIR Integration

This directory contains the CMake configuration to fetch, build, and integrate the GMP (GNU Multi Precision Arithmetic 
Library) and a fork of GMP, MPIR (Multiple Precision Integers and Rationals) into the Gestalt cryptography library.

## Overview

GMP and MPIR are an open-source libraries that provides arbitrary precision arithmetic. Gestalt uses the CMake feature:
`ExternalProject_Add` to automatically download and build GMP and MPIR as part of the Gestalt build process.

## License
The GMP and MPIR library are licensed under its their own terms, please review the terms of the licenses following the
links below.

## Additional Information
For more details about GMP and MPIR, please visit the official GMP and MPIR repository:
    - [GMP](https://gmplib.org)
    - [MPIR](https://github.com/wbhart/mpir)