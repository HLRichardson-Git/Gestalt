set(prefix "${CMAKE_BINARY_DIR}/deps")
set(MPIR_LIBRARY "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}mpir${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(MPIR_INCLUDE_DIR "${prefix}/include")

ExternalProject_Add(mpir
    PREFIX "${prefix}"
    DOWNLOAD_NAME mpir-cmake.tar.gz
    DOWNLOAD_NO_PROGRESS TRUE
    URL https://github.com/chfast/mpir/archive/cmake.tar.gz
    URL_HASH SHA256=d32ea73cb2d8115a8e59b244f96f29bad7ff03367162b660bae6495826811e06
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DCMAKE_INSTALL_LIBDIR=lib
        -DCMAKE_BUILD_TYPE=Release
        -DMPIR_GMP=On
    BUILD_BYPRODUCTS "${MPIR_LIBRARY}"
)

# Export MPIR variables for parent scope
set(MPIR_LIBRARY "${MPIR_LIBRARY}" PARENT_SCOPE)
set(MPIR_INCLUDE_DIR "${MPIR_INCLUDE_DIR}" PARENT_SCOPE)