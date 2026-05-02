/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * secure_bytes.h
 *
 * Provides SecureBytes, a typed byte-buffer wrapper around std::vector<uint8_t> with
 * automatic and explicit zeroing of sensitive material.
 *
 * Key properties:
 *   - Named constructors enforce explicit format declaration at every call site,
 *     eliminating the ASCII-vs-hex ambiguity to std::string-based APIs.
 *   - A custom ZeroingAllocator overwrites memory in deallocate() so that freed heap
 *     pages do not contain residual key or plaintext material.
 *   - The destructor calls zeroize() before the vector's destructor runs, providing a
 *     guarantee even if the allocator path is bypassed by a move.
 *   - SecureBytes::random() uses std::random_device
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <memory>

namespace detail {

// Overwrites [ptr, ptr+len) with zeros using a volatile pointer so the compiler optimize it away
inline void secureZero(void* ptr, std::size_t len) noexcept {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

template<typename T>
struct ZeroingAllocator : public std::allocator<T> {
    using Base = std::allocator<T>;
    
    using value_type = T;
    using size_type  = std::size_t;
    using pointer    = T*;

    ZeroingAllocator() noexcept = default;
    
    template<typename U>
    ZeroingAllocator(const ZeroingAllocator<U>&) noexcept : Base() {}

    void deallocate(pointer p, size_type n) noexcept {
        if (p) {
            secureZero(p, n * sizeof(T));
        }
        Base::deallocate(p, n);
    }
};

} // namespace detail

class SecureBytes {
private:
    using Buffer = std::vector<uint8_t, detail::ZeroingAllocator<uint8_t>>;
    Buffer buffer_;

public:
    SecureBytes() = default;

    // Zeroes the buffer before releasing memory.
    ~SecureBytes() { zeroize(); }

    // Constructs a buffer of n bytes, each initialised to fill.
    explicit SecureBytes(std::size_t n, uint8_t fill = 0) : buffer_(n, fill) {}

    // Parses a hexadecimal string (with or without a leading "0x" prefix) into bytes.
    static SecureBytes fromHex(const std::string& hex) {
        const std::string& h = (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
                               ? hex.substr(2) : hex;
        
        if (h.size() % 2 != 0) throw std::invalid_argument("SecureBytes::fromHex: odd-length hex string");

        SecureBytes result(h.size() / 2);
        for (std::size_t i = 0; i < h.size(); i += 2) {
            const char hi = h[i], lo = h[i + 1];
            auto nibble = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
                if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
                if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
                throw std::invalid_argument("SecureBytes::fromHex: non-hex character");
                return 0;
            };
            result.buffer_[i / 2] = static_cast<uint8_t>((nibble(hi) << 4) | nibble(lo));
        }
        return result;
    }

    // Copies the bytes of an ASCII / UTF-8 string directly into the buffer.
    static SecureBytes fromAscii(const std::string& ascii) {
        SecureBytes result(ascii.size());
        for (std::size_t i = 0; i < ascii.size(); ++i)
            result.buffer_[i] = static_cast<uint8_t>(ascii[i]);
        return result;
    }

    // Copies a std::vector<uint8_t> into the buffer.
    static SecureBytes fromVector(const std::vector<uint8_t>& v) {
        SecureBytes result(v.size());
        for (std::size_t i = 0; i < v.size(); ++i)
            result.buffer_[i] = v[i];
        return result;
    }

    static SecureBytes random(std::size_t n) {
        std::random_device rd;
        std::uniform_int_distribution<unsigned int> dist(0, 255);
        SecureBytes result(n);
        for (std::size_t i = 0; i < n; ++i)
            result.buffer_[i] = static_cast<uint8_t>(dist(rd));
        return result;
    }

    // Returns a lowercase hexadecimal string representation of the buffer.
    std::string toHex() const {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t byte : buffer_)
            oss << std::setw(2) << static_cast<unsigned int>(byte);
        return oss.str();
    }

    // Reinterprets the buffer as an ASCII / UTF-8 string.
    std::string toAscii() const {
        return std::string(buffer_.begin(), buffer_.end());
    }

    // Returns a copy of the buffer as a plain std::vector<uint8_t>.
    std::vector<uint8_t> toVector() const {
        return std::vector<uint8_t>(buffer_.begin(), buffer_.end());
    }

    // Element access
    uint8_t&       operator[](std::size_t i)       { return buffer_[i]; }
    const uint8_t& operator[](std::size_t i) const { return buffer_[i]; }

    uint8_t*       data()        noexcept { return buffer_.data(); }
    const uint8_t* data()  const noexcept { return buffer_.data(); }
    std::size_t    size()  const noexcept { return buffer_.size(); }
    bool           empty() const noexcept { return buffer_.empty(); }

    // Iterators
    auto begin()        noexcept { return buffer_.begin(); }
    auto end()          noexcept { return buffer_.end();   }
    auto begin()  const noexcept { return buffer_.begin(); }
    auto end()    const noexcept { return buffer_.end();   }
    auto cbegin() const noexcept { return buffer_.cbegin(); }
    auto cend()   const noexcept { return buffer_.cend();   }

    // Appends all bytes of other to the end of this buffer.
    void append(const SecureBytes& other) {
        buffer_.insert(buffer_.end(), other.buffer_.begin(), other.buffer_.end());
    }

    // Prepends all bytes of other before the start of this buffer.
    void prepend(const SecureBytes& other) {
        buffer_.insert(buffer_.begin(), other.buffer_.begin(), other.buffer_.end());
    }

    /*  
     *  Zeroes the buffer contents and releases the underlying memory.
     *  Called automatically by the destructor; may also be called explicitly
     *  when the caller wants to clear sensitive material before scope exit.
     */
    void zeroize() noexcept {
        if (!buffer_.empty()) {
            detail::secureZero(buffer_.data(), buffer_.size());
            Buffer empty;
            buffer_.swap(empty); // triggers deallocate which allocator zeroes again
        }
    }

    // Returns a new SecureBytes that is the concatenation of *this and other.
    SecureBytes operator+(const SecureBytes& other) const {
        SecureBytes result(*this);
        result.append(other);
        return result;
    }

    // Byte-wise equality.
    bool operator==(const SecureBytes& other) const {
        return buffer_.size() == other.buffer_.size() &&
               std::equal(buffer_.begin(), buffer_.end(), other.buffer_.begin());
    }

    bool operator!=(const SecureBytes& other) const { return !(*this == other); }

    // Deep copy. The source is not erased, that is the caller's responsibility.
    SecureBytes(const SecureBytes&)            = default;
    SecureBytes& operator=(const SecureBytes&) = default;

    // This move will not zeroize the source. Users who need the source erased should call src.zeroize() explicitly.
    SecureBytes(SecureBytes&&)            = default;
    SecureBytes& operator=(SecureBytes&&) = default;
};
