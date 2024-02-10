#include "utils.h"

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

std::vector<unsigned char> generateRandomHexData(size_t numBytes) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::vector<unsigned char> randomBytes(numBytes);
    for (size_t i = 0; i < numBytes; ++i) {
        randomBytes[i] = static_cast<unsigned char>(dis(gen));
    }

    return randomBytes;
}

/*std::vector<unsigned char> generateRandomData(size_t sizeInMB) {
    size_t sizeInBytes = sizeInMB * 1024 * 1024; // Convert MB to bytes
    std::vector<unsigned char> data(sizeInBytes);

    // Use a random device as a source of entropy
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);

    // Fill the vector with random data
    std::generate(data.begin(), data.end(), [&]() { return static_cast<unsigned char>(distrib(gen)); });

    return data;
}*/
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

void xorBlock(unsigned char* a, const unsigned char* b, size_t blockIndex)
{
    for (int i = 0; i < 16; i++)
        a[blockIndex + i] ^= b[i];
}