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
std::vector<unsigned char> generateRandomData(size_t sizeInMB) {
    size_t sizeInBytes = sizeInMB * 1024 * 1024; // Convert MB to bytes
    std::vector<unsigned char> data(sizeInBytes);

    // Use the number of available threads for parallelization
    unsigned int numThreads = std::thread::hardware_concurrency();
    size_t chunkSize = sizeInBytes / numThreads;

    // Define a lambda function to generate random data for a portion of the vector
    auto fillRandomData = [&](size_t start, size_t end) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);

        for (size_t i = start; i < end; ++i) {
            data[i] = static_cast<unsigned char>(distrib(gen));
        }
        };

    // Create threads to fill the vector concurrently
    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < numThreads - 1; ++i) {
        threads.emplace_back(fillRandomData, i * chunkSize, (i + 1) * chunkSize);
    }

    // Fill the last portion of the vector in the main thread
    fillRandomData((numThreads - 1) * chunkSize, sizeInBytes);

    // Join all threads to wait for their completion
    for (auto& thread : threads) {
        thread.join();
    }

    return data;
}

void xorBlock(std::vector<unsigned char>& a, std::vector<unsigned char>& b, size_t blockIndex)
{
    for (int i = 0; i < 16; i++)
        a[i + blockIndex] ^= b[i];
}