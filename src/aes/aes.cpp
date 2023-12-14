#include "aes.h"
#include "aesConstants.h"

enum class AESKeySize : int {
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256
};

AES::AES(std::string key) {
    switch (key.size() * 4) {
    case static_cast<int>(AESKeySize::AES_128):
        Nw = 4;
        Nr = 10;
        break;
    case static_cast<int>(AESKeySize::AES_192):
        Nw = 6;
        Nr = 12;
        break;
    case static_cast<int>(AESKeySize::AES_256):
        Nw = 8;
        Nr = 14;
        break;
    default:
        throw std::invalid_argument("Invalid key size. Expected 128, 192, or 256 bits.");
    }

    roundKey = new unsigned char[16 * (Nr + 1)];
    keyExpansion(key, roundKey);
}

void AES::encryptBlock(std::vector<unsigned char>& input, size_t blockIndex) {
    // Copy input into state
    for (size_t i = 0; i < Nb; ++i) {
        std::memcpy(state[i].data(), input.data() + blockIndex + i * Nb, Nb);
    }


    addRoundKey(roundKey);

    size_t round = 1;
    while (round < Nr) {
        subByte();
        shiftRows();
        mixColumns();
        addRoundKey(roundKey + round * Nb);
        round++;
    }

    subByte();
    shiftRows();
    addRoundKey(roundKey + Nr * Nb);

    // Copy state back to input
    for (size_t i = 0; i < Nb; ++i) {
        std::memcpy(input.data() + blockIndex + i * Nb, state[i].data(), Nb * sizeof(unsigned char));
    }
}

void AES::decryptBlock(std::vector<unsigned char>& input, size_t blockIndex) {
    // Copy input into state
    for (size_t i = 0; i < Nb; ++i) {
        std::memcpy(state[i].data(), input.data() + blockIndex + i * Nb, Nb);
    }

    addRoundKey(roundKey + Nr * Nb);

    size_t round = Nr - 1;
    while (round > 0) {
        invShiftRows();
        invSubByte();
        addRoundKey(roundKey + round * Nb);
        invMixColumns();
        round--;
    }

    invShiftRows();
    invSubByte();
    addRoundKey(roundKey);

    // Copy state back to input
    for (size_t i = 0; i < Nb; ++i) {
        std::memcpy(input.data() + blockIndex + i * Nb, state[i].data(), Nb * sizeof(unsigned char));
    }
}

void AES::subByte() {
    for (size_t i = 0; i < Nb; i++) {
        state[i / Nb][i % Nb] = SBOX[state[i / Nb][i % Nb]];
    }
}

void AES::shiftRows()
{
    for (size_t i = 1; i < Nb; i++) {
        for (size_t j = 0; j < i; j++) {
            unsigned char first = state[i][0];
            for (size_t k = 0; k < 3; k++) {
                state[i][k] = state[i][k + 1];
            }
            state[i][3] = first;
        }
    }
}

void AES::mixColumns() {
    unsigned char tmp[Nb][Nb];

    for (int col = 0; col < Nb; col++) {
        tmp[0][col] = GF_MUL_TABLE[2][state[0][col]] ^ GF_MUL_TABLE[3][state[1][col]] ^ state[2][col] ^ state[3][col];
        tmp[1][col] = state[0][col] ^ GF_MUL_TABLE[2][state[1][col]] ^ GF_MUL_TABLE[3][state[2][col]] ^ state[3][col];
        tmp[2][col] = state[0][col] ^ state[1][col] ^ GF_MUL_TABLE[2][state[2][col]] ^ GF_MUL_TABLE[3][state[3][col]];
        tmp[3][col] = GF_MUL_TABLE[3][state[0][col]] ^ state[1][col] ^ state[2][col] ^ GF_MUL_TABLE[2][state[3][col]];
    }

    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < Nb; j++) {
            state[i][j] = tmp[i][j];
        }
    }
}

void AES::addRoundKey(unsigned char* roundKey) {
    for (size_t i = 0; i < Nb; i++) {
        for (size_t j = 0; j < Nb; j++) {
            state[i][j] ^= roundKey[i * Nb + j];
        }
    }
}


/*void AES::addRoundKey(std::vector<unsigned char>& input, const std::vector<unsigned char> roundKey, size_t blockIndex, size_t round)
{
    input[blockIndex + 0] ^= roundKey[round * Nb * 4 + 0];
    input[blockIndex + 1] ^= roundKey[round * Nb * 4 + 1];
    input[blockIndex + 2] ^= roundKey[round * Nb * 4 + 2];
    input[blockIndex + 3] ^= roundKey[round * Nb * 4 + 3];
    input[blockIndex + 4] ^= roundKey[round * Nb * 4 + 4];
    input[blockIndex + 5] ^= roundKey[round * Nb * 4 + 5];
    input[blockIndex + 6] ^= roundKey[round * Nb * 4 + 6];
    input[blockIndex + 7] ^= roundKey[round * Nb * 4 + 7];
    input[blockIndex + 8] ^= roundKey[round * Nb * 4 + 8];
    input[blockIndex + 9] ^= roundKey[round * Nb * 4 + 9];
    input[blockIndex + 10] ^= roundKey[round * Nb * 4 + 10];
    input[blockIndex + 11] ^= roundKey[round * Nb * 4 + 11];
    input[blockIndex + 12] ^= roundKey[round * Nb * 4 + 12];
    input[blockIndex + 13] ^= roundKey[round * Nb * 4 + 13];
    input[blockIndex + 14] ^= roundKey[round * Nb * 4 + 14];
    input[blockIndex + 15] ^= roundKey[round * Nb * 4 + 15];
}*/

void AES::invSubByte() {
    for (size_t i = 0; i < Nb; i++) {
        state[i / Nb][i % Nb] = INVSBOX[state[i / Nb][i % Nb]];
    }
}

void AES::invShiftRows()
{
    for (size_t i = 1; i < Nb; i++) {
        for (size_t j = 0; j < i; j++) {
            unsigned char last = state[i][3];
            for (size_t k = 3; k > 0; k--) {
                state[i][k] = state[i][k - 1];
            }
            state[i][0] = last;
        }
    }
}

void AES::invMixColumns() {
    unsigned char tmp[Nb][Nb];

    for (int col = 0; col < Nb; col++) {
        tmp[0][col] = GF_MUL_TABLE[14][state[0][col]] ^ GF_MUL_TABLE[11][state[1][col]] ^ GF_MUL_TABLE[13][state[2][col]] ^ GF_MUL_TABLE[9][state[3][col]];
        tmp[1][col] = GF_MUL_TABLE[9][state[0][col]] ^ GF_MUL_TABLE[14][state[1][col]] ^ GF_MUL_TABLE[11][state[2][col]] ^ GF_MUL_TABLE[13][state[3][col]];
        tmp[2][col] = GF_MUL_TABLE[13][state[0][col]] ^ GF_MUL_TABLE[9][state[1][col]] ^ GF_MUL_TABLE[14][state[2][col]] ^ GF_MUL_TABLE[11][state[3][col]];
        tmp[3][col] = GF_MUL_TABLE[11][state[0][col]] ^ GF_MUL_TABLE[13][state[1][col]] ^ GF_MUL_TABLE[9][state[2][col]] ^ GF_MUL_TABLE[14][state[3][col]];
    }

    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < Nb; j++) {
            state[i][j] = tmp[i][j];
        }
    }
}


void AES::keyExpansion(std::string key, unsigned char* roundKey) {
    unsigned char temp[4] = { 0x00, 0x00, 0x00, 0x00 };

    unsigned int i = 0;
    for (i = 0; i < 4 * Nw; i++)
    {
        int index = i * 2;
        // Extract two hexadecimal characters
        std::string hexByte = key.substr(index, 2);

        // Convert the hexadecimal string to an unsigned char
        roundKey[i] = static_cast<unsigned char>(std::stoi(hexByte, nullptr, 16));
    }

    i = 4 * Nw;
    while (i < 4 * Nb * (Nr + 1))
    {
        temp[0] = roundKey[i - 4 + 0];
        temp[1] = roundKey[i - 4 + 1];
        temp[2] = roundKey[i - 4 + 2];
        temp[3] = roundKey[i - 4 + 3];

        if (i / 4 % Nw == 0)
        {
            rotWord(temp);
            subWord(temp);
            rcon(temp, (i / (Nw * 4)) - 1);
        }
        else if (Nw > 6 && i / 4 % Nw == 4)
        {
            subWord(temp);
        }

        roundKey[i + 0] = roundKey[i + 0 - 4 * Nw] ^ temp[0];
        roundKey[i + 1] = roundKey[i + 1 - 4 * Nw] ^ temp[1];
        roundKey[i + 2] = roundKey[i + 2 - 4 * Nw] ^ temp[2];
        roundKey[i + 3] = roundKey[i + 3 - 4 * Nw] ^ temp[3];

        i += 4;
    }
}

void AES::rotWord(unsigned char temp[4])
{
    unsigned char temp2 = temp[0];
    for (int x = 0; x < 4; x++)
    {
        temp[x] = temp[x + 1];
    }
    temp[3] = temp2;
}

void AES::subWord(unsigned char temp[4])
{
    for (int x = 0; x < 4; x++)
    {
        temp[x] = SBOX[temp[x]];
    }
}

void AES::rcon(unsigned char temp[4], int round)
{
    temp[0] ^= RCON[round];
}

unsigned char* AES::getRoundKey() 
{
    return roundKey;
}

void applyPCKS7Padding(std::vector<unsigned char>& input)
{
    int elementsInLastBlock = 16 - (input.size() % 16);
    unsigned char paddingValue = static_cast<unsigned char>(elementsInLastBlock);
    for (int i = 0; i < elementsInLastBlock; i++) {
        input.push_back(paddingValue);
    }
}

void removePCKS7Padding(std::vector<unsigned char>& input)
{
    unsigned int padding_value = static_cast<unsigned int>(input[input.size() - 1]);
    size_t amount_to_remove = input.size() - padding_value;
    input.resize(amount_to_remove);
}