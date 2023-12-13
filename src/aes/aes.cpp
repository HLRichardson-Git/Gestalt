#include "aes.h"
#include "aesConstants.h"

#include <iostream>

enum class AESKeySize : int {
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256
};

AES::AES(std::string key)
{
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

void AES::encryptBlock(std::vector<unsigned char>& input, size_t blockIndex)
{
    unsigned char state[4][4];

    // Copy input into state
    for (size_t j = 0; j < 4; j++) {
        for (size_t i = 0; i < 4; i++) {
            state[i][j] = input[blockIndex + i + 4 * j];
        }
    }

    addRoundKey(state, roundKey);

    size_t round = 1;
    while (round < Nr) {
        subByte(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKey + round * 4 * Nb);
        round++;
    }

    subByte(state);
    shiftRows(state);
    addRoundKey(state, roundKey + Nr * 4 * Nb);

    // Copy state back to input
    for (size_t j = 0; j < Nb; j++) {
        for (size_t i = 0; i < Nb; i++) {
            input[blockIndex + i + 4 * j] = state[i][j];
        }
    }
}

void AES::decryptBlock(std::vector<unsigned char>& input, size_t blockIndex)
{
    unsigned char state[4][4];

    // Copy input into state
    for (size_t j = 0; j < 4; j++) {
        for (size_t i = 0; i < 4; i++) {
            state[i][j] = input[blockIndex + i + 4 * j];
        }
    }

    addRoundKey(state, roundKey + Nr * 4 * Nb);

    size_t round = Nr - 1;
    while (round > 0) {
        invShiftRows(state);
        invSubByte(state);
        addRoundKey(state, roundKey + round * 4 * Nb);
        invMixColumns(state);
        round--;
    }

    invShiftRows(state);
    invSubByte(state);
    addRoundKey(state, roundKey);

    // Copy state back to input
    for (size_t j = 0; j < Nb; j++) {
        for (size_t i = 0; i < Nb; i++) {
            input[blockIndex + i + 4 * j] = state[i][j];
        }
    }
}

void AES::subByte(unsigned char state[4][4])
{
    for (size_t y = 0; y < 4; y++) {
        for (size_t x = 0; x < 4; x++) {
            state[x][y] = SBOX[state[x][y]];
        }
    }
}

void AES::shiftRows(unsigned char state[4][4])
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

void AES::mixColumns(unsigned char state[4][4])
{
    unsigned char temp[4][4];

    for (size_t i = 0; i < 4; ++i) {
        memset(temp[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                if (CMDS[i][k] == 1)
                    temp[i][j] ^= state[k][j];
                else
                    temp[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp[i], 4);
    }
}

void AES::addRoundKey(unsigned char state[4][4], unsigned char* roundKey)
{
    for (size_t x = 0; x < 4; x++) {
        for (size_t y = 0; y < 4; y++) {
            state[x][y] ^= roundKey[x + 4 * y];
        }
    }
}

/*void AES::mixColumns(std::vector<unsigned char>& input, size_t blockIndex) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char)GF_MUL_TABLE[2][input[blockIndex]] ^ GF_MUL_TABLE[3][input[blockIndex + 1]] ^ input[blockIndex + 2] ^ input[blockIndex + 3];
    tmp[1] = (unsigned char)input[blockIndex] ^ GF_MUL_TABLE[2][input[blockIndex + 1]] ^ GF_MUL_TABLE[3][input[blockIndex + 2]] ^ input[blockIndex + 3];
    tmp[2] = (unsigned char)input[blockIndex] ^ input[blockIndex + 1] ^ GF_MUL_TABLE[2][input[blockIndex + 2]] ^ GF_MUL_TABLE[3][input[blockIndex + 3]];
    tmp[3] = (unsigned char)GF_MUL_TABLE[3][input[blockIndex]] ^ input[blockIndex + 1] ^ input[blockIndex + 2] ^ GF_MUL_TABLE[2][input[blockIndex + 3]];

    tmp[4] = (unsigned char)GF_MUL_TABLE[2][input[blockIndex + 4]] ^ GF_MUL_TABLE[3][input[blockIndex + 5]] ^ input[blockIndex + 6] ^ input[blockIndex + 7];
    tmp[5] = (unsigned char)input[blockIndex + 4] ^ GF_MUL_TABLE[2][input[blockIndex + 5]] ^ GF_MUL_TABLE[3][input[blockIndex + 6]] ^ input[blockIndex + 7];
    tmp[6] = (unsigned char)input[blockIndex + 4] ^ input[blockIndex + 5] ^ GF_MUL_TABLE[2][input[blockIndex + 6]] ^ GF_MUL_TABLE[3][input[blockIndex + 7]];
    tmp[7] = (unsigned char)GF_MUL_TABLE[3][input[blockIndex + 4]] ^ input[blockIndex + 5] ^ input[blockIndex + 6] ^ GF_MUL_TABLE[2][input[blockIndex + 7]];

    tmp[8] = (unsigned char)GF_MUL_TABLE[2][input[blockIndex + 8]] ^ GF_MUL_TABLE[3][input[blockIndex + 9]] ^ input[blockIndex + 10] ^ input[blockIndex + 11];
    tmp[9] = (unsigned char)input[blockIndex + 8] ^ GF_MUL_TABLE[2][input[blockIndex + 9]] ^ GF_MUL_TABLE[3][input[blockIndex + 10]] ^ input[blockIndex + 11];
    tmp[10] = (unsigned char)input[blockIndex + 8] ^ input[blockIndex + 9] ^ GF_MUL_TABLE[2][input[blockIndex + 10]] ^ GF_MUL_TABLE[3][input[blockIndex + 11]];
    tmp[11] = (unsigned char)GF_MUL_TABLE[3][input[blockIndex + 8]] ^ input[blockIndex + 9] ^ input[blockIndex + 10] ^ GF_MUL_TABLE[2][input[blockIndex + 11]];

    tmp[12] = (unsigned char)GF_MUL_TABLE[2][input[blockIndex + 12]] ^ GF_MUL_TABLE[3][input[blockIndex + 13]] ^ input[blockIndex + 14] ^ input[blockIndex + 15];
    tmp[13] = (unsigned char)input[blockIndex + 12] ^ GF_MUL_TABLE[2][input[blockIndex + 13]] ^ GF_MUL_TABLE[3][input[blockIndex + 14]] ^ input[blockIndex + 15];
    tmp[14] = (unsigned char)input[blockIndex + 12] ^ input[blockIndex + 13] ^ GF_MUL_TABLE[2][input[blockIndex + 14]] ^ GF_MUL_TABLE[3][input[blockIndex + 15]];
    tmp[15] = (unsigned char)GF_MUL_TABLE[3][input[blockIndex + 12]] ^ input[blockIndex + 13] ^ input[blockIndex + 14] ^ GF_MUL_TABLE[2][input[blockIndex + 15]];

    for (int i = 0; i < 16; i++) {
        input[blockIndex + i] = tmp[i];
    }
}*/

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
}

void AES::addRoundKey(std::vector<unsigned char>& input, const std::vector<unsigned char> roundKey, size_t blockIndex, size_t round)
{
    for (size_t i = 0; i < 4 * Nb; i++) {
        input[blockIndex + i] ^= roundKey[round * Nb * 4 + i];
    }
}*/

void AES::invSubByte(unsigned char state[4][4])
{

    for (size_t y = 0; y < 4; y++) {
        for (size_t x = 0; x < 4; x++) {
            state[x][y] = INVSBOX[state[x][y]];
        }
    }

}

void AES::invShiftRows(unsigned char state[4][4])
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

void AES::invMixColumns(unsigned char state[4][4]) {
    unsigned char temp_state[4][4];

    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                temp_state[i][j] ^= GF_MUL_TABLE[INVCMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

/*void AES::invSubByte(std::vector<unsigned char>& input, size_t blockIndex)
{
    for (size_t y = 0; y < 4; y++) {
        for (size_t x = 0; x < 4; x++) {
            size_t idx = blockIndex + x + 4 * y; // Calculate index in the 'input' vector
            input[idx] = INVSBOX[input[idx]]; // Apply InvSubByte operation on 'input' vector
        }
    }
}

void AES::invShiftRows(std::vector<unsigned char>& input, size_t blockIndex)
{
    for (size_t i = 1; i < Nb; i++) {
        for (size_t j = 0; j < i; j++) {
            unsigned char last = input[blockIndex + i + 3 * 4]; // Calculate index in the 'input' vector
            for (size_t k = 3; k > 0; k--) {
                input[blockIndex + i + k * 4] = input[blockIndex + i + (k - 1) * 4]; // Shift elements in 'input' vector
            }
            input[blockIndex + i] = last; // Update the 'input' vector after shifting
        }
    }
}

void AES::invMixColumns(std::vector<unsigned char>& input, size_t blockIndex) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char)GF_MUL_TABLE[14][input[blockIndex]] ^ GF_MUL_TABLE[11][input[blockIndex + 1]] ^ GF_MUL_TABLE[13][input[blockIndex + 2]] ^ GF_MUL_TABLE[9][input[blockIndex + 3]];
    tmp[1] = (unsigned char)GF_MUL_TABLE[9][input[blockIndex]] ^ GF_MUL_TABLE[14][input[blockIndex + 1]] ^ GF_MUL_TABLE[11][input[blockIndex + 2]] ^ GF_MUL_TABLE[13][input[blockIndex + 3]];
    tmp[2] = (unsigned char)GF_MUL_TABLE[13][input[blockIndex]] ^ GF_MUL_TABLE[9][input[blockIndex + 1]] ^ GF_MUL_TABLE[14][input[blockIndex + 2]] ^ GF_MUL_TABLE[11][input[blockIndex + 3]];
    tmp[3] = (unsigned char)GF_MUL_TABLE[11][input[blockIndex]] ^ GF_MUL_TABLE[13][input[blockIndex + 1]] ^ GF_MUL_TABLE[9][input[blockIndex + 2]] ^ GF_MUL_TABLE[14][input[blockIndex + 3]];

    tmp[4] = (unsigned char)GF_MUL_TABLE[14][input[blockIndex + 4]] ^ GF_MUL_TABLE[11][input[blockIndex + 5]] ^ GF_MUL_TABLE[13][input[blockIndex + 6]] ^ GF_MUL_TABLE[9][input[blockIndex + 7]];
    tmp[5] = (unsigned char)GF_MUL_TABLE[9][input[blockIndex + 4]] ^ GF_MUL_TABLE[14][input[blockIndex + 5]] ^ GF_MUL_TABLE[11][input[blockIndex + 6]] ^ GF_MUL_TABLE[13][input[blockIndex + 7]];
    tmp[6] = (unsigned char)GF_MUL_TABLE[13][input[blockIndex + 4]] ^ GF_MUL_TABLE[9][input[blockIndex + 5]] ^ GF_MUL_TABLE[14][input[blockIndex + 6]] ^ GF_MUL_TABLE[11][input[blockIndex + 7]];
    tmp[7] = (unsigned char)GF_MUL_TABLE[11][input[blockIndex + 4]] ^ GF_MUL_TABLE[13][input[blockIndex + 5]] ^ GF_MUL_TABLE[9][input[blockIndex + 6]] ^ GF_MUL_TABLE[14][input[blockIndex + 7]];

    tmp[8] = (unsigned char)GF_MUL_TABLE[14][input[blockIndex + 8]] ^ GF_MUL_TABLE[11][input[blockIndex + 9]] ^ GF_MUL_TABLE[13][input[blockIndex + 10]] ^ GF_MUL_TABLE[9][input[blockIndex + 11]];
    tmp[9] = (unsigned char)GF_MUL_TABLE[9][input[blockIndex + 8]] ^ GF_MUL_TABLE[14][input[blockIndex + 9]] ^ GF_MUL_TABLE[11][input[blockIndex + 10]] ^ GF_MUL_TABLE[13][input[blockIndex + 11]];
    tmp[10] = (unsigned char)GF_MUL_TABLE[13][input[blockIndex + 8]] ^ GF_MUL_TABLE[9][input[blockIndex + 9]] ^ GF_MUL_TABLE[14][input[blockIndex + 10]] ^ GF_MUL_TABLE[11][input[blockIndex + 11]];
    tmp[11] = (unsigned char)GF_MUL_TABLE[11][input[blockIndex + 8]] ^ GF_MUL_TABLE[13][input[blockIndex + 9]] ^ GF_MUL_TABLE[9][input[blockIndex + 10]] ^ GF_MUL_TABLE[14][input[blockIndex + 11]];

    tmp[12] = (unsigned char)GF_MUL_TABLE[14][input[blockIndex + 12]] ^ GF_MUL_TABLE[11][input[blockIndex + 13]] ^ GF_MUL_TABLE[13][input[blockIndex + 14]] ^ GF_MUL_TABLE[9][input[blockIndex + 15]];
    tmp[13] = (unsigned char)GF_MUL_TABLE[9][input[blockIndex + 12]] ^ GF_MUL_TABLE[14][input[blockIndex + 13]] ^ GF_MUL_TABLE[11][input[blockIndex + 14]] ^ GF_MUL_TABLE[13][input[blockIndex + 15]];
    tmp[14] = (unsigned char)GF_MUL_TABLE[13][input[blockIndex + 12]] ^ GF_MUL_TABLE[9][input[blockIndex + 13]] ^ GF_MUL_TABLE[14][input[blockIndex + 14]] ^ GF_MUL_TABLE[11][input[blockIndex + 15]];
    tmp[15] = (unsigned char)GF_MUL_TABLE[11][input[blockIndex + 12]] ^ GF_MUL_TABLE[13][input[blockIndex + 13]] ^ GF_MUL_TABLE[9][input[blockIndex + 14]] ^ GF_MUL_TABLE[14][input[blockIndex + 15]];

    for (int i = 0; i < 16; i++) {
        input[blockIndex + i] = tmp[i];
    }
}*/

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