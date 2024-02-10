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

void AES::encryptBlock(unsigned char* input) {
    unsigned char state[16];
    // Copy input into state
    memcpy(state, input, 16);

    auto start = std::chrono::high_resolution_clock::now();
    addRoundKey(state, roundKey);
    auto end = std::chrono::high_resolution_clock::now();
    addRoundKeyTime += end - start;

    size_t round = 1;
    while (round < Nr) {
        start = std::chrono::high_resolution_clock::now();
        subByte(state);
        end = std::chrono::high_resolution_clock::now();
        subByteTime += end - start;

        start = std::chrono::high_resolution_clock::now();
        shiftRows(state);
        end = std::chrono::high_resolution_clock::now();
        shiftRowsTime += end - start;

        start = std::chrono::high_resolution_clock::now();
        mixColumns(state);
        end = std::chrono::high_resolution_clock::now();
        mixColumnsTime += end - start;

        start = std::chrono::high_resolution_clock::now();
        addRoundKey(state, roundKey + (16 * round));
        end = std::chrono::high_resolution_clock::now();
        addRoundKeyTime += end - start;

        round++;
    }

    start = std::chrono::high_resolution_clock::now();
    subByte(state);
    end = std::chrono::high_resolution_clock::now();
    subByteTime += end - start;

    start = std::chrono::high_resolution_clock::now();
    shiftRows(state);
    end = std::chrono::high_resolution_clock::now();
    shiftRowsTime += end - start;

    start = std::chrono::high_resolution_clock::now();
    addRoundKey(state, roundKey + Nr * (Nb*Nb));
    end = std::chrono::high_resolution_clock::now();
    addRoundKeyTime += end - start;

    // Copy state back to input
    memcpy(input, state, 16);
}

void AES::decryptBlock(unsigned char* input) {
    unsigned char state[16];
    // Copy input into state
    /*for (size_t j = 0; j < 4; j++) {
        for (size_t i = 0; i < 4; i++) {
            state[i][j] = input[blockIndex + i + 4 * j];
        }
    }*/
    memcpy(state, input, 16);

    addRoundKey(state, roundKey + Nr * (Nb*Nb));

    size_t round = Nr - 1;
    while (round > 0) {
        invShiftRows(state);
        invSubByte(state);
        addRoundKey(state, roundKey + (16 * round));
        invMixColumns(state);
        round--;
    }

    invShiftRows(state);
    invSubByte(state);
    addRoundKey(state, roundKey);

    // Copy state back to input
    /*for (size_t j = 0; j < Nb; j++) {
        for (size_t i = 0; i < Nb; i++) {
            input[blockIndex + i + 4 * j] = state[i][j];
        }
    }*/
    memcpy(input, state, 16);
}

void AES::subByte(unsigned char state[Nb*Nb]) {
    for (size_t i = 0; i < Nb*Nb; i++) {
        state[i] = SBOX[state[i]];
    }
}

void AES::shiftRows(unsigned char state[Nb*Nb])
{
    unsigned char tmp[Nb*Nb];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[5];
	tmp[2] = state[10];
	tmp[3] = state[15];
	
	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[9];
	tmp[6] = state[14];
	tmp[7] = state[3];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[13];
	tmp[10] = state[2];
	tmp[11] = state[7];
	
	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[1];
	tmp[14] = state[6];
	tmp[15] = state[11];

    memcpy(state, tmp, 16);
}

void AES::mixColumns(unsigned char state[Nb*Nb])
{
    /*unsigned char tmp[Nb][Nb];

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
    }*/

    unsigned char tmp[Nb*Nb];

    tmp[0] = GF_MUL_TABLE[2][state[0]] ^ GF_MUL_TABLE[3][state[1]] ^ state[2] ^ state[3];
    tmp[1] = state[0] ^ GF_MUL_TABLE[2][state[1]] ^ GF_MUL_TABLE[3][state[2]] ^ state[3];
    tmp[2] = state[0] ^ state[1] ^ GF_MUL_TABLE[2][state[2]] ^ GF_MUL_TABLE[3][state[3]];
    tmp[3] = GF_MUL_TABLE[3][state[0]] ^ state[1] ^ state[2] ^ GF_MUL_TABLE[2][state[3]];

    tmp[4] = GF_MUL_TABLE[2][state[4]] ^ GF_MUL_TABLE[3][state[5]] ^ state[6] ^ state[7];
    tmp[5] = state[4] ^ GF_MUL_TABLE[2][state[5]] ^ GF_MUL_TABLE[3][state[6]] ^ state[7];
    tmp[6] = state[4] ^ state[5] ^ GF_MUL_TABLE[2][state[6]] ^ GF_MUL_TABLE[3][state[7]];
    tmp[7] = GF_MUL_TABLE[3][state[4]] ^ state[5] ^ state[6] ^ GF_MUL_TABLE[2][state[7]];

    tmp[8] = GF_MUL_TABLE[2][state[8]] ^ GF_MUL_TABLE[3][state[9]] ^ state[10] ^ state[11];
    tmp[9] = state[8] ^ GF_MUL_TABLE[2][state[9]] ^ GF_MUL_TABLE[3][state[10]] ^ state[11];
    tmp[10] = state[8] ^ state[9] ^ GF_MUL_TABLE[2][state[10]] ^ GF_MUL_TABLE[3][state[11]];
    tmp[11] = GF_MUL_TABLE[3][state[8]] ^ state[9] ^ state[10] ^ GF_MUL_TABLE[2][state[11]];

    tmp[12] = GF_MUL_TABLE[2][state[12]] ^ GF_MUL_TABLE[3][state[13]] ^ state[14] ^ state[15];
    tmp[13] = state[12] ^ GF_MUL_TABLE[2][state[13]] ^ GF_MUL_TABLE[3][state[14]] ^ state[15];
    tmp[14] = state[12] ^ state[13] ^ GF_MUL_TABLE[2][state[14]] ^ GF_MUL_TABLE[3][state[15]];
    tmp[15] = GF_MUL_TABLE[3][state[12]] ^ state[13] ^ state[14] ^ GF_MUL_TABLE[2][state[15]];

    memcpy(state, tmp, 16);
}

void AES::addRoundKey(unsigned char state[Nb*Nb], unsigned char* roundKey) {
    /*for (size_t i = 0; i < Nb; i++) {
        for (size_t j = 0; j < Nb; j++) {
            state[i][j] ^= roundKey[i * Nb + j];
        }
    }*/
    for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
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

void AES::invSubByte(unsigned char state[Nb*Nb]) {
    for (size_t i = 0; i < Nb*Nb; i++) {
        state[i] = INVSBOX[state[i]];
    }
}

void AES::invShiftRows(unsigned char state[Nb*Nb])
{
    unsigned char tmp[Nb*Nb];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

    memcpy(state, tmp, 16);
}

void AES::invMixColumns(unsigned char state[Nb*Nb]) {
    unsigned char tmp[Nb*Nb];

    tmp[0]  = GF_MUL_TABLE[14][state[0]] ^ GF_MUL_TABLE[11][state[1]] ^ GF_MUL_TABLE[13][state[2]] ^ GF_MUL_TABLE[9][state[3]];
    tmp[1]  = GF_MUL_TABLE[9][state[0]] ^ GF_MUL_TABLE[14][state[1]] ^ GF_MUL_TABLE[11][state[2]] ^ GF_MUL_TABLE[13][state[3]];
    tmp[2]  = GF_MUL_TABLE[13][state[0]] ^ GF_MUL_TABLE[9][state[1]] ^ GF_MUL_TABLE[14][state[2]] ^ GF_MUL_TABLE[11][state[3]];
    tmp[3]  = GF_MUL_TABLE[11][state[0]] ^ GF_MUL_TABLE[13][state[1]] ^ GF_MUL_TABLE[9][state[2]] ^ GF_MUL_TABLE[14][state[3]];

    tmp[4]  = GF_MUL_TABLE[14][state[4]] ^ GF_MUL_TABLE[11][state[5]] ^ GF_MUL_TABLE[13][state[6]] ^ GF_MUL_TABLE[9][state[7]];
    tmp[5]  = GF_MUL_TABLE[9][state[4]] ^ GF_MUL_TABLE[14][state[5]] ^ GF_MUL_TABLE[11][state[6]] ^ GF_MUL_TABLE[13][state[7]];
    tmp[6]  = GF_MUL_TABLE[13][state[4]] ^ GF_MUL_TABLE[9][state[5]] ^ GF_MUL_TABLE[14][state[6]] ^ GF_MUL_TABLE[11][state[7]];
    tmp[7]  = GF_MUL_TABLE[11][state[4]] ^ GF_MUL_TABLE[13][state[5]] ^ GF_MUL_TABLE[9][state[6]] ^ GF_MUL_TABLE[14][state[7]];

    tmp[8]  = GF_MUL_TABLE[14][state[8]] ^ GF_MUL_TABLE[11][state[9]] ^ GF_MUL_TABLE[13][state[10]] ^ GF_MUL_TABLE[9][state[11]];
    tmp[9]  = GF_MUL_TABLE[9][state[8]] ^ GF_MUL_TABLE[14][state[9]] ^ GF_MUL_TABLE[11][state[10]] ^ GF_MUL_TABLE[13][state[11]];
    tmp[10] = GF_MUL_TABLE[13][state[8]] ^ GF_MUL_TABLE[9][state[9]] ^ GF_MUL_TABLE[14][state[10]] ^ GF_MUL_TABLE[11][state[11]];
    tmp[11] = GF_MUL_TABLE[11][state[8]] ^ GF_MUL_TABLE[13][state[9]] ^ GF_MUL_TABLE[9][state[10]] ^ GF_MUL_TABLE[14][state[11]];

    tmp[12] = GF_MUL_TABLE[14][state[12]] ^ GF_MUL_TABLE[11][state[13]] ^ GF_MUL_TABLE[13][state[14]] ^ GF_MUL_TABLE[9][state[15]];
    tmp[13] = GF_MUL_TABLE[9][state[12]] ^ GF_MUL_TABLE[14][state[13]] ^ GF_MUL_TABLE[11][state[14]] ^ GF_MUL_TABLE[13][state[15]];
    tmp[14] = GF_MUL_TABLE[13][state[12]] ^ GF_MUL_TABLE[9][state[13]] ^ GF_MUL_TABLE[14][state[14]] ^ GF_MUL_TABLE[11][state[15]];
    tmp[15] = GF_MUL_TABLE[11][state[12]] ^ GF_MUL_TABLE[13][state[13]] ^ GF_MUL_TABLE[9][state[14]] ^ GF_MUL_TABLE[14][state[15]];

    memcpy(state, tmp, 16);
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

/*void applyPCKS7Padding(std::vector<unsigned char>& input)
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
}*/

void applyPCKS7Padding(unsigned char* input, size_t origMsgLen, size_t paddedMsgLen) {
    int elementsInLastBlock = 16 - (origMsgLen % 16);
    unsigned char paddingValue = static_cast<unsigned char>(elementsInLastBlock);
    for (size_t i = origMsgLen; i < paddedMsgLen; i++) {
        input[i] = paddingValue;
    }
}

void removePCKS7Padding(unsigned char* input, size_t origMsgLen, size_t paddedMsgLen) {
    unsigned int padding_value = static_cast<unsigned int>(input[paddedMsgLen - 1]);
    size_t amount_to_remove = paddedMsgLen - padding_value;
    if (amount_to_remove > origMsgLen) {
        // Invalid padding, do nothing
        return;
    }
    // Adjust input size to the actual decrypted message length
    input[amount_to_remove] = '\0'; // Null-terminate the string at the end of the decrypted message
}

