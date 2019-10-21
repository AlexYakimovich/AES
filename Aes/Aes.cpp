#include "Aes.h"

static unsigned char sbox[] = { 99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22 };
static unsigned char invSbox[] = { 82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125};

static unsigned mixColMatrix[4][4] = { {2,3,1,1}, {1,2,3,1}, {1,1,2,3}, {3,1,1,2} };
static unsigned invMixColMatrix[4][4] = { {14, 11, 13, 9}, {9,14,11,13}, {13,9,14,11}, {11,13,9,14} };

void Aes::firstRoundKey()
{
  round = 0;
  roundKey.w[0] = extendedKey[0];
  roundKey.w[1] = extendedKey[1];
  roundKey.w[2] = extendedKey[2];
  roundKey.w[3] = extendedKey[3];
}

void Aes::nextRoundKey()
{
  if(round < 10)
    round++;
  roundKey.w[0] = extendedKey[round * 4];
  roundKey.w[1] = extendedKey[round * 4 + 1];
  roundKey.w[2] = extendedKey[round * 4 + 2];
  roundKey.w[3] = extendedKey[round * 4 + 3];
}

void Aes::previousRoundKey()
{
  if(round > 0)
    round--;
  roundKey.w[0] = extendedKey[round * 4];
  roundKey.w[1] = extendedKey[round * 4 + 1];
  roundKey.w[2] = extendedKey[round * 4 + 2];
  roundKey.w[3] = extendedKey[round * 4 + 3];
}

void Aes::lastRoundKey()
{
  round = 10;
  roundKey.w[0] = extendedKey[40];
  roundKey.w[1] = extendedKey[41];
  roundKey.w[2] = extendedKey[42];
  roundKey.w[3] = extendedKey[43];
}

void Aes::generateExtendedKey()
{
  extendedKey[0] = key.w[0];
  extendedKey[1] = key.w[1];
  extendedKey[2] = key.w[2];
  extendedKey[3] = key.w[3];

  unsigned char rc = 1;
  for (int i = 0; i < 40; i += 4)
  {
    Word g = extendedKey[i + 3];
    g = (g >> 24) + (g << 8);
    unsigned char b1 = g >> 24;
    unsigned char b2 = (g >> 16) & 255;
    unsigned char b3 = (g >> 8) & 255;
    unsigned char b4 = (g) & 255;
    g = (sbox[b1] << 24) + (sbox[b2] << 16) + (sbox[b3] << 8) + (sbox[b4]);

    Word rcon = rc << 24;
    if (rc == 0x80)
      rc = 1;
    else
      rc *= 2;
    g = g ^ rcon;

    extendedKey[i + 4] = extendedKey[i] ^ g;
    extendedKey[i + 5] = extendedKey[i + 4] ^ extendedKey[i + 1];
    extendedKey[i + 6] = extendedKey[i + 5] ^ extendedKey[i + 2];
    extendedKey[i + 7] = extendedKey[i + 6] ^ extendedKey[i + 3];
  }
}

Block Aes::subBytes(Block data)
{
  Block result;
  for (int i = 0; i < 4; i++)
  {
    unsigned char b1 = data.w[i] >> 24;
    unsigned char b2 = (data.w[i] >> 16) & 255;
    unsigned char b3 = (data.w[i] >> 8) & 255;
    unsigned char b4 = (data.w[i]) & 255;

    result.w[i] = (sbox[b1] << 24) + (sbox[b2] << 16) + (sbox[b3] << 8) + (sbox[b4]);
  }
  return result;
}

Block Aes::shiftRows(Block data)
{
  Block result;
  for (int i = 0; i < 4; i++)
  {
    unsigned char b[4];
    b[0] = data.w[i] >> 24;
    b[1] = (data.w[i] >> 16) & 255;
    b[2] = (data.w[i] >> 8) & 255;
    b[3] = (data.w[i]) & 255;

    result.w[i] = (b[i] << 24) + (b[(i + 1)%4] << 16) + (b[(i + 2)%4] << 8) + (b[(i + 3)%4]);
  }
  return result;
}

Block Aes::mixColumns(Block data)
{
  Block result;
  result.w[0] = 0;
  result.w[1] = 0;
  result.w[2] = 0;
  result.w[3] = 0;
  for (int i = 0; i < 4; i++)
  {
    unsigned char s[4];
    for (int g = 0; g < 4; g++)
      s[g] = (data.w[g] >> ((3 - i) * 8)) & 255;
    unsigned char ns[4] = { 0,0,0,0 };

    for (int g = 0; g < 4; g++)
      for (int j = 0; j < 4; j++)
        ns[g] = (ns[g] + s[j] * mixColMatrix[g][j]) & 255;

    for (int g = 0; g < 4; g++)
      result.w[g] += ns[g] << ((3 - i) * 8);
  }
  return result;
}

Block Aes::addRoundKey(Block data)
{
  Block result;
  for (int i = 0; i < 4; i++)
    result.w[i] = data.w[i] ^ roundKey.w[i];
  return result;
}

Block Aes::invShiftRows(Block data)
{
  Block result;
  for (int i = 0; i < 4; i++)
  {
    unsigned char b[4];
    b[0] = data.w[i] >> 24;
    b[1] = (data.w[i] >> 16) & 255;
    b[2] = (data.w[i] >> 8) & 255;
    b[3] = (data.w[i]) & 255;

    result.w[i] = (b[(4 -i) %4] << 24) + (b[(5 - i) % 4] << 16) + (b[(6 - i) % 4] << 8) + (b[(7 - i) % 4]);
  }
  return result;
}

Block Aes::invSubBytes(Block data)
{
  Block result;
  for (int i = 0; i < 4; i++)
  {
    unsigned char b1 = data.w[i] >> 24;
    unsigned char b2 = (data.w[i] >> 16) & 255;
    unsigned char b3 = (data.w[i] >> 8) & 255;
    unsigned char b4 = (data.w[i]) & 255;

    result.w[i] = (invSbox[b1] << 24) + (invSbox[b2] << 16) + (invSbox[b3] << 8) + (invSbox[b4]);
  }
  return result;
}

Block Aes::invMixColumns(Block data)
{
  Block result;
  result.w[0] = 0;
  result.w[1] = 0;
  result.w[2] = 0;
  result.w[3] = 0;
  for (int i = 0; i < 4; i++)
  {
    unsigned char s[4];
    for (int g = 0; g < 4; g++)
      s[g] = (data.w[g] >> ((3 - i) * 8)) & 255;
    unsigned char ns[4] = { 0,0,0,0 };

    for (int g = 0; g < 4; g++)
      for (int j = 0; j < 4; j++)
        ns[g] = (ns[g] + s[j] * invMixColMatrix[g][j]) & 255;

    for (int g = 0; g < 4; g++)
      result.w[g] += ns[g] << ((3 - i) * 8);
  }
  return result;
}

Aes::Aes(Word w1, Word w2, Word w3, Word w4)
{
  key.w[0] = w1;
  key.w[1] = w2;
  key.w[2] = w3;
  key.w[3] = w4;

  generateExtendedKey();
}

static Word charToWord(char c1, char c2, char c3, char c4)
{
  Word result = 0;
  result += c1 << 24;
  result += c2 << 16;
  result += c3 << 8;
  result += c4;
  return result;
}

void Aes::encrypt(Block * data, unsigned int dataSize)
{
  firstRoundKey();
  Block block = *data;
  /*block.w[0] = charToWord(data[0], data[1], data[2], data[3]);
  block.w[1] = charToWord(data[4], data[5], data[6], data[7]);
  block.w[2] = charToWord(data[8], data[9], data[10], data[11]);
  block.w[3] = charToWord(data[12], data[13], data[14], data[15]);*/

  block = addRoundKey(block);
  nextRoundKey();

  for (int i = 0; i < 10; i++)
  {
    block = subBytes(block);
    block = shiftRows(block);
    block = mixColumns(block);
    block = addRoundKey(block);
    nextRoundKey();
  }

  data->w[0] = block.w[0];
  data->w[1] = block.w[1];
  data->w[2] = block.w[2];
  data->w[3] = block.w[3];
}

void Aes::decrypt(Block * data, unsigned int dataSize)
{
  lastRoundKey();
  Block block = *data;
  /*block.w[0] = charToWord(data[0], data[1], data[2], data[3]);
  block.w[1] = charToWord(data[4], data[5], data[6], data[7]);
  block.w[2] = charToWord(data[8], data[9], data[10], data[11]);
  block.w[3] = charToWord(data[12], data[13], data[14], data[15]);*/

  block = addRoundKey(block);
  previousRoundKey();

  for (int i = 0; i < 10; i++)
  {
    block = invShiftRows(block);
    block = invSubBytes(block);
    block = addRoundKey(block);
    if(i < 9)
      block = invMixColumns(block);
    previousRoundKey();
  }

  data->w[0] = block.w[0];
  data->w[1] = block.w[1];
  data->w[2] = block.w[2];
  data->w[3] = block.w[3];
}

Aes::~Aes()
{
}
