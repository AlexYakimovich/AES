#pragma once

typedef unsigned int Word;

typedef struct {
  Word w[4];
} Block;

class Aes
{
public:
  Aes(Word w1, Word w2, Word w3, Word w4);
  void encrypt(char * data, unsigned int dataSize);
  void decrypt(char * data, unsigned int dataSize);
  ~Aes();

  Block key;
  unsigned int round;
  Block roundKey;
  Word extendedKey[44];

  void firstRoundKey();
  void nextRoundKey();
  void previousRoundKey();
  void lastRoundKey();

  void generateExtendedKey();

  Block subBytes(Block data);
  Block shiftRows(Block data);
  Block mixColumns(Block data);
  Block addRoundKey(Block data);


  Block invShiftRows(Block data);
  Block invSubBytes(Block data);
  Block invMixColumns(Block data);
};

