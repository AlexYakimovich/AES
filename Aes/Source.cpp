#include <iostream>
#include <stdio.h>
#include "Aes.h"
#pragma warning(disable:4996)
using namespace std;

void printMatrix(Block block)
{
  for (int i = 0; i < 4; i++)
  {
    printf("%c%c%c%c", (block.w[i] >> 24), (block.w[i] >> 16) & 255, (block.w[i] >> 8) & 255, (block.w[i]) & 255);
  }
}

int main()
{
  Aes aes(0x0f1571c9, 0x47d9e859, 0x0cb7addf, 0xaf7f6798);

  cout << "key: ";
  printMatrix(aes.key);

  Block block;
  block.w[0] = 0x89abcdef;
  block.w[1] = 0xab4def31;
  block.w[2] = 0xc2ef5123;
  block.w[3] = 0xef712d45;
  /*
  printMatrix(block);


  cout << endl << "Sub bytes" << endl;

  block = aes.subBytes(block);

  printMatrix(block);

  cout << endl << "Shift rows" << endl;
  block = aes.shiftRows(block);

  printMatrix(block);

  cout << endl << "Mix columns" << endl;

  block = aes.mixColumns(block);
*/

  cout << "Input data: " << endl;
  printMatrix(block);
  aes.encrypt(&block, 2);
  cout << endl << "Encrypted: " << endl; 
  printMatrix(block);

  aes.decrypt(&block, 2);
  cout << endl << "Decrypted: " << endl;
  printMatrix(block);
  system("pause");
}