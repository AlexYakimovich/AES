#include <stdio.h>
#include <iostream>
#include "Aes.h"
#pragma warning(disable:4996)

using namespace std;

void printMatrix(Block block)
{
  for (int i = 0; i < 4; i++)
  {
    printf("%x %x %x %x \n", (block.w[i] >> 24), (block.w[i] >> 16) & 255, (block.w[i] >> 8) & 255, (block.w[i]) & 255);
  }
}

int main() {
  /*unsigned char * arr = new unsigned char[4];
  arr[0] = 0xdb;
  arr[1] = 0x13;
  arr[2] = 0x53;
  arr[3] = 0x45;
  printf("%x %x %x %x\n", arr[0], arr[1], arr[2], arr[3]);
  gmix_column(arr[0], arr[1], arr[2], arr[3]);
  printf("%x %x %x %x\n", arr[0], arr[1], arr[2], arr[3]);
  ginv_column(arr[0], arr[1], arr[2], arr[3]);
  printf("%x %x %x %x", arr[0], arr[1], arr[2], arr[3]);*/
  
  Aes aes(12, 12, 12, 12);

  char * data = new char[64];
  strcpy(data, "Hi, my frend, my name is alex yakimovich.Today I'm good as fuck");

  cout << "Original: " << data << endl;

  
  //block = aes.addRoundKey(block);
  aes.encrypt(data, 64);

  cout << endl << "Mixed: " << data << endl;

  //block = aes.addRoundKey(block);
  aes.decrypt(data, 64);

  cout << endl << "Inv Mixed: " << data << endl;
 
  system("pause");
}