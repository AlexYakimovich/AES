#pragma once

typedef struct {
  unsigned int dataSize;
  int  alingment1;
  int  alingment2;
  int  alingment3;
} DataHeader;

typedef struct {
  char fileName[128];
} FileHeader;


typedef struct {
  char data[1024];
} File;