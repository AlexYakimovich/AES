#include <stdio.h>
#include <iostream>
#include <windows.h>
#include <string>
#include <vector>
#include "../KDS_AES/Aes.h"
#include "../KDS_AES/DataHeader.h"
#pragma comment(lib,"WS2_32")
#pragma warning(disable:4996)

using namespace std;

const Block key{ 0x12345678, 0x9abcdef0, 0xffffaaaa, 0xabbaffff };



int main() {
  Aes aes(key.w[0], key.w[1], key.w[2], key.w[3]);

  void * encryptedData = malloc(1024);
  const char reqFiles[128] = "FILES";
  char editFile[128] = "EDIT";
  vector<string> files;
  files.push_back("file1.txt");
  files.push_back("file2.txt");
  files.push_back("file3.txt");
  vector<string> filesData;
  filesData.push_back("file1 data");
  filesData.push_back("file2 data");
  filesData.push_back("file3 data");

  int iResult;
  WSADATA wsaData;
  // Initialize Winsock
  iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != 0) {
    printf("WSAStartup failed: %d\n", iResult);
    return 1;
  }
  int MasterSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct sockaddr_in SockAddr;
  SockAddr.sin_family = AF_INET;
  SockAddr.sin_port = htons(1337);
  SockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  bind(MasterSocket, (struct sockaddr *)(&SockAddr), sizeof(SockAddr));

  listen(MasterSocket, SOMAXCONN);

  printf("Waiting 4 a client...\n");
  int ActiveSocket;
  fd_set socketsSet, recievedSet;
  int max = MasterSocket;

  FD_ZERO(&socketsSet);
  FD_ZERO(&recievedSet);
  FD_SET(MasterSocket, &socketsSet);

  DataHeader * dataHeader = (DataHeader *)malloc(sizeof(DataHeader));
  FileHeader * fileHeader = (FileHeader *)malloc(sizeof(FileHeader));
  File * file = (File *)malloc(sizeof(File));

  while (1)
  {
    recievedSet = socketsSet;

    select(max + 1, &recievedSet, NULL, NULL, NULL);

    for (ActiveSocket = 0; ActiveSocket <= max; ActiveSocket++)
    {
      if (FD_ISSET(ActiveSocket, &recievedSet))
      {
        if (ActiveSocket != MasterSocket)
        {
          char Buffer[128];
          size_t msg_size = recv(ActiveSocket, Buffer, 128, 0);
          aes.decrypt(Buffer, sizeof(Buffer));

          if (strcmp(Buffer, reqFiles) == 0)
          {

            dataHeader->dataSize = sizeof(FileHeader) * files.size();
            aes.encrypt((char *)dataHeader, sizeof(DataHeader));
            send(ActiveSocket, (char *)dataHeader, sizeof(DataHeader), 0);
            for (int i = 0; i < files.size(); i++)
            {
              strcpy(fileHeader->fileName, files[i].c_str());
              aes.encrypt((char *)fileHeader, sizeof(FileHeader));
              send(ActiveSocket, (char *)fileHeader, sizeof(FileHeader), 0);
            }
          }
          else if (strcmp(Buffer, editFile) == 0)
          {
            msg_size = recv(ActiveSocket, (char *)fileHeader, sizeof(FileHeader), 0);
            aes.decrypt((char *)fileHeader, sizeof(FileHeader));
            msg_size = recv(ActiveSocket, (char *)file, sizeof(File), 0);
            aes.decrypt((char *)file, sizeof(File));

            for (int i = 0; i < files.size(); i++)
            {
              if (strncmp(files[i].c_str(), fileHeader->fileName, files[i].size()) == 0)
              {
                filesData[i] = string(file->data);
                break;
              }
            }

            files.push_back(string(fileHeader->fileName));
            filesData.push_back(string(file->data));
          }
          else
          {

            for (int i = 0; i < files.size(); i++)
            {
              if (strncmp(files[i].c_str(), Buffer, files[i].size()) == 0)
              {
                strcpy(file->data, filesData[i].c_str());
                aes.encrypt((char *)file, sizeof(File));
                send(ActiveSocket, (char *)file, sizeof(File), 0);
                break;
              }
            }
          }
          //printf("Client #%d send msg: %s\n", ActiveSocket, Buffer);
        }
        else
        {
          ActiveSocket = accept(MasterSocket, 0, 0);
          FD_SET(ActiveSocket, &socketsSet);
          if (ActiveSocket > max)
            max = ActiveSocket;
          printf("Client #%d connected!\n", ActiveSocket);
        }
      }
    }


  }

  system("pause");
}