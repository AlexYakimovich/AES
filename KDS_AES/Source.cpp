#include <stdio.h>
#include <iostream>
#include <winsock.h>
#include <string>
#include <vector>
#include "Aes.h"
#include "DataHeader.h"
#include <string>
#pragma comment(lib,"WS2_32")
#pragma warning(disable:4996)

using namespace std;

const Block key{ 0x12345678, 0x9abcdef0, 0xffffaaaa, 0xabbaffff };

int main() {
  Aes aes(key.w[0], key.w[1], key.w[2], key.w[3]);
  vector<string> files;
  string request;
  string data;
  bool fileFound = false;
  bool edit = false;
  char reqFiles[128] = "FILES";
  char editFile[128] = "EDIT";
  char buffer[128];
  int iResult;
  WSADATA wsaData;
  // Initialize Winsock
  iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != 0) {
    printf("WSAStartup failed: %d\n", iResult);
    return 1;
  }

  int ClientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ClientSocket == NULL)
  {
    cout << "Error creating socket";
    return -1;
  }
  struct sockaddr_in SockAddr;
  SockAddr.sin_family = AF_INET;
  SockAddr.sin_port = htons(1337);
  SockAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  connect(ClientSocket, (struct sockaddr *)&SockAddr, sizeof(SockAddr));

  DataHeader * dataHeader = (DataHeader *)malloc(sizeof(DataHeader));
  FileHeader * fileHeader = (FileHeader *)malloc(sizeof(FileHeader));
  File * file = (File *)malloc(sizeof(File));
  
  cout << "Files on server:" << endl;

  aes.encrypt(reqFiles, sizeof(reqFiles));
  send(ClientSocket, reqFiles, sizeof(reqFiles), 0);
  size_t msg_size = recv(ClientSocket, (char *)dataHeader, sizeof(DataHeader), 0);
  aes.decrypt((char*)dataHeader, sizeof(DataHeader));
  for (int i = 0; i < dataHeader->dataSize / (sizeof(FileHeader)); i++)
  {
    size_t msg_size = recv(ClientSocket, (char *)fileHeader, sizeof(FileHeader), 0);
    aes.decrypt((char *)fileHeader, sizeof(FileHeader));
    files.push_back(string(fileHeader->fileName));
    cout << fileHeader->fileName << endl;
  }
  while (true) {
    edit = false;
    cout << "Enter file to download, or .edit for editing and .close to exit" << endl;
    fileFound = false;
    while (!fileFound)
    {
      cin >> request;

      if (request == ".close")
      {
        cout << "Closing";
        closesocket(ClientSocket);
        return 0;
      }

      if (request == ".edit")
      {
        edit = true;
        cout << "Enter file name:";
        cin >> request;
        for (int i = 0; i < files.size(); i++)
          if (files[i] == request) {
            fileFound = true;
            break;
          }
        if (!fileFound)
          files.push_back(request);
        cin.get();
        cout << "Enter file data: ";
        getline(cin, data);

        strcpy(buffer, editFile);
        aes.encrypt(buffer, 128);
        send(ClientSocket, buffer, sizeof(buffer), 0);

        strcpy(fileHeader->fileName, request.c_str());
        aes.encrypt((char *)fileHeader, sizeof(fileHeader));
        send(ClientSocket, (char *)fileHeader, sizeof(FileHeader), 0);

        strcpy(file->data, data.c_str());
        aes.encrypt((char *)file, sizeof(file));
        send(ClientSocket, (char *)file, sizeof(File), 0);

        cout << "File written" << endl;
      }

      for (int i = 0; i < files.size(); i++)
        if (files[i] == request) {
          fileFound = true;
          break;
        }
      if (!fileFound)
        cout << "File is not in the list!" << endl;
    }
    if (edit)
      continue;
    strcpy(buffer, request.c_str());
    aes.encrypt(buffer, 128);
    send(ClientSocket, buffer, sizeof(buffer), 0);


    msg_size = recv(ClientSocket, (char *)file, sizeof(File), 0);
    aes.decrypt((char*)file, sizeof(File));
    cout << "Recieved data: " << endl;
    cout << file->data << endl;
  }
}