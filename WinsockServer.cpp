#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include<string>

#include<ios>
#include<limits>

#include "RSA.h"

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

int __cdecl main(int argc, char** argv) 
{
	bool DEBUG = false;

	//Booleans to do RSA checks
	bool RSA_ON = false;
	bool RSA_REC = false;
	bool RSA_SEN = false;

	//RSA variables, p and q are local while e and n are recieved
	unsigned long long int p = 5, q = 7, e = 0, n = 0;

	if (argc >= 2 && std::string(argv[1]) == "RSA") {
		RSA_ON = true;
		std::cout << "RSA Enabled" << std::endl;
		std::cout << "Enter 2 different prime numbers whose product is over 255:" << std::endl;
		std::cout << "p:" << std::endl;
		std::cin >> p;
		std::cout << "q:" << std::endl;
		std::cin >> q;
	}

	//Only really needed here for scope later on
	RSA rsa = RSA(p, q);

	if (RSA_ON) {
		if (p * q < 255 || !rsa.checkPrime(p) || !rsa.checkPrime(q)) {
			std::cout << "Numbers don't work" << std::endl;
			return 1;
		}
		std::cin.clear();
		std::cin.ignore();
	}

    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    int iSendResult = 0;
    char recvbuf[DEFAULT_BUFLEN];
	char* sendbuf = new char[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);
    iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
	printf("Waiting for client to establish a connection \n");
    ClientSocket = accept(ListenSocket, NULL, NULL);

	printf("Connection esablished, waiting on message \n");
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);

    // Receive until the peer shuts down the connection
    do {

        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
        if (iResult > 1) {

			//RECIEVE MODE
			//spacing to look nice
			std::cout << std::endl;
			if(DEBUG) printf("Bytes received: %d\n", iResult);
			printf("%.*s", iResult, recvbuf);
			if (RSA_ON) std::cout << std::endl;
			
			//Print the necessary characters using the recieved bytes size

			//update with recieved public RSA vars
			if (RSA_ON && !RSA_REC) {
				std::string str(recvbuf);
				int space = str.find(' ');
				e = stoull(str.substr(2, space - 2));

				n = stoull(str.substr(space + 3));
				std::cout << "RSA: Recieved public keys e: " << e << ", n: " << n << std::endl;
				RSA_REC = true;
			}
			//use public vars to decrypt message
			else if (RSA_ON && RSA_REC) {
				std::string str(recvbuf);
				str = str.substr(0, iResult);
				std::string message = "";
				//if (DEBUG) std::cout << "Raw: " << str << std::endl;
				int index = 0;
				int nextColon = str.find(':');
				int finalColon = str.rfind(':');
				if (nextColon != finalColon) {
					do {
						message += char(rsa.decrypt(stoull(str.substr(index, nextColon - index)), rsa.get_d(), rsa.get_n()));
						//if (DEBUG) std::cout << str.substr(index, nextColon - index) << std::endl;
						index = nextColon + 1;
						nextColon = str.find(':', nextColon + 1);
						//if (DEBUG) std::cout << "next: " << nextColon << " final: " << finalColon << " index: " << index << std::endl;
					} while (nextColon < finalColon);
				}
				//if(DEBUG) std::cout << str.substr(index, finalColon - index) << std::endl;
				message += char(rsa.decrypt(stoull(str.substr(index, finalColon - index)), rsa.get_d(), rsa.get_n()));
				std::cout << message << std::endl;
			}

			//SEND MODE

			//gather user input and fill the sendbuffer with it
			printf("Input a message: \n>> ");

			//send keys
			if (RSA_ON && !RSA_SEN) {
				std::string pub_key = "e:" + std::to_string(rsa.get_e()) + " n:" + std::to_string(rsa.get_n()) + '\n';
				char* c = _strdup(pub_key.c_str());
				sendbuf = c;
				RSA_SEN = true;
			}
			//send message if RSA is on and keys were sent
			else if (RSA_ON && RSA_SEN) {
				std::string input;
				std::getline(std::cin, input);
				std::string final = "";
				for (char c : input) {
					final += std::to_string(rsa.encrypt((int)c, e, n)) + ":"; //encrypt with recieved public vars
				}
				sendbuf = _strdup(final.c_str());
			}
			//send message if RSA is off
			else {
				fgets(sendbuf, DEFAULT_BUFLEN, stdin);
			}

			// Send a message to the sender
            iSendResult = send( ClientSocket, sendbuf, (int)strlen(sendbuf), 0 );
            if (iSendResult == SOCKET_ERROR) {
				std::cout << "error 1: ";
                printf("send failed with error: %d\n", WSAGetLastError());
                closesocket(ClientSocket);
                WSACleanup();
                return 1;
            }
            if(DEBUG) printf("Bytes sent: %d\n", iSendResult);
        }
        else if (iSendResult == 1)
            printf("Connection closing...\n");
        else  {
			std::cout << "error 2: ";
            printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }

    } while (iResult > 1);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}