#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string>

#include "RSA.h"


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

int __cdecl main(int argc, char **argv) 
{
	bool DEBUG = false;
	//Booleans to do RSA checks
	bool RSA_ON = false;
	bool RSA_REC = false;
	bool RSA_SEN = false;

	//RSA variables, p and q are local while e and n are recieved
	unsigned long long int p = 5, q = 7, e = 0, n = 0;

	if (argc >= 3 && std::string(argv[2]) == "RSA") {
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
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL,
                    *ptr = NULL,
                    hints;
    char *sendbuf = new char[DEFAULT_BUFLEN];
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;
    
    // Validate the parameters
	/*
    if (argc != 2) {
        printf("usage: %s server-name\n", argv[0]);
        return 1;
    }
	*/

    // Initialize Winsock
	printf("Initialize Winsock \n");
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
	printf("Resolve the server address and port \n");
    iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
	printf("Attempt to connect to an address until one succeeds \n");
    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {

        // Create a SOCKET for connecting to server
		printf("Create a SOCKET for connecting to server \n");
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, 
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    // Send an initial buffer
	printf("Send an initial buffer \n");

	// loop to continuously send messages until the size is 1, meaning endline
	do {
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
		else if(RSA_ON && RSA_SEN) {
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

		fflush(stdin);

		// Send a message to the sender
		iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
		if (iResult == SOCKET_ERROR) {
			printf("send failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
			WSACleanup();
			return 1;
		}

		if (iResult > 1) 
			printf("Bytes Sent: %ld\n", iResult);
		else if (iResult == 1)
			printf("Connection closed\n");
		else
			printf("recv failed with error: %d\n", WSAGetLastError());

		iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		if (iResult > 1) {

			//Print message
			//spacing to look nice
			std::cout << std::endl;
			if(DEBUG) printf("\nBytes received: %d\n", iResult);
			printf("%.*s", iResult, recvbuf);
			if(RSA_ON) std::cout << std::endl;

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
		}
		else if (iResult == 1)
			printf("Connection closed\n");
		else
			printf("recv failed with error: %d\n", WSAGetLastError());

	} while (iResult > 1);

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}