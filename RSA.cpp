#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>
#include <random>

#include "RSA.h"

bool DEBUG = false;

//handles both encryption and decryption
unsigned long long int crypt(unsigned long long int m, unsigned long long int e, unsigned long long int n) {
	//returns m^e mod (n)
	unsigned long long int c;
	if (m > n) {
		if (DEBUG) std::cout << "input must be less than n (" << n << ")" << std::endl;
		return -1;
	}
	else {
		c = 1;
		for (int i = 1; i <= e; i++) {
			c *= m;
			c = c % n;
		}
		if (DEBUG) std::cout << "c = m^e % n" << '\n' << "m: " << m << '\n' << "c: " << c << std::endl;
		return c;
	}
}

unsigned long long int RSA::encrypt(unsigned long long int m, unsigned long long int e, unsigned long long int n) {
	return crypt(m, e, n);
}

unsigned long long int RSA::decrypt(unsigned long long int c, unsigned long long int d, unsigned long long int n) {
	return crypt(c, d, n);
}


unsigned long long int findGCD(unsigned long long int n1, unsigned long long int n2) {
	//Euclid's method of GCD
	if (n2 == 0) {
		return n1;
	}
	return findGCD(n2, n1 % n2);
}

unsigned long long int carMFunc(unsigned long long int n1, unsigned long long int n2) {
	unsigned long long int GCD = findGCD(n1, n2);
	//if(DEBUG) cout<<"GCD = "<<GCD<<endl;
	unsigned long long int LCM = (((n1) * (n2)) / GCD);
	//System.out.println("LCM of " + n1 + " and " + n2 + " is: " + LCM);
	return LCM;
}

unsigned long long int findD(unsigned long long int e, unsigned long long int carM) {
	if (DEBUG) std::cout << "FindD" << std::endl;
	unsigned long long int d = 0;
	while (!(((d * e) % carM) == 1)) {
		d++;
	}
	return d;
}

bool checkPrime(unsigned long long n) {
	double rootN = floor(pow(n, 0.5));
	for (long i = 2; i <= rootN; i++) {
		if (n % 2 == 0) return false;
		if (n % i == 0) return false;
	}
	return true;
}

bool RSA::checkPrime(unsigned long long n) {
	double rootN = floor(pow(n, 0.5));
	for (long i = 2; i <= rootN; i++) {
		if (n % 2 == 0) return false;
		if (n % i == 0) return false;
	}
	return true;
}

//get an e value randomly from created prime vector
unsigned long long int findE(unsigned long long int carM) {
	std::vector<unsigned long long int> primes;
	int totalPrimes = 0;
	for (unsigned long long int i = 2; i < carM && totalPrimes <= 200; ++i) {
		if (DEBUG) std::cout << "Checking " << i << std::endl;
		if (checkPrime(i)) {
			if (DEBUG) std::cout << "Adding #" << totalPrimes << " " << i << std::endl;
			totalPrimes += 1;
			primes.push_back(i);
		}
	}
	std::random_device dev;
	std::mt19937 rng(dev());
	std::uniform_int_distribution<std::mt19937::result_type> dist(0, primes.size() - 1);
	unsigned long long int e = primes.at(dist(rng));
	//reroll e so it's coprime to carM
	while (carM % e == 0) {
		e = primes.at(dist(rng));
	}

	return e;
}

RSA::RSA(unsigned long long int n1, unsigned long long int n2) {
	//initialize first 3 variables
	p = n1;
	q = n2;
	n = p * q;

	//get the carmichael totient value
	unsigned long long int carM = carMFunc(p - 1, q - 1);

	//get the e value
	e = findE(carM);

	if (DEBUG) {
		std::cout << "p: " << p << std::endl;
		std::cout << "q: " << q << std::endl;
		std::cout << "n: " << n << std::endl;
		std::cout << "e: " << e << std::endl;
	}

	//get the d value
	d = findD(e, carM);
}