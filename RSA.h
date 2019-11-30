#pragma once
#ifndef RSA_H
#define RSA_H

class RSA {
private:
	unsigned long long int p, q, n, e, d;
public:
	RSA(unsigned long long int num1, unsigned long long int num2);
	unsigned long long int encrypt(unsigned long long int m, unsigned long long int e, unsigned long long int n);
	unsigned long long int decrypt(unsigned long long int c, unsigned long long int d, unsigned long long int n);

	bool checkPrime(unsigned long long n);

	unsigned long long int get_p() { return p; }
	unsigned long long int get_q() { return q; }
	unsigned long long int get_n() { return n; }
	unsigned long long int get_e() { return e; }
	unsigned long long int get_d() { return d; }
};

#endif