#pragma once
#include <iostream> 
#include <vector> 
#include <string> 
#include <cstdlib> 
#include <ctime> 
#define N 100000
typedef unsigned long long ull;
using namespace std;
class RSA {
	struct PublicKey {
		ull e, n;
	} MyPublicKey;
	struct PrivateKey {
		ull d, p, q, fi;
	} MyPrivateKey;
	vector<ull> PrimeArray;
	void GeneratePrimesNumber() {
		bool* primo = new bool[N];
		for (unsigned i = 0; i < N; i++)
			primo[i] = true;
		for (unsigned i = 2; i < N; i++) {
			for (unsigned j = 2; i * j < N; j++)
				primo[i * j] = false;
		}
		for (unsigned i = 0; i < N; i++) {
			if (primo[i])
				PrimeArray.push_back(i);
		}
		delete primo;
	}
	bool EuclidesAlgorithm(ull d, ull fi) {
		ull r = 1;
		while (r != 0) {
			r = fi % d;
			fi = d;
			d = r;
		}
		return fi == 1;
	}
	ull Calc_e_Value(ull d, ull fi) {
		ull e;
		for (ull i = 2; i <= fi; i++) {
			if (((i * d) % fi) == 1) {
				e = i;
				break;
			}
		}
		return e;
	}
	ull EncryptOrDecryptFormula(ull code, ull e_or_d_value, ull n) {
		ull ret = 1;
		while (e_or_d_value != 0) {
			if (e_or_d_value % 2 != 0)
				ret = ret * code % n;
			code = code * code % n;
			e_or_d_value /= 2;
		}
		return ret;
	}
public:
	RSA() = default;
	~RSA() = default;
	ull encrypt(PublicKey& puk, ull msg) {
		return EncryptOrDecryptFormula(msg, puk.e, puk.n);
	}
	ull decrypt(PrivateKey& prk, PublicKey& puk, ull c) {
		return EncryptOrDecryptFormula(c, prk.d, puk.n);
	}
	void NewKey() {
		GeneratePrimesNumber();
		srand((unsigned)time(0));
		do {
			MyPrivateKey.p = rand() % (PrimeArray.size() - 1000) + 1000;
			MyPrivateKey.q = rand() % (PrimeArray.size() - 1000) + 1000;
			MyPrivateKey.d = rand() % (PrimeArray.size() - 500) + 500;
		} while (MyPrivateKey.p == MyPrivateKey.q);
		MyPrivateKey.p = PrimeArray[MyPrivateKey.p];
		MyPrivateKey.q = PrimeArray[MyPrivateKey.q];
		MyPrivateKey.d = PrimeArray[MyPrivateKey.d];
		MyPublicKey.n = MyPrivateKey.p * MyPrivateKey.q;
		MyPrivateKey.fi = (MyPrivateKey.p - 1) * (MyPrivateKey.q - 1);
		while (!EuclidesAlgorithm(MyPrivateKey.d, MyPrivateKey.fi))
			++MyPrivateKey.d;
		MyPublicKey.e = Calc_e_Value(MyPrivateKey.d, MyPrivateKey.fi);
	}
	PublicKey GetPublicKey() {
		return MyPublicKey;
	}
	PrivateKey GetPrivateKey() {
		return MyPrivateKey;
	}
	void Information(PublicKey& pu, PrivateKey& pr) {
		cout << endl << endl;
		cout << "p: " << pr.p << endl;
		cout << "q: " << pr.q << endl;
		cout << "fi: " << pr.fi << endl;
		cout << endl;
		cout << "public key:" << endl;
		cout << "e: " << pu.e << endl;
		cout << "n: " << pu.n << endl;
		cout << "private key: " << endl;
		cout << "d: " << pr.d << endl;
		cout << endl << endl;
	}
	void EncryptationMetodRSA(RSA& rsa, PublicKey& pu, PrivateKey& pr) {
		string Message; cout << "\nMessage: " << endl << endl; cin.ignore(); getline(cin, Message);
		vector<ull> vcode; ull code;
		cout << "\nCipher text: " << endl << endl;
		for (ull character : Message) {
			code = rsa.encrypt(pu, (ull)character);
			vcode.push_back(code);
			cout << code << " ";
		}
		cout << endl;
		vector<ull> dcodes;
		cout << "\nDecipher: " << endl;
		cout << "\nCode ASCII: " << endl;
		for (ull c : vcode) {
			code = rsa.decrypt(pr, pu, c);
			dcodes.push_back(code);
			cout << code << " ";
		}
		cout << "\nOriginal Message: " << endl;
		string DecipherMessage;
		for (ull decryptcharacter : dcodes)
			DecipherMessage += (char)decryptcharacter;
		cout << DecipherMessage << endl << endl;
	}
};