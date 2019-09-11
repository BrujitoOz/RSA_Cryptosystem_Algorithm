#include <iostream> 
#include <vector> 
#include <string> 
#include <cstdlib> 
#include <ctime> 
using namespace std;
class RSA {
	struct PublicKey {
		long long e;
		long long n;
	};
	struct PrivateKey {
		long long d;
		long long p;
		long long q;
	};
	long long p, q, n, e, d;
	PublicKey MyPublicKey;
	PrivateKey MyPrivateKey;
	vector<long long> PrimeArray;
	void GeneratePrimesNumber() {
		bool* primo = new bool[50000];
		for (unsigned i = 0; i < 50000; i++)
			primo[i] = true;
		for (unsigned i = 2; i < 50000; i++) {
			for (unsigned j = 2; i * j < 50000; j++)
				primo[i * j] = false;
		}
		for (unsigned i = 0; i < 50000; i++) {
			if (primo[i])
				PrimeArray.push_back(i);
		}
		delete primo;
	}
	long long CalcEuler(long long p, long long q) {
		return (p - 1) * (q - 1);
	}
	bool EuclidesAlgorithm(long long e, long long fi) {
		long long r1, r2, r3 = 1;
		if (e < fi) {
			r1 = e;
			r2 = fi;
		}
		else {
			r1 = fi;
			r2 = e;
		}
		while (r3 != 0) {
			r3 = r2 % r1;
			r2 = r1;
			r1 = r3;
		}
		return r2 == 1;
	}
	long long Calc_d_Value(long long e, long long fi) {
		long long d;
		for (long long i = 2; i <= fi; i++) {
			long long temp = (i * e) % fi;
			if (temp == 1) {
				d = i;
				break;
			}
		}
		return d;
	}
	long long EncryptOrDecryptFormula(long long code, long long e_or_d_value, long long n) {
		long long ret = 1;
		long long tmp = code;
		while (e_or_d_value != 0) {
			if (e_or_d_value % 2 != 0)
				ret = ret * tmp % n;
			tmp = tmp * tmp % n;
			e_or_d_value /= 2;
		}
		return ret;
	}
public:
	RSA() = default;
	~RSA() = default;
	long long encrypt(PublicKey& puk, long long msg) {
		return EncryptOrDecryptFormula(msg, puk.e, puk.n);
	}
	long long decrypt(PrivateKey& prk, PublicKey& puk, long long c) {
		return EncryptOrDecryptFormula(c, prk.d, puk.n);
	}
	void NewKey() {
		GeneratePrimesNumber();
		srand((unsigned)time(0));
		do {
			p = rand() % (PrimeArray.size() - 1000) + 1000;
			q = rand() % (PrimeArray.size() - 1000) + 1000;
		} while (p == q);
		p = PrimeArray[p];
		q = PrimeArray[q];
		n = p * q;
		long long fi = CalcEuler(p, q);
		e = 23;
		while (!EuclidesAlgorithm(e, fi))
			++e;
		d = Calc_d_Value(e, fi);
		MyPublicKey.e = e;
		MyPublicKey.n = n;
		MyPrivateKey.d = d;
		MyPrivateKey.p = p;
		MyPrivateKey.q = q;
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
		cout << "fi: " << (pr.p - 1) * (pr.q - 1) << endl;
		cout << endl;
		cout << "public key:" << endl;
		cout << "e: " << pu.e << endl;
		cout << "n: " << pu.n << endl;
		cout << "private key: " << endl;
		cout << "d: " << pr.d << endl;
		cout << endl << endl;
	}
	void EncryptationMetodRSA(RSA& rsa, PublicKey& pu, PrivateKey& pr) {
		string Message;
		cout << "\nMessage: " << endl << endl; cin.ignore(); getline(cin, Message);
		vector<long long> vcode;
		long long code;
		cout << "\nCipher text: " << endl << endl;
		for (long long character : Message) {
			code = rsa.encrypt(pu, (long long)character);
			vcode.push_back(code);
			cout << code << " ";
		}
		cout << endl;
		vector<long long> dcodes;
		cout << "\nDecipher: " << endl;
		cout << "\nCode ASCII: " << endl;
		for (long long c : vcode) {
			code = rsa.decrypt(pr, pu, c);
			dcodes.push_back(code);
			cout << code << " ";
		}
		cout << "\nOriginal Message: " << endl;
		string DecipherMessage;
		for (long long decryptcharacter : dcodes)
			DecipherMessage += (char)decryptcharacter;
		cout << DecipherMessage << endl << endl;
	}
};
void menu(RSA* CrypthoRSA, int* Option) {
	while (true) {
		cout << "1.- Encrypt: " << endl;
		cout << "2.- Show values: " << endl;
		cout << "3.- Generate new key: " << endl;
		cout << "4.- Close" << endl;
		cout << "Option: "; cin >> *Option;
		if (*Option == 1)
			CrypthoRSA->EncryptationMetodRSA(*CrypthoRSA, CrypthoRSA->GetPublicKey(), CrypthoRSA->GetPrivateKey());
		if (*Option == 2)
			CrypthoRSA->Information(CrypthoRSA->GetPublicKey(), CrypthoRSA->GetPrivateKey());
		if (*Option == 3)
			CrypthoRSA->NewKey();
		if (*Option == 4)
			break;
	}
}
int main() {
	RSA* CrypthoRSA = new RSA();
	int* Option = new int;
	CrypthoRSA->NewKey();
	menu(CrypthoRSA, Option);
	delete CrypthoRSA;
	delete Option;
	return 0;
}