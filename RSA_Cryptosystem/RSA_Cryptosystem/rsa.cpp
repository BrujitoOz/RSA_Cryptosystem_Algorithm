#include "RSA.h"
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
	delete CrypthoRSA, Option;
	return 0;
}