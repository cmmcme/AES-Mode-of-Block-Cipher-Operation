#include "AES.h"

// 파일입출력을 도와주는 함수
vector<byte> inputFile(FILE *file)
{
	vector<byte> input;

	// file을 1byte씩 읽어서 vector에 넣어줌
	while (!feof(file))
	{
		byte in = fgetc(file);
		input.push_back(in);
	}
	return input;
}

// CTR mode에서 counter를 1씩 증가 시키기 위한 함수
void increase(vector < byte >& counter)
{
	for (int i = 0; i < counter.size(); i++)
		printf("%02X ", counter[i]);
	puts("");
	// 0번쨰 byte부터 증가 시켜줌
	for (int i = counter.size() - 1; i >= 0; i--)
	{
		counter[i]++;
		if (counter[i] != 0)
			break;
	}

	for (int i = 0; i < counter.size(); i++)
		printf("%02X ", counter[i]);
	puts("");
}

int main(int argc, char *argv[])
{
	// key, initial, plaintext, ciphertext
	vector<byte> key(16), initial(16), plain, cipher;
	// key 파일 입출력
	FILE* key_fp;
	key_fp = fopen("key.bin", "rb");
	/* 상위 16바이트 = key
	하위 16바이트 = initial
	*/
	for (int i = 0; i < 16; i++)
		key[i] = fgetc(key_fp);

	for (int i = 0; i < 16; i++)
		initial[i] = fgetc(key_fp);

	// AES 생성자 호출
	AES aes(key);

	// key 파일 닫음
	fclose(key_fp);

	// E = Encrypt
	if (argv[1][0] == 'e')
	{
		FILE *ecb_c, *cbc_c, *cfb_c, *ofb_c, *ctr_c;
		FILE *ecb_p, *cbc_p, *cfb_p, *ofb_p, *ctr_p;

		// ECB Encrypt
		ecb_p = fopen("ecb_p.bin", "rb");
		ecb_c = fopen("ecb_c.bin", "wb+");
		plain = inputFile(ecb_p);
		fclose(ecb_p);
		plain.resize(plain.size() - (plain.size() % 16));

		// plaintext를 16byte씩 쪼개서 암호화 
		for (int i = 0; i < plain.size(); i += 16)
			aes.Encrypt(plain, i);

		puts("ECB Mode :");
		for (int i = 0; i < plain.size(); i++) {
			printf("%02x ", plain[i]);
			fputc(plain[i], ecb_c);
		}
		fclose(ecb_c);

		// CBC Encrypt
		cbc_p = fopen("cbc_p.bin", "rb");
		cbc_c = fopen("cbc_c.bin", "wb+");
		plain = inputFile(cbc_p);
		fclose(cbc_p);
		plain.resize(plain.size() - (plain.size() % 16));

		// 상위 16byte plaintext ^ initial vector
		for (int i = 0; i < 16; i++)
			plain[i] ^= initial[i];

		// 16byte plaintext Encrypt
		aes.Encrypt(plain, 0);

		// 직전에 암호화된 16byte의 plaintext와 XOR후 Encrypt
		for (int i = 16; i < plain.size(); i += 16)
		{
			for (int j = i; j < i + 16; j++)
			{
				plain[j] ^= plain[j - 16];
			}
			aes.Encrypt(plain, i);
		}

		for (int i = 0; i < plain.size(); i++) {
			fputc(plain[i], cbc_c);
		}
		fclose(cbc_c);

		//CFB Encrypt
		vector<byte> CFBinitial = initial;

		cfb_p = fopen("cfb_p.bin", "rb");
		cfb_c = fopen("cfb_c.bin", "wb+");
		plain = inputFile(cfb_p);
		fclose(cfb_p);

		plain.resize(plain.size() - (plain.size() % 16));

		// initial을 Encrypt 한 후, plaintext와 XOR
		// cipher = initial이 된다
		for (int i = 0; i < plain.size(); i += 16)
		{
			aes.Encrypt(CFBinitial, 0);

			for (int j = i; j < i + 16; j++)
			{
				plain[j] ^= CFBinitial[j % 16];
				CFBinitial[j % 16] = plain[j];
			}

		}
		for (int i = 0; i < plain.size(); i++)
			fputc(plain[i], cfb_c);


		fclose(cfb_c);

		// OFB Encrypt
		// Nonce = initial
		vector<byte> OFBinitial = initial;

		ofb_p = fopen("ofb_p.bin", "rb");
		ofb_c = fopen("ofb_c.bin", "wb+");
		plain = inputFile(ofb_p);
		fclose(ofb_p);
		plain.resize(plain.size() - (plain.size() % 16));

		// Nonce를 Encrypt 한 후 다음 Nonce = Encrypt한 Nonce
		for (int i = 0; i < plain.size(); i += 16)
		{
			aes.Encrypt(OFBinitial, 0);

			for (int j = i; j < i + 16; j++)
			{
				// cipher = Encrypt(Nonce) ^ plain
				plain[j] ^= OFBinitial[j % 16];
			}
		}
		for (int i = 0; i < plain.size(); i++)
			fputc(plain[i], ofb_c);

		fclose(ofb_c);

		// CTR Encrypt
		// counter = initial
		vector<byte> CTRinitial = initial;

		ctr_p = fopen("ctr_p.bin", "rb");
		ctr_c = fopen("ctr_c.bin", "wb+");
		plain = inputFile(ctr_p);

		plain.resize(plain.size() - (plain.size() % 16));

		// Counter Encrypt 후 plain과 XOR
		// Counter은 블록마다 1씩 증가
		for (int i = 0; i < plain.size(); i += 16)
		{
			aes.Encrypt(initial, 0);
			for (int j = i; j < i + 16; j++)
				plain[j] ^= initial[j % 16];

			increase(CTRinitial);
			initial = CTRinitial;
		}

		for (int i = 0; i < plain.size(); i++)
			fputc(plain[i], ctr_c);

		fclose(ctr_c);

	}


	// D = Decrypt
	if (argv[1][0] == 'd')
	{
		FILE *ecb_c, *cbc_c, *cfb_c, *ofb_c, *ctr_c;
		FILE *ecb_p, *cbc_p, *cfb_p, *ofb_p, *ctr_p;

		// ECB Decrypt
		ecb_c = fopen("ecb_c.bin", "rb");
		ecb_p = fopen("ecb_p.bin", "wb+");
		cipher = inputFile(ecb_c);
		fclose(ecb_c);
		cipher.resize(cipher.size() - (cipher.size() % 16));

		// cipertext 를 16byte씩 Decrypt
		for (int i = 0; i < cipher.size(); i += 16)
			aes.Decrypt(cipher, i);

		for (int i = 0; i < cipher.size(); i++)
			fputc(cipher[i], ecb_p);

		fclose(ecb_p);

		// CBC Decrypt

		cbc_c = fopen("cbc_c.bin", "rb");
		cbc_p = fopen("cbc_p.bin", "wb+");
		cipher = inputFile(cbc_c);
		fclose(cbc_c);

		vector<byte> CBCcipher = cipher;
		cipher.resize(cipher.size() - (cipher.size() % 16));

		// cipher Decrypt
		aes.Decrypt(cipher, 0);

		for (int i = 0; i < 16; i++)
			cipher[i] ^= initial[i];

		// Decrypt 후 그 전의 Cipertext block와 XOR
		for (int i = 16; i < cipher.size(); i += 16)
		{
			aes.Decrypt(cipher, i);
			for (int j = i; j < i + 16; j++)
				cipher[j] ^= CBCcipher[j - 16];

		}

		for (int i = 0; i < cipher.size(); i++)
			fputc(cipher[i], cbc_p);

		fclose(cbc_p);

		// CFB Decrypt
		vector<byte> CFBinitial = initial;
		vector<byte> CFBCiper;
		cfb_c = fopen("cfb_c.bin", "rb");
		cfb_p = fopen("cfb_p.bin", "wb+");
		cipher = inputFile(cfb_c);
		fclose(cfb_c);

		cipher.resize(cipher.size() - (cipher.size() % 16));

		CFBCiper = cipher;

		// initial을 Encrypt 한 후, ciphertext와 XOR
		// 원래 cipher = initial이 된다 => 그래서 예전 ciper를 따로 저장해놨음
		for (int i = 0; i < cipher.size(); i += 16)
		{
			aes.Encrypt(CFBinitial, 0);

			for (int j = i; j < i + 16; j++)
			{
				cipher[j] ^= CFBinitial[j % 16];
				CFBinitial[j % 16] = CFBCiper[j];
			}

		}
		for (int i = 0; i < cipher.size(); i++)
			fputc(cipher[i], cfb_p);

		fclose(cfb_p);

		// OFB Decrypt
		// Nonce = initial
		vector<byte> OFBinitial = initial;

		ofb_c = fopen("ofb_c.bin", "rb");
		ofb_p = fopen("ofb_p.bin", "wb+");
		cipher = inputFile(ofb_c);
		fclose(ofb_c);
		cipher.resize(cipher.size() - (cipher.size() % 16));

		// Nonce를 Encrypt 한 후 다음 Nonce = Encrypt한 Nonce
		for (int i = 0; i < cipher.size(); i += 16)
		{
			aes.Encrypt(OFBinitial, 0);

			for (int j = i; j < i + 16; j++)
			{
				cipher[j] ^= OFBinitial[j % 16];
			}
		}

		for (int i = 0; i < cipher.size(); i++)
			fputc(cipher[i], ofb_p);

		fclose(ofb_p);

		// CTR Decrypt
		// counter = initial
		vector<byte> CTRinitial = initial;

		ctr_c = fopen("ctr_c.bin", "rb");
		ctr_p = fopen("ctr_p.bin", "wb+");

		cipher = inputFile(ctr_c);
		fclose(ctr_c);
		cipher.resize(cipher.size() - (cipher.size() % 16));

		// Counter Encrypt 후 cipher과 XOR
		// Counter은 블록마다 1씩 증가
		for (int i = 0; i < cipher.size(); i += 16)
		{
			aes.Encrypt(initial, 0);
			// plain = Encrypt(Nonce) ^ cipher
			for (int j = i; j < i + 16; j++)
				cipher[j] ^= initial[j % 16];

			increase(CTRinitial);
			initial = CTRinitial;
		}

		for (int i = 0; i < cipher.size(); i++)
			fputc(cipher[i], ctr_p);

		fclose(ctr_p);
	}
	return 0;

}