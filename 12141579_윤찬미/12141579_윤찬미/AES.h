#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
using namespace std;

typedef unsigned char byte;
typedef unsigned int word;

struct Solution { int x, y; };

class AES
{
public:
	// AES Class 생성자
	AES(vector<byte> key) {
		// S-Box, ISbox 초기화
		memset(Sbox, 0, sizeof(0));
		memset(ISbox, 0, sizeof(0));

		//SBox를 만드는 함수
		getSBOX();
		//Key확장 함수
		KeyExpansion(key);
	}
	//암호화
	void Encrypt(vector<byte>&, int);
	//복호화
	void Decrypt(vector<byte>&, int);
private:
	word w[44];	// 44개의 KEY word
	word Rcon[11] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };	//Key 확장 함수에서 XOR 할 RCon

																							// Mixcolumn matrix
	const byte MC_MATRIX[4][4] = {
		{ 0x02, 0x03, 0x01, 0x01 },
		{ 0x01, 0x02, 0x03, 0x01 },
		{ 0x01, 0x01, 0x02, 0x03 },
		{ 0x03, 0x01, 0x01, 0x02 } };

	// Inverse Mixcolumn matrix
	const byte IMC_MATRIX[4][4] = {
		{ 0x0E, 0x0B, 0x0D, 0x09 },
		{ 0x09, 0x0E, 0x0B, 0x0D },
		{ 0x0D, 0x09, 0x0E, 0x0B },
		{ 0x0B, 0x0D, 0x09, 0x0E } };

	//SBox matrix
	int Sbox[256];
	//Inverse SBox matrix
	int ISbox[256];

	//SBox를 구하기 위해 곱해지는 행렬
	const byte COLUMN_VECTOR = 0x63;

	//SBox를 구하기 위해 XOR되는 행렬
	const byte SUBTI_MATRIX[8] = { 0x8F, 0xC7, 0xE3, 0xF1, 0xF8, 0x7C, 0x3E, 0x1F };

private:
	void SubstituteBytes(vector<vector<byte>>&);	//SBox
	void ShiftRow(vector<vector<byte>>&);			//Shift Row
	void MixColumn(vector<vector<byte>>&);			//MixColumn
	void AddRoundKey(vector<vector<byte>>&, byte);	//AddRoundKey
	void InverseSubstituteBytes(vector<vector<byte>>&);	//Inverse SBox 
	void InverseShiftRow(vector<vector<byte>>&);		//Inverse Shift Row
	void InverseMixColumn(vector<vector<byte>>&);		//Inverse MixColumn
	word rotWord(word);									// Key Expansion - byte Rotation 
	word subWord(word);									// Key Expansion - S-Box
	void KeyExpansion(const vector<byte>&);				// Key Expansion
	byte Multiple(byte, byte);							// MixColumn - Multiple
	int getMSB(int);									// 최상위 비트의 위치를 구하는 함수
	int Mod(int, int, int&);							// 확장 유클리드 시 필요한 나머지 값
	Solution ExtendedEuclid(int, int);					// 역원을 구하기 위한 확장 유클리드
	byte getInverseElement(byte);						// 확장유클리드를 이용하여 역원을 구한 후 Galois Field
	void getSBOX();										// S-Box
};