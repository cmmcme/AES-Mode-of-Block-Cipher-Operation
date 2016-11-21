#include "AES.h"

// 암호화 함수      (암호화 할 vector, 어디서 부터 암호화 할지)
void AES::Encrypt(vector<byte>& plain, int num)
{
	// 실제로 암호화 될 byte를 저장하는 vector
	vector<vector<byte>> block;

	// 4*4 행렬로 초기화
	block.resize(4, vector<byte>(4));

	// 암호화 할 vector 에서 실제 암호화 할 byte를 저장해줌
	for (int j = 0; j < 4; j++)
		for (int k = 0; k < 4; k += 1)
			block[k][j] = plain[num + (4 * j) + k];

	// AES 암호화의 과정 (0Round - AddRound key)
	AddRoundKey(block, 0);

	// 1~9 Round = SBox - ShiftRow - MixColumn - AddRoundKey
	for (int i = 1; i <= 9; i++)
	{
		SubstituteBytes(block);
		ShiftRow(block);
		MixColumn(block);
		AddRoundKey(block, i);
	}
	// 10 Round = SBox - ShiftRow - AddRoundKey
	SubstituteBytes(block);
	ShiftRow(block);
	AddRoundKey(block, 10);

	// 암호화된 block를 plain 에 다시 적용 한다.
	for (int j = 0; j < 4; j++)
		for (int k = 0; k < 4; k++)
			plain[num + 4 * j + k] = block[k][j];

}

// 복호화 함수 (복호화할 cipher, 어디서부터 복호화 할지)
void AES::Decrypt(vector<byte>& cipher, int num)
{
	// 복호화 할 blcok 4*4 행렬
	vector<vector<byte>> block;
	block.resize(4, vector<byte>(4));

	// block 에 복호화 할 위치부터 있는 cipher text를 할당
	for (int j = 0; j < 4; j++)
		for (int k = 0; k < 4; k += 1)
			block[k][j] = cipher[num + (4 * j) + k];

	// 복호화 과정
	// 10 Round = AddRoundKey 
	AddRoundKey(block, 10);

	// 9~1 Round = InverseShiftRow - InverseSubtituteByte - AddRoundKey - InverseMixColumn
	for (int i = 9; i >= 1; i--)
	{
		InverseShiftRow(block);
		InverseSubstituteBytes(block);
		AddRoundKey(block, i);
		InverseMixColumn(block);
	}

	// 0 Round =  InverseShiftRow - InverseSubtituteByte - AddRoundKey
	InverseShiftRow(block);
	InverseSubstituteBytes(block);
	AddRoundKey(block, 0);

	// 복호화된 block를 다시 cipher에 할당
	for (int j = 0; j < 4; j++)
		for (int k = 0; k < 4; k++)
			cipher[num + 4 * j + k] = block[k][j];
}

// SubstituteByte 
void AES::SubstituteBytes(vector<vector<byte>> &block)
{
	// SBox를 이용해 치환한다
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			block[i][j] = Sbox[block[i][j]];
}

// ShiftRow
void AES::ShiftRow(vector<vector<byte>> &block)
{
	byte temp;

	/*
	0 Row = 0 shift
	1 Row = Left 1 shift
	2 Row = Left 2 shift
	3 Row = Left 3 shift
	*/
	temp = block[1][0];
	for (int i = 1; i < 4; i++)
		block[1][i - 1] = block[1][i];

	block[1][3] = temp;

	temp = block[2][0];
	block[2][0] = block[2][2];
	block[2][2] = temp;

	temp = block[2][1];
	block[2][1] = block[2][3];
	block[2][3] = temp;

	temp = block[3][3];
	for (int i = 3; i >= 0; i--)
		block[3][i] = block[3][(i + 3) % 4];

	block[3][0] = temp;
}

// MixColumn
void AES::MixColumn(vector<vector<byte>> &block)
{
	// 곱하기 하기위해 temp = block 
	vector<vector<byte>> temp = block;

	// block 초기화
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			block[i][j] = 0;

	// Multiple 후 XOR
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			for (int k = 0; k < 4; k++)
				block[i][j] ^= Multiple(MC_MATRIX[i][k], temp[k][j]);

}
// AddRoundKey
void AES::AddRoundKey(vector<vector<byte>> &block, byte Round)
{
	// KeyExpansion을 이용해 만든 Key 와 XOR
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			block[j][i] = block[j][i] ^ (w[Round * 4 + i] >> (8 * (3 - j)));
}

word AES::rotWord(word wd)
{
	// KeyExpansion시 사용되는 Rotation
	word ret;
	ret = (wd >> 24) | (wd << 8);
	return ret;
}

word AES::subWord(word wd)
{
	// KeyExpansion시 사용되는 S-Box 연산
	word ret = 0, and = 0xff;
	for (int i = 0; i < 4; i++)
	{
		word temp = wd & (and << (8 * i));
		temp >>= (8 * i);
		ret |= Sbox[temp] << (8 * i);
	}
	return ret;
}

// KeyExpansion
void AES::KeyExpansion(const vector<byte> &key)
{
	// 0~3번째 Word는 16바이트 Key를 4바이트씩 가지고 온 것
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			w[i] <<= 8;
			w[i] |= key[(i * 4) + j];
		}
	}
	/* 3번째 Word를 Rotation과 Sbox를 이용해 바꾼 후
	Word의 0번째 byte는 Rcon과 XOR
	*/
	word temp;
	for (int i = 4; i < 44; i++)
	{
		temp = w[i - 1];
		if (i % 4 == 0)
			temp = subWord(rotWord(temp)) ^ (Rcon[i / 4] << 24);

		w[i] = w[i - 4] ^ temp;
	}
}

// Multiple
byte AES::Multiple(byte b1, byte b2)
{
	byte ret = 0;
	// Galois Field 인수분해가 안되는 다항식
	byte norm = (1 << 4) + (1 << 3) + (1 << 1) + 1;

	// 두 byte를 XOR 한 후 범위를 벗어나면 Galois Field를 이용하여 Congruence 값 이용
	for (int i = 0; i < 8; i++)
	{
		if (b2 & (1 << i))
			ret ^= b1;

		if (b1 & (1 << 7))
		{
			b1 <<= 1;
			b1 ^= norm;
		}
		else
			b1 <<= 1;
	}

	return ret;
}

// Inverse S-Box
void AES::InverseSubstituteBytes(vector<vector<byte>> &block)
{
	// 함수를 통해 만든 Inverse S-Box를 적용하여 치환함
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			block[i][j] = ISbox[block[i][j]];
}

void AES::InverseShiftRow(vector<vector<byte>> &block)
{
	/*
	0 Row = 0 shift
	1 Row = Right 1 shift
	2 Row = Right 2 shift
	3 Row = Right 3 shift
	*/

	byte temp;
	temp = block[1][3];
	for (int i = 3; i > 0; i--)
		block[1][i] = block[1][(i + 3) % 4];
	block[1][0] = temp;

	temp = block[2][0];
	block[2][0] = block[2][2];
	block[2][2] = temp;

	temp = block[2][1];
	block[2][1] = block[2][3];
	block[2][3] = temp;

	temp = block[3][0];
	for (int i = 1; i < 4; i++)
		block[3][i - 1] = block[3][i];

	block[3][3] = temp;
}

// InverseMixColumn
void AES::InverseMixColumn(vector<vector<byte>> &block)
{
	// 곱하기 하기위해 temp = block 
	vector<vector<byte>> temp = block;

	// block 초기화
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			block[i][j] = 0;

	// Multiple 후 XOR
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			for (int k = 0; k < 4; k++)
				block[i][j] ^= Multiple(IMC_MATRIX[i][k], temp[k][j]);
}

// 최상위 비트의 위치를 구하는 함수
int AES::getMSB(int a)
{
	for (int i = 8; i >= 0; i--)
		if (a & (1 << i))
			return i;
	return 0;
}

// Mod - 확장유클리드 연산 시, 필요한 Mod 값을 구하는 함수
int AES::Mod(int a, int b, int &q)
{
	// q는 몫
	q = 0;
	int ret = 0;
	while (a)
	{
		int MaxBitA = getMSB(a);
		int MaxBitB = getMSB(b);
		if (MaxBitA < MaxBitB) break;
		int exp = MaxBitA - MaxBitB;
		q |= 1 << exp;
		a = a ^ (b << exp);
	}
	return a;
}

// ExtendedEuclid
Solution AES::ExtendedEuclid(int a, int b)
{
	// Mod를 이용하여 나머지를 구한 뒤 재귀적으로 탐색
	int q;
	int r = Mod(a, b, q);
	if (r == 0) return Solution{ 0, 1 };
	Solution s = ExtendedEuclid(b, r);
	return Solution{ s.y, s.x ^ Multiple(q, s.y) };
}

// GetInverseElement
byte AES::getInverseElement(byte b)
{
	// 확장유클리드를 통해 역원을 구한다.
	int a = (1 << 8) | (1 << 4) | (1 << 3) | (1 << 1) | 1;
	return ExtendedEuclid(a, (int)b).y;
}

// SBox, InverseSBox 를 만드는 함수
void AES::getSBOX()
{
	byte fx = 0;
	while (1)
	{
		byte gx = 0;
		if (fx != 0) gx = getInverseElement(fx);

		byte state = 0;
		for (int j = 0; j < 8; j++)
		{
			byte bit = (COLUMN_VECTOR >> j) & 1;
			for (int k = 0; k < 8; k++)
				bit ^= ((SUBTI_MATRIX[j] >> k) & 1) & ((gx >> (7 - k)) & 1);

			state |= (bit << j);
		}
		Sbox[fx] = state;
		ISbox[state] = fx;
		if (fx == 0xff) break;
		fx++;
	}
}