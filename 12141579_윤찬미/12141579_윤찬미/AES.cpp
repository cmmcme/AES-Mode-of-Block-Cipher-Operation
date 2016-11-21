#include "AES.h"

// ��ȣȭ �Լ�      (��ȣȭ �� vector, ��� ���� ��ȣȭ ����)
void AES::Encrypt(vector<byte>& plain, int num)
{
	// ������ ��ȣȭ �� byte�� �����ϴ� vector
	vector<vector<byte>> block;

	// 4*4 ��ķ� �ʱ�ȭ
	block.resize(4, vector<byte>(4));

	// ��ȣȭ �� vector ���� ���� ��ȣȭ �� byte�� ��������
	for (int j = 0; j < 4; j++)
		for (int k = 0; k < 4; k += 1)
			block[k][j] = plain[num + (4 * j) + k];

	// AES ��ȣȭ�� ���� (0Round - AddRound key)
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

	// ��ȣȭ�� block�� plain �� �ٽ� ���� �Ѵ�.
	for (int j = 0; j < 4; j++)
		for (int k = 0; k < 4; k++)
			plain[num + 4 * j + k] = block[k][j];

}

// ��ȣȭ �Լ� (��ȣȭ�� cipher, ��𼭺��� ��ȣȭ ����)
void AES::Decrypt(vector<byte>& cipher, int num)
{
	// ��ȣȭ �� blcok 4*4 ���
	vector<vector<byte>> block;
	block.resize(4, vector<byte>(4));

	// block �� ��ȣȭ �� ��ġ���� �ִ� cipher text�� �Ҵ�
	for (int j = 0; j < 4; j++)
		for (int k = 0; k < 4; k += 1)
			block[k][j] = cipher[num + (4 * j) + k];

	// ��ȣȭ ����
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

	// ��ȣȭ�� block�� �ٽ� cipher�� �Ҵ�
	for (int j = 0; j < 4; j++)
		for (int k = 0; k < 4; k++)
			cipher[num + 4 * j + k] = block[k][j];
}

// SubstituteByte 
void AES::SubstituteBytes(vector<vector<byte>> &block)
{
	// SBox�� �̿��� ġȯ�Ѵ�
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
	// ���ϱ� �ϱ����� temp = block 
	vector<vector<byte>> temp = block;

	// block �ʱ�ȭ
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			block[i][j] = 0;

	// Multiple �� XOR
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			for (int k = 0; k < 4; k++)
				block[i][j] ^= Multiple(MC_MATRIX[i][k], temp[k][j]);

}
// AddRoundKey
void AES::AddRoundKey(vector<vector<byte>> &block, byte Round)
{
	// KeyExpansion�� �̿��� ���� Key �� XOR
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			block[j][i] = block[j][i] ^ (w[Round * 4 + i] >> (8 * (3 - j)));
}

word AES::rotWord(word wd)
{
	// KeyExpansion�� ���Ǵ� Rotation
	word ret;
	ret = (wd >> 24) | (wd << 8);
	return ret;
}

word AES::subWord(word wd)
{
	// KeyExpansion�� ���Ǵ� S-Box ����
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
	// 0~3��° Word�� 16����Ʈ Key�� 4����Ʈ�� ������ �� ��
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			w[i] <<= 8;
			w[i] |= key[(i * 4) + j];
		}
	}
	/* 3��° Word�� Rotation�� Sbox�� �̿��� �ٲ� ��
	Word�� 0��° byte�� Rcon�� XOR
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
	// Galois Field �μ����ذ� �ȵǴ� ���׽�
	byte norm = (1 << 4) + (1 << 3) + (1 << 1) + 1;

	// �� byte�� XOR �� �� ������ ����� Galois Field�� �̿��Ͽ� Congruence �� �̿�
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
	// �Լ��� ���� ���� Inverse S-Box�� �����Ͽ� ġȯ��
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
	// ���ϱ� �ϱ����� temp = block 
	vector<vector<byte>> temp = block;

	// block �ʱ�ȭ
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			block[i][j] = 0;

	// Multiple �� XOR
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			for (int k = 0; k < 4; k++)
				block[i][j] ^= Multiple(IMC_MATRIX[i][k], temp[k][j]);
}

// �ֻ��� ��Ʈ�� ��ġ�� ���ϴ� �Լ�
int AES::getMSB(int a)
{
	for (int i = 8; i >= 0; i--)
		if (a & (1 << i))
			return i;
	return 0;
}

// Mod - Ȯ����Ŭ���� ���� ��, �ʿ��� Mod ���� ���ϴ� �Լ�
int AES::Mod(int a, int b, int &q)
{
	// q�� ��
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
	// Mod�� �̿��Ͽ� �������� ���� �� ��������� Ž��
	int q;
	int r = Mod(a, b, q);
	if (r == 0) return Solution{ 0, 1 };
	Solution s = ExtendedEuclid(b, r);
	return Solution{ s.y, s.x ^ Multiple(q, s.y) };
}

// GetInverseElement
byte AES::getInverseElement(byte b)
{
	// Ȯ����Ŭ���带 ���� ������ ���Ѵ�.
	int a = (1 << 8) | (1 << 4) | (1 << 3) | (1 << 1) | 1;
	return ExtendedEuclid(a, (int)b).y;
}

// SBox, InverseSBox �� ����� �Լ�
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