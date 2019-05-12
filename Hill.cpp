/*
 * Hill.cpp
 *
 *  Created on: 2018年12月24日
 *      Author: Administrator
 */

#include<iostream>
#include <string>
#include <memory.h>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <windows.h>
using namespace std;


//行和列均为4
const int ROW =4;
const int COL =4;


int K[ROW][COL];//密钥矩阵
int N[ROW][COL];//逆矩阵
int C[ROW];//密文矩阵
int P[ROW];//明文矩阵
int temp[ROW]; //temp matrix, used in calculation

class Hill_Cipher
{
public:

	//求矩阵的行列式
	int Det(int matrix[ROW][ROW], int row);

	//矩阵相乘
	int* multiphy(int B[ROW][ROW], int A[ROW], int row);

	//求出伴随矩阵
	int fun(int matrix[ROW][ROW], int row);

	//将明文加密为密文
	string encryption(string plaintext);

	//将密文解密为明文(为了辨识清楚,我们统一以小写字母作为明文,大写字母作为密文)
	string deciphering(string ciphertext);
	//模26
	int Mod(int a);

private:

};

int Hill_Cipher::Mod(int a)
{
	return a >= 0 ? a % 26 : (26+ a % 26);
}
//求矩阵的行列式
int Hill_Cipher::Det(int matrix[ROW][ROW], int row)
{
	int i, j;
	int cofa[ROW][ROW];            //用于存放余子阵
	int l;   //l为所递归的余子阵的行
	int p = 0, q = 0;
	int sum = 0;

	//递归基
	if (row == 1)
		return matrix[0][0];
	for (i = 0; i < row; i++)
	{
		for (l = 0; l < row - 1; l++)
		{
			if (l < i)
				p = 0;
			else
				p = 1;
			for (j = 0; j < row - 1; j++)
			{
				cofa[l][j] = matrix[l + p][j + 1];
			}
		}
		//相当于(-1)^i
		if (i % 2 == 0)
			q = 1;
		else
			q = (-1);
		sum = sum + matrix[i][0] * q * Det(cofa, row - 1);
	}
	return sum;
}
//矩阵相乘
int* Hill_Cipher::multiphy(int B[ROW][ROW], int A[ROW], int row)
{
	int i, j;
	int Q[ROW];
	//先将单元清零
//	memset(Q, 0, sizeof(Q));
	for (i = 0; i < ROW; i++)
	{
		for (j = 0; j < ROW; j++)
		{
			temp[i] += A[j] * B[j][i];
			Q[i] +=A[j] * B[j][i];
		}
	}
	return Q;
}
//求伴随矩阵
int Hill_Cipher::fun(int matrix[ROW][ROW], int row)
{
	int i, j, k, l;
	int p, q;
	p = q = 0;
	int ban = 0;
	int temp[ROW][ROW];
	for (i = 0; i < ROW; i++)
	{
		for (j = 0; j < ROW; j++)
		{
			for (k = 0; k < ROW - 1; k++)
			{
				if (k < i)
					p = 0;
				else
					p = 1;
				for (l = 0; l < ROW - 1; l++)
				{
					if (l < j)
						q = 0;
					else
						q = 1;
					temp[k][l] = matrix[k + p][l + q];
				}
			}
			N[j][i] = (int)pow(-1, i + j)*Det(temp, ROW - 1);

		}
	}
	return ban;
}

//将明文加密为密文
string Hill_Cipher::encryption(string plaintext)
{
	int i;


	string ciphertext;
	//将字符串转化为明文数组
	for (i = 0; i < ROW; i++)
	{
		P[i] = plaintext[i] - 'a';
	}
	multiphy(K, P, ROW);
	//将密文数组转化为密文
	for (i = 0; i < ROW; i++)
		//这里先将其模26,再翻译为对应的字母
	{
		temp[i] = Mod(temp[i]);
		ciphertext += temp[i]  + 'A';
	}
	return ciphertext;
}


//将密文解密为明文(为了辨识清楚,我们统一以小写字母作为明文,大写字母作为密文)
string Hill_Cipher::deciphering(string ciphertext)
{


	//求出矩阵的逆
	string text;
	int NI;
	//先求伴随矩阵
	NI=(fun(K, ROW)/ Det(K, ROW));//求密钥的逆矩阵N
	int i;
	//将字符串转化为密文数组
	for (i = 0; i < ROW; i++)
	{
		C[i] = text[i] - 'a';
	}
	multiphy(N, C, ROW);
	//将明文数组转化为明文
	for (i = 0; i < ROW; i++)
		//这里先将其模26,再翻译为对应的字母
	{
		P[i] = Mod(P[i]);
		text += P[i]  + 'A';
	}
	return text;

}



int main()
{
	string plaintext, ciphertext;
	Hill_Cipher hh;
	string PN;//已知明文的逆矩阵
	string fullc;//剩余密文
	string fullp;//剩余明文
	string partc;//部分密文
	int partp[ROW][ROW];//部分明文
	int b;
	int det = -1;     //计算K的行列式的值

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			K[i][j] = i * 4 + j + 1;
		}
		cout << endl;
	}

	while(1)
	{
		cout << "===============================================================" << endl;
		cout << "***************************************************************" << endl;
		cout << "********      欢迎进入hill密码的可视化及其        *************" << endl;
		cout << "********           已知明文攻击的实现             *************" << endl;
		cout << "********  请输入你的选择：                        *************" << endl;
		cout << "******** 1.用hill密码进行加密                     *************" << endl;
		cout << "******** 2.用hill密码进行解密                     *************" << endl;
		cout << "******** 3.用已知明文攻击破解密文                 *************" << endl;
		cout << "******** 4.退出                                   *************" << endl;
		cout << "***************************************************************" << endl;
		cout << "===============================================================" << endl;
		cin >> b;
		cin.clear();
		cin.sync();
		switch (b)
		{
		case 1:

				cout << "下面进行hill密码加密......" << endl;
				cout << "给定进行hill密码加密的密钥为：" << endl;
				for (int i = 0; i < 4; i++)
				{
					for (int j = 0; j < 4; j++)
					{
						cout << K[i][j] << " ";
					}
					cout << endl;
				}
				cout << endl;
				cout << "请输入明文：" << endl;
				getline(cin, plaintext);
//				cin >> plaintext;
				ciphertext = hh.encryption(plaintext);
				cout << endl;
				cout << "该明文通过希尔密码法加密过后,输出的密文消息为:" << endl;
				cout << ciphertext << endl;
				cout << endl;
				break;

		case 2:

				cout << "下面进行hill密码解密......" << endl;
				cout << "给定进行hill密码解密的密钥为：" << endl;
				for (int i = 0; i < 4; i++)
				{
					for (int j = 0; j < 4; j++)
					{
						cout << K[i][j] << " ";
					}
					cout << endl;
				}
				cout << "请输入密文：" << endl;
				getline(cin, ciphertext);
//				cin >> ciphertext;
				hh.fun(K, ROW);
				ciphertext = hh.deciphering(plaintext);
				cout << "该密文解密过后,显示的原来的明文消息:" << endl;
				cout << ciphertext << endl;
				cout << endl;
				break;
		case 3:

				int key;//密钥
				int(*pp[ROW]);
				cout << "下面进行用已知明文攻击破解密文......" << endl;
				cout << "请输入已知的部分明文：" << endl;
				cin >> partp[ROW][ROW];
				for (int i = 0; i < ROW; i++)
				{
						pp[i] = partp[i] - 'a';
				}
				cout << "请输入已知的部分明文对应的密文：" << endl;
				cin >> partc;
				for (int i = 0; i < ROW; i++)
				{
					partc[i] = partc[i] - 'a';
				}
				cout << "请输入剩余密文：" << endl;
				cin >> fullc;
				for (int i = 0; i < ROW; i++)
				{
					fullc[i] = fullc[i] - 'a';
				}
				PN = (hh.fun(partp, ROW) / hh.Det(partp, ROW));
//				key = hh.multiphy(N, C, ROW) % 26;//求出密钥
				cout << "由已知的部分密文及其对应的明文可求出其密钥为：" << endl;
				cout << key << endl;
				fullp = hh.deciphering(fullc);
				cout << "由此密钥可求出剩余明文为：" << endl;
				cout << fullp << endl;
				break;
		case 4:
            	cout << endl;
				cout << "退出" << endl;

				break;

		}
	}
	return 0;
}




