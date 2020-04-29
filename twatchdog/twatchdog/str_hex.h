#pragma once
#include <string.h>
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

void StrToHex(unsigned char *pbDest, unsigned char *pbSrc, int nLen)
{
	char h1, h2;
	unsigned char s1, s2;
	int i;

	for (i = 0; i < nLen; i++)
	{
		h1 = pbSrc[2*i];
		h2 = pbSrc[2*i + 1];

		s1 = toupper(h1) - 0x30;
		if (s1 > 9)
			s1 -= 7;

		s2 = toupper(h2) - 0x30;
		if (s2 > 9)
			s2 -= 7;

		pbDest[i] = s1 * 16 + s2;
	}
}


//字节流转换为十六进制字符串的另一种实现方式  
void Hex2Str(const char *sSrc, char *sDest, int nSrcLen)  
{  
	int  i;  
	char szTmp[3];  
  
	for (i = 0; i < nSrcLen; i++)  
	{  
		sprintf(szTmp, "%02X", (unsigned char) sSrc[i]);  
		memcpy(&sDest[i * 2], szTmp, 2);  
	}  
	return ;  
}  
  
//十六进制字符串转换为字节流  
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)  
{  
	short i;  
	unsigned char highByte, lowByte;  
      
	for (i = 0; i < sourceLen; i += 2)  
	{  
		highByte = toupper(source[i]);  
		lowByte  = toupper(source[i + 1]);  
  
		if (highByte > 0x39)  
			highByte -= 0x37;  
		else  
			highByte -= 0x30;  
  
		if (lowByte > 0x39)  
			lowByte -= 0x37;  
		else  
			lowByte -= 0x30;  
  
		dest[i / 2] = (highByte << 4) | lowByte;  
	}  
	return ;  
}

