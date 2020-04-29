#ifndef _GREEENCRYPT_H
#define _GREEENCRYPT_H

#include <vector>
#include <list>
#include <string>
using namespace std;

#ifndef DLL_LOCAL
	#if defined _WIN32 || defined __CYGWIN__
		#ifdef BUILDING_DLL
			#ifdef __GNUC__
				#define DLL_PUBLIC __attribute__((dllexport))
			#else
				#define DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
			#endif
		#else
			#ifdef __GNUC__
				#define DLL_PUBLIC __attribute__((dllimport))
			#else
				#define DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
			#endif
		#endif

		#define DLL_LOCAL
	#else
		#if __GNUC__ >= 4
			#define DLL_PUBLIC __attribute__ ((visibility("default")))
			#define DLL_LOCAL  __attribute__ ((visibility("hidden")))
		#else
			#define DLL_PUBLIC
			#define DLL_LOCAL
		#endif
	#endif
#endif

#ifndef CALLMODE
	#ifdef _WIN32
	#define CALLMODE __cdecl
	#else
	#define CALLMODE
	#endif
#endif

#ifndef OUT
#define OUT	
#endif

#ifndef _NEED_READ_DOG
#define _NEED_READ_DOG
#endif

#ifdef _NEED_READ_DOG

#define READ_BUFFER	(5120)	//最多8192字节,8的整数倍。//+2048
#define PROTECT_CHAR_LEN 256	//保护特征字符长度。

#define HAND_TO_HAND	0x10101010

typedef enum _TOOL_SERIAL
{
	TOOLS_002=0,//linux
	TOOLS_003,//病毒、木马
	TOOLS_005,//网络设备，如路由器交换机【OEM】
	TOOLS_008,//安全设备，如防火墙【OEM】
	TOOLS_009,//弱口令

	TOOLS_011,//系统漏扫
	TOOLS_012,//网站安全,即web漏扫。
	TOOLS_013,//数据库【OEM】

	//
	//TOOLS_工具额外程序编号。用于自动升级。
	//
	TOOLS_10001,//	---金网络工具调度
	TOOLS_10002,//	---刘U口工具调度

	TOOLS_10003,//	---web文件，路径C:\gree\tomcat\webapps
	TOOLS_10004,//	---四合一的包，路径C:\gree\nginx\html\greetooldir
	TOOLS_COUNT,//无意义，数数。
}TOOL_SERIAL;

#define MAX_SERIAL_LEN	32

typedef struct _KEY_CONTENT_T_
{
	char			strFlag[4];//grxa
	unsigned char 	strVersion[4];
	unsigned short 	uPort;
	unsigned short	uReserved;
	char			strDbUser[20];
	char			strDbPwd[20];
	char			strLoginQuery[32];	//SELECT * FROM wa_cp_0007
	char			strConfigFileName[64];	//"Config\\Config.ini"
	char			strExpWordFile[64];	//WordEngine.dll
	char			szKey[16];			//qizc。加密键有效
	char			confpath[64];		//qizc。金恺
	char			deamonpath[64];		//qizc。金恺
	union
	{
		char			resvered[512];		//qizc。保留。将来拆分。

		struct
		{
			char serial[MAX_SERIAL_LEN];
			unsigned int expired;//+4
			unsigned int releaseTime;//+4
			char resvered2[472];
		};
	};

	char tools[TOOLS_COUNT][PROTECT_CHAR_LEN];

}KeyContent;

typedef struct _TOOL_ITEM
{
	TOOL_SERIAL item;
	char		name[32];
}TOOL_ITEM;
#endif

extern "C" 
{
//客户端函数
	DLL_LOCAL void CALLMODE Outer_ReadHDSerial(char* szSerialLocal);

	//数据流加密。其中输出参数cipher_buf需要调用者释放
	DLL_LOCAL void CALLMODE Outer_DoEncrypt(const char* plain_buf,int plain_len,OUT char*& cipher_buf,OUT int& cipher_len);

	//文件加密
	DLL_LOCAL bool CALLMODE Outer_EncryptFile(char *szFileNamePlain,char *szFileNameCipher);

//以下服务端专用

	//
	//	生产key文件greeinfonew.ini，然后分发到客户端exe的相同目录下。
	//	把key也写入加密锁。服务端从加密锁读取key。
	//
	DLL_LOCAL bool CALLMODE Outer_ProduceKeyFile(const char* szKey);//长度必须是8位。
	DLL_LOCAL void CALLMODE Outer_GetIni_str_Decrypt2(const char* szFile,OUT char* szValue);

//	数据流解密。调用者 free 参数 plain_buf。szKey从加密锁读取。
//	DLL_LOCAL void CALLMODE Outer_DoDecrypt(const char* cipher_buf,int cipher_len,char*& plain_buf,int& plain_len,const char* szKey);
//	文件解密。szKey从加密锁读取。
//	DLL_LOCAL bool CALLMODE Outer_DecryptFile(const char *szFileNameCipher,const char *szFileNamePlain,const char* szKey);

	DLL_LOCAL void CALLMODE Outer_DoDecrypt_FromIni(const char* cipher_buf,int cipher_len,char*& plain_buf,int& plain_len);

#ifdef _NEED_READ_DOG
	//注意：目标工程需要有 "./libs/debug/RK5DLL.lib" 和 "./libs/release/RK5DLL.lib"，
	//并且需要 RK5DLL.dll 和 Rockey3.dll
	DLL_LOCAL bool CALLMODE Outer_IsDogValid_NotBind(int nHandToHand);//不和硬件绑定。
	DLL_LOCAL bool CALLMODE Outer_IsDogValid(int nHandToHand);//参数 HAND_TO_HAND。是否和硬件绑定？
	DLL_LOCAL bool CALLMODE Outer_IsDogValid2(int nHandToHand,KeyContent& kc);

	//以下函数不和硬件序列号绑定。
	DLL_LOCAL void CALLMODE Outer_DoDecrypt_FromDog(const char* cipher_buf,int cipher_len,char*& plain_buf,int& plain_len);
	DLL_LOCAL bool CALLMODE Outer_DecryptFile_FromDog(const char *szFileNameCipher,const char *szFileNamePlain);
	DLL_LOCAL bool CALLMODE Outer_ReadProtectChar(const char* szToolNumer,char* szProtectchar);
	DLL_LOCAL bool CALLMODE Outer_ReadDogAll(KeyContent* pKeyContent);
	DLL_LOCAL bool CALLMODE Outer_ReWriteKey(int nHandToHand,vector<string> vec);

	DLL_LOCAL unsigned long CALLMODE Imm_ReadKeyRaw(char* sz,int size);
	DLL_LOCAL unsigned long CALLMODE Imm_WriteKeyRaw(char* sz,int size);

	DLL_LOCAL void CALLMODE Outer_SetKey(int nHandToHand,const char* sz);
#endif
}

#endif

/*
void TestDog()
{
	//Outer_IsDogValidNotBind()//不和硬件绑定
	//Outer_IsDogValid()//和硬件绑定
	if( !Outer_IsDogValid_NotBind(HAND_TO_HAND) )
	{
		printf("no dog or not match.\n");
	}

	char szProtectchar[PROTECT_CHAR_LEN]={0};
	if( Outer_ReadProtectChar("009",szProtectchar) )//
	{
		printf("rkl protected char is:%s\n",szProtectchar);
	}
}
*/

/*
//解密测试
void Test_Decrypt(const char* cipher_buf,int cipher_len)
{
	//测试解密
	int outSize=0;
	char* p_buf_out=NULL;

	Outer_DoDecrypt(cipher_buf,cipher_len,p_buf_out,outSize,"h3cN0001");//key从加密锁读取
	if(p_buf_out)
	{
		//注意不能当字符串处理，要当字节流处理。
		TRACE("info:解密成功，在此处理p_buf_out\n");
		free(p_buf_out);
	}
	else
	{
		TRACE("aleart:解密失败\n");
	}
}

//加密测试
void Test_Encrypt()
{
	char buf_in[]="abcdABCD";
	int inSize=(int)strlen(buf_in);
	int outSize=0;
	char* p_buf_out=NULL;

	Outer_DoEncrypt(buf_in,inSize,p_buf_out,outSize);

	if(p_buf_out)
	{
		//
		TRACE("info:加密成功，在此处理p_buf_out\n");

		//顺便测试解密
		Test_Decrypt(p_buf_out,outSize);//

		//
		free(p_buf_out);
	}
	else
	{
		TRACE("aleart:加密失败\n");
	}
}

void FileTest()
{
	if(!Outer_EncryptFile("D:\\1.txt","D:\\1_cypher.txt"))
	{
		TRACE("aleart:加密文件失败\n");
	}

	if(!Outer_DecryptFile("D:\\1_cypher.txt","D:\\2.txt",TEST_KEY))
	{
		TRACE("aleart:解密文件失败\n");
	}
}
*/
