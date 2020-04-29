/*key_check.cpp 
author : liulinghong 
brief : key_check socket 
description : Create a service that encapsulates the data  encryption in the USE_KEY_DOG at the request of the socket and returns it for key validation 
time : 2019 : 9 : 13 
*/
#include <iostream>
#include <string>
#include<cstdio>
#include<errno.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<sys/wait.h>
#include <unistd.h>
#include "json/json.h"
#include <stdlib.h>  
#include <stdio.h>  
#include <stddef.h>  
#include <sys/socket.h>  
#include <sys/un.h>  
#include <errno.h>  
#include <string.h>  
#include <unistd.h>  
#include <ctype.h> 
#include <sys/stat.h>
#include "base64codes.h"
#include "rc4.h"
#include "str_hex.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include<string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include "greeencrypt.h"
#include "md5.h"
using namespace std;
#define USE_SOFT_KEY
char g_exe_path[256];	
#define BUF_SIZE 1024

//#define USE_KEY_DOG
int TestDog2()	
{
	if (!Outer_IsDogValid_NotBind(HAND_TO_HAND))	
	{	
		return 0;	
	}	
	char szProtectchar[PROTECT_CHAR_LEN] = { 0 };	
	if (Outer_ReadProtectChar("002", g_exe_path))//	
	{	
		printf("rkl protected char is:%s\n", g_exe_path);	
	}	
	return 1;	
}		  

struct package_hdr {	
	int length;	
	int type;	
};	
	
struct package {	
	struct package_hdr hdr;	
	unsigned char* data;	
};

typedef struct
{
	char board_serial[50];
	char cpu_id[50] ;
	char mac_address[50];
	char hard_disk[50];
}device_info;

typedef struct
{
	char expire[50];
	
}expire_info;

char device_encode[100] =  { 0 };
char device_code[100] =  { 0 };
char SOCK_PATH[256] = "/echo.sock";
//struct device_info device;
expire_info *expire_time = new expire_info;
pthread_rwlock_t rwlock;
pthread_rwlock_t frwlock;
#ifdef USE_SOFT_KEY
#include "linuxhard.h"
void device_reader()
{
	device_info *temp_device = new device_info;
	if (get_board_serial_number(temp_device->board_serial) != 1)
	{
		perror("board_serial read failed!");	
		exit(EXIT_FAILURE);
	}
	if (get_cpu_id(temp_device->cpu_id) != 1)
	{
		perror("cpu_id read failed!");	
		exit(EXIT_FAILURE);
	}
	if (get_mac_address(temp_device->mac_address) != 1)
	{
		perror("mac_address read failed!");	
		exit(EXIT_FAILURE);
	}
	char pData[200] = { 0 };
	strcat(pData, temp_device->cpu_id);
	strcat(pData, temp_device->board_serial);
	strcat(pData, temp_device->mac_address);
	
	char rc4key[16] = { "grxa2019" };
	unsigned char rc4s[256] = { 0 };       //S-box
	ULONG len = strlen(pData);
	rc4_init(rc4s, (unsigned char *)rc4key, strlen(rc4key));           //已经完成了初始化
	rc4_crypt(rc4s, (unsigned char *)pData, len);         //加密
	char strenc[200] = { 0 };
	char temp[100];
	base64_encode((unsigned char *)pData, temp, len);
	//char *temp = base64_encode(pData, (unsigned char *)strenc);
	char secret_key[20] = { 0 };
	md5_encode((unsigned char*)temp, secret_key);
	memcpy(device_code, secret_key, strlen(secret_key));
	sprintf(device_encode, "%s%s%s", "xyx", secret_key, "cy");
}

int expire_time_parse(char *srcfilename,int mode)
{
	char  buff[4096];
	unsigned char s[256] = { 0 };
	char result[50] = { 0 };
	memset(s, 0, sizeof(s));
	//memset(lict, 0, sizeof(struct license_t));
	memset(buff, 0, sizeof(buff));
	pthread_rwlock_wrlock(&frwlock);
	FILE* fp = fopen(srcfilename, "rb");
	if (fp != NULL)
	{
		int nread = fread(buff, 1, sizeof(buff), fp);
		fclose(fp);
		pthread_rwlock_unlock(&frwlock);
		if (nread > 0)
		{
			char strenc[200] = { 0 };
			int strenc_len = base64_decode(buff, (unsigned char *)strenc);
			//ndec = strlen(strenc);
			if(strenc_len > 1024)
			{
				return -2;
			}
			memset(buff, 0, sizeof(buff));
			memcpy(buff, strenc, strenc_len);
			rc4_init(s, (unsigned char *)device_encode, sizeof(device_encode));           //已经完成了初始化
			rc4_crypt(s, (unsigned char *)buff, strenc_len);         //加密

			if(buff[0] != '<' || buff[1] != '?' || buff[2] != 'x' || buff[3] != 'm' || buff[4] != 'l')
			{
				return -1;
			}
			char* pstart = strstr(buff, "expire=\"");
			if (pstart != NULL)
			{
				memcpy(result, pstart + 8, 10);
				if (mode == 1)
				{
					time_t t;	
					time_t rawtime;	
					struct tm * timeinfo;	
					char nowtime[128];	
					time(&rawtime);	
					timeinfo = localtime(&rawtime);	
					strftime(nowtime, sizeof(nowtime), "%Y-%m-%d", timeinfo);
					if (strcmp(result, nowtime) > 0 && strcmp(result, expire_time->expire) > 0)
					{
						char license_cp_cmd[50];
						pthread_rwlock_wrlock(&frwlock);
						sprintf(license_cp_cmd, "cp -rf %s %s", srcfilename, "/td01/license.lic");
						system(license_cp_cmd);
						pthread_rwlock_unlock(&frwlock);
						pthread_rwlock_wrlock(&rwlock);
						memcpy(expire_time->expire, result, sizeof(result));
						pthread_rwlock_unlock(&rwlock);
						return 1;
					}
				}
				else if (mode == 0)
				{
					pthread_rwlock_wrlock(&rwlock);
					memcpy(expire_time->expire, result, sizeof(result));
					pthread_rwlock_unlock(&rwlock);
					return 1;
				}
				else
				{
					return -1;
				}
			}
			else
			{
				return -1;
			}
		}
	}
	else
	{
	pthread_rwlock_unlock(&frwlock);
	}

}

void *expire_time_loop(void *arg)
{
	while (1)
	{
		expire_time_parse("/td01/license.lic",0);
		sleep(5 * 60 * 100);
	}
}



#endif // USE_SOFT_KEY


int listenfd;	
void handle_signal(int signo);	
void handle_signal(int signo) {	
	if (signo == SIGINT) {	
		fprintf(stderr, "received signal: SIGINT(%d)\n", signo);	
	}	
	else if (signo == SIGHUP) {	
		fprintf(stderr, "received signal: SIGHUP(%d)\n", signo);	
	}	
	else if (signo == SIGTERM) {	
		fprintf(stderr, "received signal: SIGTERM(%d)\n", signo);	
	}	
	
	close(listenfd);	
	unlink(SOCK_PATH);	
	exit(EXIT_SUCCESS);	
}	
	
typedef struct conn_thread	
{	
	int connfd;	
}conn_thread_t;	
 
void str_hex(unsigned char *str, unsigned char *hex)
{
	unsigned char ctmp, ctmp1, half;
	unsigned int num = 0;
	do {
		do {
			half = 0;
			ctmp = *str;
			if (!ctmp) break;
			str++;
		} while ((ctmp == 0x20) || (ctmp == 0x2c) || (ctmp == '\t'));
		if (!ctmp) break;
		if (ctmp >= 'a') ctmp = ctmp - 'a' + 10;
		else if (ctmp >= 'A') ctmp = ctmp - 'A' + 10;
		else ctmp = ctmp - '0';
		ctmp = ctmp << 4;
		half = 1;
		ctmp1 = *str;
		if (!ctmp1) break;
		str++;
		if ((ctmp1 == 0x20) || (ctmp1 == 0x2c) || (ctmp1 == '\t'))
		{
			ctmp = ctmp >> 4;
			ctmp1 = 0;
		}
		else if (ctmp1 >= 'a') ctmp1 = ctmp1 - 'a' + 10;
		else if (ctmp1 >= 'A') ctmp1 = ctmp1 - 'A' + 10;
		else ctmp1 = ctmp1 - '0';
		ctmp += ctmp1;
		*hex = ctmp;
		hex++;
		num++;
	} while (1);
	if (half)
	{
		ctmp = ctmp >> 4;
		*hex = ctmp;
		num++;
	}
}

void* socket_message(void* prama)	
{	
	struct package message;	
	int connfd, nbuf;	
	char buf[BUF_SIZE + 1];	
	conn_thread_t *p = (conn_thread_t *)prama;	
	connfd = p->connfd;	
	unsigned char s[256] = { 0 };	
	unsigned char st[256] = { 0 };	
	time_t t;	
	time_t rawtime;	
	struct tm * timeinfo;	
	char key[128];	
	time(&rawtime);	
	timeinfo = localtime(&rawtime);	
	memset(buf, 0, sizeof(buf));	
	nbuf = 0;	
	//receive message'head	
	int nrecv = 0;	
	while (nrecv < sizeof(message.hdr))	
	{	
		memset(&message, 0, sizeof(message));	
		nbuf = recv(connfd, buf + nrecv, sizeof(message.hdr) - nrecv, 0);	
		if (nbuf < 0) {	
			printf("have error!\n");	
			close(connfd);	
			return 0;	
		}	
		nrecv = nrecv + nbuf;	
	}	
	message.hdr = *((struct package_hdr*)buf);	
	int rev_type = message.hdr.type;
	if (message.hdr.length <= 0)	
	{	
		close(connfd);	
		return 0;	
	}	
	nbuf = 0;	
	int datasize = message.hdr.length - sizeof(message.hdr);
	char *packet_buff = (char*)malloc(datasize);
	//receive message'data	
	int revdata = 0;	
	nrecv = 0;
	if (rev_type == 0)
	{
		strftime(key, sizeof(key), "%Y%m%d%H", timeinfo);
	}
	else if (rev_type == 1 || rev_type == 2 || rev_type == 3)
	{
		strcpy(key, "www.365sec.com");
	}
	while (nbuf < datasize - nrecv)	
	{	 
		nbuf = recv(connfd, packet_buff + nrecv, datasize - nrecv, 0);	
		if (nbuf < 0) {	
			printf("have error!\n");	
			close(connfd);	
			return 0;
		}
		nrecv = nrecv + nbuf;
	}
	packet_buff[datasize] = '\0';	
	//let buf assign to struct'data	
	message.data = (unsigned char *)packet_buff;
	unsigned char recv_data[1024];
	if(strlen((char*)message.data) > 0)
	{	
		//data 16string->string	
		HexStrToByte((char *)message.data, recv_data, strlen((char *)(message.data)));	
		//rc4 Decryption	 
		rc4_init(st, (unsigned char *)key, strlen(key));	
		rc4_crypt(st, recv_data, strlen((char*)(recv_data)));	
	}
	Json::Value tdkey;
	char message_r[4096];
	memset(message_r, 0, sizeof(message_r));
	memcpy(message_r, expire_time->expire, sizeof(expire_time->expire));
	if (rev_type == 2)
	{
		if (sizeof(device_code) > 0)
		{
			tdkey["device"] = device_code;
			tdkey["state"] = 1;
		}
		else
		{
			tdkey["device"] = "";
			tdkey["state"] = 1;
		}

	}
	else if (rev_type == 3)
	{
		if (expire_time_parse((char *)recv_data,1) == 1)
		{
			tdkey["success"] = 1;
			tdkey["key"] = expire_time->expire;
			tdkey["state"] = 1;
		}
		else
		{
			tdkey["success"] = 0;
			tdkey["state"] = 1;
		}
	}
	else
	{
		tdkey["key"] = message_r;
		tdkey["state"] = 1;
	}
	struct package remessage;	
	char message_r16[1024] = { 0 };	
	std::string DevStr = tdkey.toStyledString();	
	//rc4 encryption	
	//cout << DevStr << endl;
	rc4_init(s, (unsigned char *)key, strlen(key));	
	rc4_crypt(s, (unsigned char *)&DevStr[0], DevStr.length());	
	Hex2Str(DevStr.c_str(), message_r16, DevStr.length());	
	remessage.hdr.length = 8 + strlen(message_r16);	
	remessage.hdr.type = 1;	
	remessage.data = (unsigned char *)message_r16;
	//memcpy struct->buf	
	char* buf_r = (char*)malloc(sizeof(remessage.hdr) + strlen((char*)remessage.data));	
	memcpy(buf_r, &remessage, sizeof(remessage.hdr));	
	memcpy(buf_r + sizeof(remessage.hdr), remessage.data, strlen((char*)remessage.data));	
	int nsend = 0;	
	while (nsend < remessage.hdr.length)	
	{	
		int n = send(connfd, buf_r, remessage.hdr.length, 0);	
		if (n < 0)	
		{	
			break;	
		}	
		nsend += n;	
	}	
	close(connfd);	
	if (prama != NULL)	
	{	
		free(prama);	
	}	
}

int main() {	
	signal(SIGINT, handle_signal);	
	signal(SIGHUP, handle_signal);	
	signal(SIGTERM, handle_signal);	
	
	//first read lic
	
	
	if ((listenfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {	
		perror("socket");	
		exit(EXIT_FAILURE);	
	}	
	
	struct sockaddr_un servaddr;	
	memset(&servaddr, 0, sizeof(servaddr));	
	servaddr.sun_family = AF_UNIX;	
	strcpy(servaddr.sun_path, SOCK_PATH);	
	
	unlink(SOCK_PATH);	
	if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {	
		perror("bind");	
		exit(EXIT_FAILURE);	
	}	
	chmod(SOCK_PATH, 00640);	
	
	if (listen(listenfd, SOMAXCONN) < 0) {	
		perror("listen");	
		exit(EXIT_FAILURE);	
	}
	pthread_t write_id;
	pthread_rwlock_init(&rwlock, NULL);
	pthread_rwlock_init(&frwlock, NULL);
	device_reader();
	pthread_create(&write_id, NULL, expire_time_loop, NULL);
	for (;;) {	
		int connfd;	
		if ((connfd = accept(listenfd, NULL, NULL)) < 0) {	
			perror("accept");	
			return 0;	
		}	
		conn_thread_t *p = (conn_thread_t*)malloc(sizeof(conn_thread_t));	
		pthread_t pthread_id;
		p->connfd = connfd;	
		int rc = pthread_create(&pthread_id, 0, socket_message, (void*)p);
	} 
	return 0;
}	
