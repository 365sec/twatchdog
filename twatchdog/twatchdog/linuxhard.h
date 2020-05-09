#ifndef LINUX_HARD_H
#define LINUX_HARD_H
//#include "customtypedef.h"
#ifndef _WIN32
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
//#include <scsi/sg.h>
//#include <linux/hdreg.h>
//#include <arpa/inet.h>
//#include <netinet/in.h>
int get_mac_address(char* mac_address);
int get_disk_serial_number(char* serial_no);
int get_cpu_id(char*  cpu_id);
int get_board_serial_number(char* board_serial);


#include "linuxhard.h"
static void parse_pipeline(const char * match_words, char * board_serial, char *result)
{
	while (1)
	{
		const char * board = strstr(board_serial, match_words);
		if (NULL == board)
		{
			continue;
		}
		board += strlen(match_words);
		int strset = 0;
		int resultset = 0;
		while ('\0' != board[strset])
		{
			if (' ' != board[strset] && '\n' != board[strset] && ':' != board[strset])
			{
				result[resultset] = board[strset];
				resultset++;
			}
			++strset;
		}
		result[resultset + 1] = '\0';
		if (strlen(result) > 0)
		{
			break;
		}
	}
}

int get_board_serial_by_dmi(char* result)
{
	FILE *pf;
	char command[512] = { 0 };
	char board_serial[100] = { 0 };
	snprintf(command, sizeof(command), "cat /sys/class/dmi/id/product_serial");
	pf = popen(command, "r");
	fread(board_serial, sizeof(board_serial), 1, pf);

	if (strlen(board_serial) > 0)
	{
		parse_pipeline("", board_serial, result);
		return 1;
	}
	else
	{
		return 0;
	}
}

int get_board_serial_by_system(char* result)
{
	FILE *pf;
	char command[512] = { 0 };
	char board_serial[100] = { 0 };
	snprintf(command, sizeof(command), "dmidecode |grep \'Serial Number\' | awk \'NR==1\'");
	pf = popen(command, "r");
	fread(board_serial, sizeof(board_serial), 1, pf);

	if (strlen(board_serial) > 0)
	{
		parse_pipeline("Serial Number:", board_serial, result);
		return 1;
	}
	else
	{
		return 0;
	}
}

int get_board_serial_number(char* board_serial)
{
	char result[50] = { 0 };
	if (get_board_serial_by_system(board_serial))
	{
		strcpy(result, board_serial);
		return 1;
	}
	else
	{
		if (get_board_serial_by_dmi(board_serial))
		{
			strcpy(result, board_serial);
			printf("board_serial:%s\n", result);
			return 1;
		}
		else
		{
			return 0;
		}
	}
}

static int get_cpu_id_by_asm(char * cpu_id)
{
	unsigned int s1 = 0;
	unsigned int s2 = 0;
	asm volatile
	(
	    "movl $0x01, %%eax; \n\t"
	    "xorl %%edx, %%edx; \n\t"
	    "cpuid; \n\t"
	    "movl %%edx, %0; \n\t"
	    "movl %%eax, %1; \n\t"
	    : "=m"(s1),
		"=m"(s2));

	if (0 == s1 && 0 == s2)
	{
		return 0;
	}
	char cpu[32] = { 0 };
	snprintf(cpu, sizeof(cpu), "%08X%08X", htonl(s2), htonl(s1));
	//snprintf(cpu_id, sizeof(cpu_id), "%08X%08X", htonl(s2), htonl(s1));
	//("%s", cpu);
	strcpy(cpu_id, cpu);
	return 1;
}

static int get_cpu_id_by_system(char* result)
{
	FILE *pf;
	char command[512] = { 0 };
	char cpu_id[100] = { 0 };
	snprintf(command, sizeof(command), "dmidecode -t 4 |grep \'ID\' | awk \'NR==1\'");
	pf = popen(command, "r");
	fread(cpu_id, sizeof(cpu_id), 1, pf);

	if (strlen(cpu_id) > 0)
	{
		parse_pipeline("ID:", cpu_id, result);
		return 1;
	}
	else
	{
		return 0;
	}
}


int get_cpu_id(char *cpu_id)
{
	char result[50] = { 0 };
	if (get_cpu_id_by_asm(result))
	{
		strcpy(cpu_id, result);
		return 1;
	}
	else
	{
		if (get_cpu_id_by_system(result))
		{
			strcpy(cpu_id, result);
			return 1;
		}
		return 0;
	}
}

int get_mac_address_by_ioctl(char* mac_address)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		return 0;
	}

	struct ifreq ifr = { 0 };
	strncpy(ifr.ifr_name, "eth0", sizeof(ifr.ifr_name) - 1);
	int ret = ioctl(sock, SIOCGIFHWADDR, &ifr);
	close(sock);
	const char hex[] = 
	{
		'0',
		'1',
		'2',
		'3',
		'4',
		'5',
		'6',
		'7', 
		'8',
		'9',
		'a',
		'b',
		'c',
		'd',
		'e',
		'f' 
	};
	char mac[16] = { 0 };
	int index = 0;
	for (index; index < 6; ++index)
	{
		size_t value = ifr.ifr_hwaddr.sa_data[index] & 0xFF;
		mac[2 * index + 0] = hex[value / 16];
		mac[2 * index + 1] = hex[value % 16];
	}
	strcpy(mac_address, mac);
	char nullstr[20] = { 0 };
	strcpy(nullstr, "000000000000");
	if (strcmp(mac_address, nullstr) == 0)
	{
		return 0;
	}
	return ret > 0 ? 0 : 1;
}

static int get_mac_address_by_system(char* result)
{
	FILE *pf;
	char command[512] = { 0 };
	char mac_address[100] = { 0 };
	snprintf(command, sizeof(command), "lshw -c network | grep serial | head -n 1");
	pf = popen(command, "r");
	fread(mac_address, sizeof(mac_address), 1, pf);

	if (strlen(mac_address) > 0)
	{
		parse_pipeline("serial:", mac_address, result);
		return 1;
	}
	else
	{
		return 0;
	}
}

int get_mac_address(char *mac_address)
{
	char result[50] = { 0 };
	if (get_mac_address_by_ioctl(result))
	{
		strcpy(mac_address, result);
		//printf("mac_address:%s\n", mac_address);
		return 1;
	}
	else
	{
		
		if (get_mac_address_by_system(result))
		{
			strcpy(mac_address, result);
			return 1;
		}
		return 0;
	}
}
#endif

#endif  //LINUX_HARD_H
