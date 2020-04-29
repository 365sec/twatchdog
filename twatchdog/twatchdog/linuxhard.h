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
#include <arpa/inet.h>

int get_mac_address(char* mac_address);
int get_disk_serial_number(char* serial_no);
int get_cpu_id(char*  cpu_id);
int get_board_serial_number(char* board_serial);
#endif

#endif  //LINUX_HARD_H
