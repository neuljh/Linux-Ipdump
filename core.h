#ifndef CORE_H
#define CORE_H

#endif // CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
//opt和包的显示
#define IFRLEN 20//network interface length
#define MAXSIZE 4096//buffer size

#include<string>
#include<vector>
using namespace std;

class Core{
public:
//    struct cmd_flags{
//        bool a;//arp和ip,其他
//        bool e;//显示Ethernet报头
//        bool d;//包的内容是以16进制整数和ASCII码来显示
//        bool i;
//        char ifname[IFRLEN];
//        bool p;
//        bool f;
//    };

//    struct print_out{//只在指定了-p时有用
//        bool arp;
//        bool ip;
//        bool icmp;
//        bool tcp;
//        bool udp;
//    };

//    struct ne{
//        u_char a[6];
//        struct ne *next;
//    };

//    //统计
//    struct count{
//        //main
//        time_t st;
//        int mac_s;
//        int mac_l;
//        int macbyte;
//        int mac;
//        //p_count
//        int macbroad;

//        int ipbroad;
//        int ipbyte;
//        int ip;
//        int tcp;
//        int udp;

//        int icmp;
//        int icmp_r;
//        int icmp_d;
//    };

//    struct filter{
//        bool i;
//        bool p;
//        unsigned int ip;
//        int port;
//    };

    static unsigned int submask;
    static string res;
    static bool stop;

    static string start_time;
    static string end_time;
    static string mac_board;
    static string mac_short;
    static string mac_long;
    static string mac_byte;
    static string mac_packet;
    static string bit_s;
    static string mac_byte_speed;
    static string mac_packet_speed;
    static string ip_broadcast;
    static string ip_byte;
    static string ip_packet;
    static string udp_packet;
    static string tcp_packet;
    static string icmp_packet;
    static string icmp_redir;
    static string icmp_des;
};
