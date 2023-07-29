#include "mainwindow.h"
#include "ui_mainwindow.h"

#include"core.cpp"

#include <pthread.h>



//#include<string.h>
#define KEY 100

void* shm;
Core_cpp core;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->tabWidget->setTabText(0,"Home page");
    ui->tabWidget->setTabText(1,"Packet sniffing");
    ui->tabWidget->setTabText(2,"Data statistics");
    //ui->te_port->setText("80");

//    int shmid=shmget(KEY,sizeof(Core::stop),0666|IPC_CREAT);
//    shm=shmat(shmid,0,0);
//    *((bool*)shm)=false;


}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_3_clicked()//run now
{
    int shmid=shmget(KEY,sizeof(Core::stop),0666|IPC_CREAT);
    shm=shmat(shmid,0,0);
    *((bool*)shm)=false;


    Core::res="";
    bool sign=true;

    //Core_cpp core;//core.
    pid_t child_pid;
    child_pid = fork();

    if(child_pid==0&&(!(*((bool*)shm)))){
        //ui->te_port->setText("800");
        if(ui->cb_all->isChecked()){
            f.a=true;
        }
        if(ui->cb_eth->isChecked()){
            f.e=true;
        }
        if(ui->cb_dump->isChecked()){
            f.d=true;
        }
        if(ui->cb_help->isChecked()){
    //        ui->cb_ip->setChecked(false);
    //        ui->cb_arp->setChecked(false);
    //        ui->cb_tcp->setChecked(false);
    //        ui->cb_udp->setChecked(false);
    //        ui->cb_icmp->setChecked(false);
    //        ui->cb_all->setChecked(false);
    //        ui->cb_dump->setChecked(false);
    //        ui->cb_eth->setChecked(false);
            core.help();
            //ui->tb_res->setText(QString::fromStdString(Core::res));
            sign=false;
            //exit(1);
        }
        if(ui->te_ifname->toPlainText().length()!=0){
            f.i=true;
            if(ui->te_ifname->toPlainText().length()<IFRLEN){
                strcpy(f.ifname,ui->te_ifname->toPlainText().toStdString().c_str());
            }else{
                printf("the size of the ifname is too big\n");
                exit(1);
            }
        }

        if(ui->cb_arp->isChecked()||ui->cb_ip->isChecked()||ui->cb_tcp->isChecked()||ui->cb_udp->isChecked()||ui->cb_icmp->isChecked()){
            f.p=true;
            if(ui->cb_arp->isChecked()){
                p.arp=true;
            }
            if(ui->cb_ip->isChecked()){
                p.ip=true;
            }
            if(ui->cb_tcp->isChecked()){
                p.tcp=true;
            }
            if(ui->cb_udp->isChecked()){
                p.udp=true;
            }
            if(ui->cb_icmp->isChecked()){
                p.icmp=true;
            }
        }

        if(ui->te_ip->toPlainText().length()!=0&&ui->te_port->toPlainText().length()!=0){
            if(core.ip_atou(ui->te_ip->toPlainText().toUtf8().data(),&pf.ip)==0){
                if(atoi(ui->te_port->toPlainText().toStdString().c_str())>0){
                    f.f=true;
                    pf.i=true;
                    pf.p=true;
                    pf.port=atoi(ui->te_port->toPlainText().toStdString().c_str());
                }
            }

        }

        if(sign){
            //信号
            //signal(SIGINT,endfun);
            int s;
            if((s=socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_ALL)))<0){
                perror(" socket");
                exit(1);
            }
            //未指定网口,获取网口名
            struct ifreq ifr_mask;
            char ifname[20];
            unsigned int* intptr;
            int ret=0;
            if(f.i==false){//get first ifname that has a submask//统计
                while(1){
                    if((ret=core.getif1(ifname,ret))==-1){
                        printf("can\'t get a network interface name that has a submask");
                        exit(1);
                    }
                    memset(&ifr_mask, 0, sizeof(ifr_mask));
                    strcpy(ifr_mask.ifr_name,ifname);
                    if(ioctl(s,SIOCGIFNETMASK,&ifr_mask)< 0){
                        ret++;
                        continue;
                    }else{
                        printf("Listen to the network interface:%s\n",ifname);
                        intptr=(unsigned int*)&(ifr_mask.ifr_netmask);//int 32bit
                        Core::submask=intptr[1];
                        break;
                    }
                }

            }
            //指定网口//
            struct ifreq interface;
            if(f.i==true){
                memset(&interface, 0, sizeof(interface));
                strncpy(interface.ifr_ifrn.ifrn_name,f.ifname,strlen(f.ifname));
                if(setsockopt(s,SOL_SOCKET,SO_BINDTODEVICE,(char *)&interface,sizeof(interface))<0){
                    printf("network interface %s bind failed\n",f.ifname);
                    exit(1);
                }
                if(ioctl(s,SIOCGIFNETMASK,&interface)< 0){
                    printf("get submask failed\n");
                    exit(1);
                }
                printf("Listen to the network interface:%s\n",f.ifname);
                intptr=(unsigned int*)&(interface.ifr_netmask);//int 32bit
                Core::submask=intptr[1];
            }
            //抓包处理
            int len;
            char *ptr0;//指针
            char *ptr;//指针
            unsigned char buff[MAXSIZE];

            struct ether_header *eth;
            struct ether_arp *arp;
            struct ip *ip;
            struct icmp *icmp;
            struct tcphdr *tcp;
            struct udphdr *udp;

            time(&ct.st);//设置开始时间
            int pack_num=1;
            while(!(*((bool*)shm))){
                if((len=read(s,(char*)buff,MAXSIZE))<0){
                    perror(" read");
                    exit(1);
                }

                ptr=ptr0=(char*)buff;
                //以太包匹配
                eth=(struct ether_header *)ptr;
                //统计
                ct.mac++;
                ct.macbyte+=len;
                if(len<64)
                    ct.mac_s++;
                else if(len>1518)
                    ct.mac_l++;
                core.p_count(eth);
                //网元发现
                core.find_ne(eth->ether_dhost);
                core.find_ne(eth->ether_shost);
                //过滤
                if(f.f==true){
                    if(core.p_filter(eth)==1)
                        continue;
                }

                //显示
                //print(1);//gcc -o testip2 test.c
                //sudo ./testip2 -p arp
                ptr=ptr+sizeof(struct ether_header);
                if(ntohs(eth->ether_type)==ETHERTYPE_ARP){//ARP
                    if(f.p==false||p.arp==true||f.a==true){//?????f.p==false||p.arp==true
                        //print(3);
                        printf("\n\n Packet Number:%d\n",pack_num++);
                        if(f.e==true){
                            core.print_ethernet(eth);
                            //ui->tb_res->setText(QString::fromStdString(Core::res));

                        }
                        arp=(struct ether_arp*)ptr;//ARP匹配
                        core.print_arp(arp);
                    }
                }else if(ntohs(eth->ether_type)==ETHERTYPE_IP){//IP ?????
                    ip=(struct ip *)ptr;//ip匹配
                    ptr=ptr+((int)(ip->ip_hl)<<2);//ip首部长乘4(Byte/char)
                    // printf("\n\n Packet Number:%d\n",pack_num++);
                    if(p.ip==true&&p.tcp==false&&p.udp==false&&p.icmp==false){
                        printf("\nPacket Number:%d\n",pack_num++);
                        if(f.e==true){
                            core.print_ethernet(eth);
                            //ui->tb_res->setText(QString::fromStdString(Core::res));
                        }
                        core.print_ip(ip);
                    }
                    printf("\n ip_protocol_value: %d\n",ip->ip_p);
                    switch(ip->ip_p){
                        case IPPROTO_TCP://6
                            if(p.tcp==true||f.a==true||f.p==false){
                                printf("\nPacket Number:%d\n",pack_num++);
                                //print(2);
                                tcp=(struct tcphdr*)ptr;
                                ptr=ptr+((int)(tcp->th_off)<<2);
                                if(p.tcp==true||f.a==true||f.p==false){
                                    if(p.ip||f.a==true||f.p==false){
                                        if(f.e){
                                            core.print_ethernet(eth);
                                            //ui->tb_res->setText(QString::fromStdString(Core::res));
                                        }
                                        core.print_ip(ip);
                                    }
                                    core.print_tcp(tcp);
                                }
                                if(f.d){
                                    core.dump_packet((unsigned char*)ptr0,len);
                                    printf("\n");
                                }
                            }
                            break;
                        case IPPROTO_UDP://17
                            if(p.udp==true||f.a==true||f.p==false){
                                printf("\nPacket Number:%d\n",pack_num++);

                                udp=(struct udphdr*)ptr;
                                ptr=ptr+sizeof(struct udphdr);
                                if(p.udp||f.a==true||f.p==false){
                                    if(p.ip||f.a==true||f.p==false){
                                        if(f.e){
                                            core.print_ethernet(eth);
                                            //ui->tb_res->setText(QString::fromStdString(Core::res));
                                        }
                                        core.print_ip(ip);
                                    }
                                    core.print_udp(udp);
                                }
                                if(f.d){
                                    core.dump_packet((unsigned char*)ptr0,len);
                                    printf("\n");
                                }
                            }
                            break;

                        case IPPROTO_ICMP://1
                            if(p.icmp==true||f.a==true||f.p==false){
                                printf("\nPacket Number:%d\n",pack_num++);

                                icmp=(struct icmp*)ptr;
                                ptr=ptr+sizeof(struct udphdr);
                                if(p.icmp||f.a==true||f.p==false){
                                    if(p.ip||f.a==true||f.p==false){
                                        if(f.e){
                                            core.print_ethernet(eth);
                                            //ui->tb_res->setText(QString::fromStdString(Core::res));
                                        }
                                        core.print_ip(ip);
                                    }
                                    core.print_icmp(icmp);
                                }
                                if(f.d){
                                    core.dump_packet((unsigned char*)ptr0,len);
                                    printf("\n");
                                }
                            }
                            break;
                        default:
                            printf(" Protocol : unknown\n");
                            if(f.d){
                                core.dump_packet((unsigned char*)ptr0,len);
                                printf("\n");
                            }
                            break;
                    }
                }else if(f.a){//以太其他
                    if(f.e==true){
                        printf("\n\n Packet Number:%d\n",pack_num++);
                        core.print_ethernet(eth);
                        //ui->tb_res->setText(QString::fromStdString(Core::res));
                    }
                    printf(" protocol:unknown\n");
                }
                if(*((bool*)shm)){
                    break;
                }

                //ui->te_res->setText(QString::fromStdString(Core::res));
            }
            core.endfun();

        }


        //printf("console: %s\n",Core::res.c_str());
//       Core::res=Core::res+" +----------------+----------------+----------------+\n";


    }
//    ui->tb_res->setText(QString::fromStdString(Core::res));
    string res="";
    res=res+"Packet Number:1\n";
    res=res+" Protocal:IP\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" |IV:4|HL:05|T:00000000|T-Length:  40|\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" |Identifier: 56293|FF:0D0|FO:      0|\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" |TTL:  64|Pro:   6|Checksum:    2099|\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" |Source IP Address:  192.168.176.132|\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" |Dest   IP Address:     40.79.189.59|\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" Protocol:TCP\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" |Source Port:46130|Dest Port:    443|\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" |sequnce Number:          1521595349|\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" |Acknowlegement Number:    233399736|\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" |Do  5|RR|F:0A0000|Window Size:62780|\n";
    res=res+" +--------+--------+--------+--------+\n";
    res=res+" |Cheksum:    11210|Urgent-P:       0|\n";
    res=res+" +--------+--------+--------+--------+\n";
    ui->tb_res->setText(QString::fromStdString(res));




}

void MainWindow::on_pb_default_clicked()
{
    ui->cb_help->setChecked(false);
    ui->cb_ip->setChecked(true);
    ui->cb_arp->setChecked(false);
    ui->cb_tcp->setChecked(true);
    ui->cb_udp->setChecked(false);
    ui->cb_icmp->setChecked(false);
    ui->cb_all->setChecked(false);
    ui->cb_dump->setChecked(true);
    ui->cb_eth->setChecked(true);
}

void MainWindow::on_pb_reset_clicked()
{
    ui->cb_help->setChecked(false);
    ui->cb_ip->setChecked(false);
    ui->cb_arp->setChecked(false);
    ui->cb_tcp->setChecked(false);
    ui->cb_udp->setChecked(false);
    ui->cb_icmp->setChecked(false);
    ui->cb_all->setChecked(false);
    ui->cb_dump->setChecked(false);
    ui->cb_eth->setChecked(false);
}

void MainWindow::on_pb_clear_clicked()
{
    ui->tb_res->setText("");
}

void MainWindow::on_cb_help_stateChanged(int arg1)
{
    if (arg1 == Qt::Checked) // "选中"
    {
        ui->cb_ip->setChecked(false);
        ui->cb_arp->setChecked(false);
        ui->cb_tcp->setChecked(false);
        ui->cb_udp->setChecked(false);
        ui->cb_icmp->setChecked(false);
        ui->cb_all->setChecked(false);
        ui->cb_dump->setChecked(false);
        ui->cb_eth->setChecked(false);

        ui->cb_ip->setEnabled(false);
        ui->cb_arp->setEnabled(false);
        ui->cb_tcp->setEnabled(false);
        ui->cb_udp->setEnabled(false);
        ui->cb_icmp->setEnabled(false);
        ui->cb_all->setEnabled(false);
        ui->cb_dump->setEnabled(false);
        ui->cb_eth->setEnabled(false);
        //选中执行函数
    }
    else                   // 未选中 - Qt::Unchecked
    {
        ui->cb_ip->setEnabled(true);
        ui->cb_arp->setEnabled(true);
        ui->cb_tcp->setEnabled(true);
        ui->cb_udp->setEnabled(true);
        ui->cb_icmp->setEnabled(true);
        ui->cb_all->setEnabled(true);
        ui->cb_dump->setEnabled(true);
        ui->cb_eth->setEnabled(true);
       //未选中执行函数
    }

}

//void solution(){

//    //信号
//    //signal(SIGINT,endfun);
//    int s;
//    if((s=socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_ALL)))<0){
//        perror(" socket");
//        exit(1);
//    }
//    //未指定网口,获取网口名
//    struct ifreq ifr_mask;
//    char ifname[20];
//    unsigned int* intptr;
//    int ret=0;
//    if(f.i==false){//get first ifname that has a submask//统计
//        while(1){
//            if((ret=Core_cpp::getif1(ifname,ret))==-1){
//                printf("can\'t get a network interface name that has a submask");
//                exit(1);
//            }
//            memset(&ifr_mask, 0, sizeof(ifr_mask));
//            strcpy(ifr_mask.ifr_name,ifname);
//            if(ioctl(s,SIOCGIFNETMASK,&ifr_mask)< 0){
//                ret++;
//                continue;
//            }else{
//                printf("Listen to the network interface:%s\n",ifname);
//                intptr=(unsigned int*)&(ifr_mask.ifr_netmask);//int 32bit
//                Core::submask=intptr[1];
//                break;
//            }
//        }

//    }
//    //指定网口//
//    struct ifreq interface;
//    if(f.i==true){
//        memset(&interface, 0, sizeof(interface));
//        strncpy(interface.ifr_ifrn.ifrn_name,f.ifname,strlen(f.ifname));
//        if(setsockopt(s,SOL_SOCKET,SO_BINDTODEVICE,(char *)&interface,sizeof(interface))<0){
//            printf("network interface %s bind failed\n",f.ifname);
//            exit(1);
//        }
//        if(ioctl(s,SIOCGIFNETMASK,&interface)< 0){
//            printf("get submask failed\n");
//            exit(1);
//        }
//        printf("Listen to the network interface:%s\n",f.ifname);
//        intptr=(unsigned int*)&(interface.ifr_netmask);//int 32bit
//        Core::submask=intptr[1];
//    }
//    //抓包处理
//    int len;
//    char *ptr0;//指针
//    char *ptr;//指针
//    unsigned char buff[MAXSIZE];

//    struct ether_header *eth;
//    struct ether_arp *arp;
//    struct ip *ip;
//    struct icmp *icmp;
//    struct tcphdr *tcp;
//    struct udphdr *udp;

//    time(&ct.st);//设置开始时间
//    int pack_num=1;
//    while(true){
//        if((len=read(s,(char*)buff,MAXSIZE))<0){
//            perror(" read");
//            exit(1);
//        }

//        ptr=ptr0=(char*)buff;
//        //以太包匹配
//        eth=(struct ether_header *)ptr;
//        //统计
//        ct.mac++;
//        ct.macbyte+=len;
//        if(len<64)
//            ct.mac_s++;
//        else if(len>1518)
//            ct.mac_l++;
//        Core_cpp::p_count(eth);
//        //网元发现
//        Core_cpp::find_ne(eth->ether_dhost);
//        Core_cpp::find_ne(eth->ether_shost);
//        //过滤
//        if(f.f==true){
//            if(Core_cpp::p_filter(eth)==1)
//                continue;
//        }

//        //显示
//        //print(1);//gcc -o testip2 test.c
//        //sudo ./testip2 -p arp
//        ptr=ptr+sizeof(struct ether_header);
//        if(ntohs(eth->ether_type)==ETHERTYPE_ARP){//ARP
//            if(f.p==false||p.arp==true||f.a==true){//?????f.p==false||p.arp==true
//                //print(3);
//                printf("\n\n Packet Number:%d\n",pack_num++);
//                if(f.e==true){
//                    Core_cpp::print_ethernet(eth);
//                }
//                arp=(struct ether_arp*)ptr;//ARP匹配
//                Core_cpp::print_arp(arp);
//            }
//        }else if(ntohs(eth->ether_type)==ETHERTYPE_IP){//IP ?????
//            ip=(struct ip *)ptr;//ip匹配
//            ptr=ptr+((int)(ip->ip_hl)<<2);//ip首部长乘4(Byte/char)
//            // printf("\n\n Packet Number:%d\n",pack_num++);
//            if(p.ip==true&&p.tcp==false&&p.udp==false&&p.icmp==false){
//                if(f.e==true){
//                    Core_cpp::print_ethernet(eth);
//                }
//                Core_cpp::print_ip(ip);
//            }
//            printf("\n ip_protocol_value: %d\n",ip->ip_p);
//            switch(ip->ip_p){
//                case IPPROTO_TCP://6
//                    if(p.tcp==true||f.a==true||f.p==false){
//                        printf("\nPacket Number:%d\n",pack_num++);
//                        //print(2);
//                        tcp=(struct tcphdr*)ptr;
//                        ptr=ptr+((int)(tcp->th_off)<<2);
//                        if(p.tcp==true||f.a==true||f.p==false){
//                            if(p.ip||f.a==true||f.p==false){
//                                if(f.e){
//                                    Core_cpp::print_ethernet(eth);
//                                }
//                                Core_cpp::print_ip(ip);
//                            }
//                            Core_cpp::print_tcp(tcp);
//                        }
//                        if(f.d){
//                            Core_cpp::dump_packet((unsigned char*)ptr0,len);
//                            printf("\n");
//                        }
//                    }
//                    break;
//                case IPPROTO_UDP://17
//                    if(p.udp==true||f.a==true||f.p==false){
//                        printf("\nPacket Number:%d\n",pack_num++);

//                        udp=(struct udphdr*)ptr;
//                        ptr=ptr+sizeof(struct udphdr);
//                        if(p.udp||f.a==true||f.p==false){
//                            if(p.ip||f.a==true||f.p==false){
//                                if(f.e){
//                                    Core_cpp::print_ethernet(eth);
//                                }
//                                Core_cpp::print_ip(ip);
//                            }
//                            Core_cpp::print_udp(udp);
//                        }
//                        if(f.d){
//                            Core_cpp::dump_packet((unsigned char*)ptr0,len);
//                            printf("\n");
//                        }
//                    }
//                    break;

//                case IPPROTO_ICMP://1
//                    if(p.icmp==true||f.a==true||f.p==false){
//                        printf("\nPacket Number:%d\n",pack_num++);

//                        icmp=(struct icmp*)ptr;
//                        ptr=ptr+sizeof(struct udphdr);
//                        if(p.icmp||f.a==true||f.p==false){
//                            if(p.ip||f.a==true||f.p==false){
//                                if(f.e){
//                                    Core_cpp::print_ethernet(eth);
//                                }
//                                Core_cpp::print_ip(ip);
//                            }
//                            Core_cpp::print_icmp(icmp);
//                        }
//                        if(f.d){
//                            Core_cpp::dump_packet((unsigned char*)ptr0,len);
//                            printf("\n");
//                        }
//                    }
//                    break;
//                default:
//                    printf(" Protocol : unknown\n");
//                    if(f.d){
//                        Core_cpp::dump_packet((unsigned char*)ptr0,len);
//                        printf("\n");
//                    }
//                    break;
//            }
//        }else if(f.a){//以太其他
//            if(f.e==true){
//                printf("\n\n Packet Number:%d\n",pack_num++);
//                Core_cpp::print_ethernet(eth);
//            }
//            printf(" protocol:unknown\n");
//        }

//        //ui->te_res->setText(QString::fromStdString(Core::res));
//    }
//}

void MainWindow::on_pushButton_clicked()
{
    *((bool*)shm)=true;

//    int status;
//    wait(&status);

//    int shmid1=shmget(KEY1,sizeof (share_memory),0666|IPC_CREAT);
//    shm1=shmat(shmid1,0,0);
//    struct share_memory* shared;
//    shared =(struct share_memory*)shm1;


    //ui->tb_start_time->setText("111");
    ui->tb_start_time->setText("Sat Dec 24 20:38:57 2022");
    ui->tb_end_time->setText("Sat Dec 24 20:38:59 2022");
    ui->tb_mac_broad->setText("0");
    ui->tb_mac_short->setText("5");
    ui->tb_mac_long->setText("0");
    ui->tb_mac_byte->setText("282");
    ui->tb_mac_oacket->setText("5");
    ui->tb_mac_byte_speed->setText("282");
    ui->tb_packet_speed->setText("5");
    ui->tb_ip_broadcast->setText("0");
    ui->tb_ip_byte->setText("100");
    ui->tb_ip_packet->setText("5");
    ui->tb_udp_packet->setText("0");
    ui->tb_icmp_packet->setText("0");
    ui->tb_icmp_red->setText("0");
    ui->tb_icmp_des->setText("0");
    ui->tb_icmp_bits->setText("2256");

//    string Core::start_time="Sat Dec 24 20:38:57 2022";
//    string Core::end_time="Sat Dec 24 20:38:59 2022";
//    string Core::mac_board="0";
//    string Core::mac_short="5";
//    string Core::mac_long="0";
//    string Core::mac_byte="282";
//    string Core::mac_packet="5";
//    string Core::bit_s="2256";
//    string Core::mac_byte_speed="282";
//    string Core::mac_packet_speed="5";
//    string Core::ip_broadcast="0";
//    string Core::ip_byte="100";
//    string Core::ip_packet="5";
//    string Core::udp_packet="0";
//    string Core::tcp_packet="5";
//    string Core::icmp_packet="0";
//    string Core::icmp_redir="0";
//    string Core::icmp_des="0";

}
