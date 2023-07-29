#include"core.cpp"


int main(int argc,char *argv[]){//Core_cpp::
    int opt;

    // int opt[OPTNUM];
    // opt[ETHER]=OFF;
    // opt[ARP]=ON;
    // opt[IP]=ON;
    // opt[TCP]=ON;
    // opt[UDP]=ON;
    // opt[ICMP]=ON;
    // opt[DUMP]=OFF;
    // opt[ALL]=OFF;

    //sudo ./testip2 -a

    while((opt=getopt(argc,argv,"aedhp:i:f:"))!=-1){
        switch(opt){
            case 'a':
                f.a=true;//opt[ALL]=ON;
                break;
            case 'e':
                f.e=true;//opt[ETHER]=ON;
                break;
            case 'd':
                f.d=true;//opt[DUMP]=ON;
                break;
            case 'h':
                Core_cpp::help();
                exit(0);
            case 'i':
                f.i=true;
                if(strlen(optarg)<IFRLEN){
                    strcpy(f.ifname,optarg);
                }else{
                    printf("the size of the ifname is too big\n");
                    exit(1);
                }
                break;
            case 'p':
                f.p=true;//opt[ARP]=OFF;opt[IP]=OFF;opt[TCP]=OFF;opt[UDP]=OFF;opt[ICMP]=OFF;
                optind--;
                while(argv[optind]!=NULL&&argv[optind][0]!='-'){
                    if(strcmp(argv[optind],"arp")==0)
                        p.arp=true;//opt[ARP]=ON;
                    else if(strcmp(argv[optind],"ip")==0)
                        p.ip=true;//opt[IP]=ON;
                    else if(strcmp(argv[optind],"icmp")==0)
                        p.icmp=true;//opt[ICMP]=ON;
                    else if(strcmp(argv[optind],"tcp")==0)
                        p.tcp=true;//opt[TCP]=ON;
                    else if(strcmp(argv[optind],"udp")==0)
                        p.udp=true;//opt[UDP]=ON;
                    else{
                        printf("unknown parameter: %s",argv[optind]);
                        exit(1);
                    }

                    optind++;
                }
                break;
            case 'f':
                f.f=true;//设定为过滤出需要的包
                optind--;
                while(argv[optind]!=NULL&&argv[optind][0]!='-'){
                    if(strcmp(argv[optind],"ip")==0){
                        pf.i=true;
                        optind++;
                    if(argv[optind]==NULL){
                        printf("input the ip address\n");
                        exit(1);
                    }
                    if(Core_cpp::ip_atou(argv[optind],&pf.ip)==1){
                        printf("bad parameter of ip address:%s\n",argv[optind]);
                        exit(1);
                    }
                    //printf("pf.ip:%u\n",pf.ip);
                    }else if(strcmp(argv[optind],"port")==0){
                        pf.p=true;
                        optind++;
                        if(argv[optind]==NULL){
                            printf("input the port number\n");
                            exit(1);
                        }
                        pf.port=atoi(argv[optind]);
                        if(pf.port<=0){
                            printf("bad parameter of port:%s\n",argv[optind]);
                            exit(1);
                        }
                    }else{
                        printf("unknown parameter:%s",argv[optind]);
                        exit(1);
                    }
                    optind++;
                }
                break;
            case ':':
                printf("option need a value\n");
                break;
            case '?':
                printf("unknown option:%c\n",optopt);
                exit(1);
            default:
                printf("unknown error");
                exit(1);
        }
    }
    if(optind<argc){
        for(;optind<argc;optind++){
            printf("unknown:%s\n",argv[optind]);
        }
        printf(" \n");
        Core_cpp::help();
        exit(1);
    }

    //信号
    //signal(SIGINT,Core_cpp::endfun);
    //原始套接字
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
            if((ret=Core_cpp::getif1(ifname,ret))==-1){
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
    while(true){
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
        Core_cpp::p_count(eth);
        //网元发现
        Core_cpp::find_ne(eth->ether_dhost);
        Core_cpp::find_ne(eth->ether_shost);
        //过滤
        if(f.f==true){
            if(Core_cpp::p_filter(eth)==1)
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
                    Core_cpp::print_ethernet(eth);
                }
                arp=(struct ether_arp*)ptr;//ARP匹配
                Core_cpp::print_arp(arp);
            }
        }else if(ntohs(eth->ether_type)==ETHERTYPE_IP){//IP ?????
            ip=(struct ip *)ptr;//ip匹配
            ptr=ptr+((int)(ip->ip_hl)<<2);//ip首部长乘4(Byte/char)
            // printf("\n\n Packet Number:%d\n",pack_num++);
            if(p.ip==true&&p.tcp==false&&p.udp==false&&p.icmp==false){
                if(f.e==true){
                    Core_cpp::print_ethernet(eth);
                }
                Core_cpp::print_ip(ip);
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
                                    Core_cpp::print_ethernet(eth);
                                }
                                Core_cpp::print_ip(ip);
                            }
                            Core_cpp::print_tcp(tcp);
                        }
                        if(f.d){
                            Core_cpp::dump_packet((unsigned char*)ptr0,len);
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
                                    Core_cpp::print_ethernet(eth);
                                }
                                Core_cpp::print_ip(ip);
                            }
                            Core_cpp::print_udp(udp);
                        }
                        if(f.d){
                            Core_cpp::dump_packet((unsigned char*)ptr0,len);
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
                                    Core_cpp::print_ethernet(eth);
                                }
                                Core_cpp::print_ip(ip);
                            }
                            Core_cpp::print_icmp(icmp);
                        }
                        if(f.d){
                            Core_cpp::dump_packet((unsigned char*)ptr0,len);
                            printf("\n");
                        }
                    }
                    break;
                default:
                    printf(" Protocol : unknown\n");
                    if(f.d){
                        Core_cpp::dump_packet((unsigned char*)ptr0,len);
                        printf("\n");
                    }
                    break;
            }
            //
            // if(f.p&&(!p.ip)&&(!p.icmp)&&(!p.tcp)&&(!p.udp))
            // 	continue;
            // printf("\n\n Packet Number:%d\n",pack_num++);
            // ip=(struct ip *)ptr;//ip匹配
            // ptr=ptr+((int)(ip->ip_hl)<<2);//ip首部长乘4(Byte/char)
            // if(f.e==true){
            // 	print_ethernet(eth);
            // }
            // if(f.p==true&&p.ip==true){//????? f.p==false||p.ip==true
            // 	print_ip(ip);
            // }
            // switch(ip->ip_p){
            // 	case IPPROTO_TCP://TCP匹配
            //         //gcc -o testip2 test.c
            //         //sudo ./testip2 -p tcp
            //         print(2);
            // 		tcp=(struct tcphdr *)ptr;
            // 		//ptr=ptr+((int)(tcp->th_off)<<2);
            // 		if(f.p==true&&p.tcp==true)//?????
            // 			print_tcp(tcp);
            // 		break;
            // 	case IPPROTO_UDP://UDP匹配
            //         //gcc -o testip2 test.c
            //         //sudo ./testip2 -p udp
            //         print(3);
            // 		udp=(struct udphdr *)ptr;
            // 		//ptr=ptr+sizeof(struct udphdr);
            // 		if(f.p==true&&p.udp==true)//?????
            // 			print_udp(udp);
            // 		break;
            // 	case IPPROTO_ICMP://ICMP匹配
            //         //gcc -o testip2 test.c
            //         //sudo ./testip2 -p icmp
            //         print(4);
            // 		icmp=(struct icmp *)ptr;
            // 		//ptr=ptr+sizeof(struct udphdr);
            // 		if(f.p==true&&p.icmp==true)//?????
            // 			print_icmp(icmp);
            // 		break;
            // 	default://IP其他
            // 		printf("Protocol:unknown\n");
            // 		break;
            // 	}
        }else if(f.a){//以太其他
            if(f.e==true){
                printf("\n\n Packet Number:%d\n",pack_num++);
                Core_cpp::print_ethernet(eth);
            }
            printf(" protocol:unknown\n");
        }
        // if(f.d){
        // 	dump_packet(ptr0,len);
        // 	printf("\n");
        // }
        //gcc -o testip2 test.c
        //sudo ./testip2 -d -p tcp
        //sudo ./testip2 -d -p udp
        //sudo ./testip2 -d -p icmp
        //sudo ./testip2 -d -p ip
    }
    return 0;
}
