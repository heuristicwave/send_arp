#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <cstdlib>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
//#include <net/if.h>
#include <unistd.h>

struct EthernetInfo {
    u_char DMac[6];
    u_char SMac[6];
    u_short Type;
};

struct ArpInfo {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    u_char sender_mac[6];
    u_char sender_ip[4];
    u_char target_mac[6];
    u_char target_ip[4];
};

typedef struct {
    struct EthernetInfo ethernet_header;
    struct ArpInfo arp_header;
} L2;

void usage();
void create_arp_header(struct pcap_pkthdr *header, const u_char *packet, char* argv);
void get_my_mac(uint8_t* address);
void extract_ip(uint8_t* source_ip, char* argv);

int main(int argc, char* argv[])
{
    if (argc != 4) {
      usage();
      //return -1;
    }

    char* dev = argv[1];
    // char* dev = "dum0"; // using debug
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    //if (res == 0) continue;
    //if (res == -1 || res == -2) break;

    create_arp_header(header, packet, argv[3]); // call function print basic info

    pcap_close(handle);

    return 0;
}

void usage(){
    printf("usage : send_arp <interface> <sender ip> <target ip>\n");
    // ex : send_arp wlan0 192.168.10.2 192.168.10.1
}

void create_arp_header(struct pcap_pkthdr *header, const u_char *packet, char* argv){
    L2* l2_layer = const_cast<L2*>(reinterpret_cast<const L2*>(packet));

    uint8_t broadcast_arp[42] = {0};
    uint8_t mac_address[6] = {0};
    uint8_t target_ip[4] = {0};

    //change_ip(target_ip, argv[3]);

    printf("host device mac address : ");
    get_my_mac(mac_address);

    for(int i=0; i<6; i++){
        l2_layer->ethernet_header.DMac[i] = 0xff;
        l2_layer->ethernet_header.SMac[i] = mac_address[i];
    }
    l2_layer->ethernet_header.Type = htons(0x0806);
    l2_layer->arp_header.hardware_type = htons(0x0001);
    l2_layer->arp_header.protocol_type = htons(0x0800);
    l2_layer->arp_header.opcode = htons(0x0001);

    for(int i=0; i<6; i++){
        l2_layer->arp_header.sender_mac[i] = l2_layer->ethernet_header.SMac[i];
        //memcpy(l2_layer->arp_header.sender_mac[i], l2_layer->ethernet_header.SMac[i], 6);
        l2_layer->arp_header.target_mac[i] = 00;
    }

    extract_ip(target_ip, &argv[3]);

    for(int i=0; i<4; i++){
        l2_layer->arp_header.sender_ip[i] = 00;
        l2_layer->arp_header.target_ip[i] = target_ip[i];
    }

}

void extract_ip(uint8_t* source_ip, char* argv){
    //uint8_t* target_ip = source_ip;
    char* split_ip;

    split_ip = strtok(argv,".");
    source_ip[1] = *split_ip;
    printf("\npart 1 ip: %s", split_ip);
    printf("\number 1 ip: %c", source_ip[1]);
    split_ip = strtok (NULL,".");
    source_ip[2] = *split_ip;
    printf("\npart 2 ip: %s",split_ip);
    printf("\number 2 ip: %c", source_ip[2]);

    split_ip = strtok (NULL,".");
    printf("\npart 3 ip: %s",split_ip);
    split_ip = strtok (NULL,".");
    printf("\npart 4 ip: %s",split_ip);
}

void get_my_mac(uint8_t* address){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "eth0");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
      int i;
      for (i = 0; i < 6; ++i){
          address[i] = static_cast<uint8_t>(s.ifr_addr.sa_data[i]);
          printf("%02x", address[i]);
          if(i!=5) printf(":");
      }
      puts("\n");
    }
}
