#ifndef ARP_SPOOF_H
#define ARP_SPOOF_H
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>

struct EthernetInfo {
    uint8_t DMac[6];
    uint8_t SMac[6];
    u_short Type;
};
/// Unify member var type
struct ArpInfo {    // char -> uint8_t
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

typedef struct {
    struct EthernetInfo ethernet_header;
    struct ArpInfo arp_header;
} L2;

void usage();
void get_my_mac(uint8_t* mac_address, char* dev);
void extract_ip(uint8_t* source_ip, char* argv);
void create_arp_header(const u_char *packet, uint8_t *mac_address, uint8_t *sender_ip, pcap_t* handle, uint8_t *sender_mac);
void arp_spoof(pcap_t* handle, const u_char *packet, uint8_t* host_mac, uint8_t* sender_mac, uint8_t* sender_ip, uint8_t* target_ip);

#endif // ARP_SPOOF_H
