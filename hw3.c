#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>



// Custom enum for different protocol versions
typedef enum {TCP, UDP, ICMP, ICMPv6, UNKNOWN, EXTH} protocol_ver;
protocol_ver cur_protocol = UNKNOWN;


// Custom struct for an IPv6 header
struct ipv6 {
	uint32_t vtcfl;
	uint16_t length;
	uint8_t next_header;
	uint8_t hop_limit;
	struct in6_addr ip_src;
	struct in6_addr ip_dst;
};

// Uses a protocol number and returns a string based off that number from a subset of protocols.
const char* get_protocol_name(int value) {
	//printf("VALUE: %d\n", value);
	const char *protocol = " ";
	switch(value)
	{
		case 0:
		protocol = "IPv6 Extension - Hop-by-hop";
		cur_protocol = EXTH;
		return protocol;

		case 1:
		protocol = "ICMP";
		cur_protocol = ICMP;
		return protocol;

		case 6:
		protocol = "TCP";
		cur_protocol = TCP;
		return protocol;

		case 17:
		protocol = "UDP";
		cur_protocol = UDP;
		return protocol;

		case 43:
		protocol = "IPv6 Extension - Routing";
		cur_protocol = EXTH;
		return protocol;

		case 44:
		protocol = "IPv6 Extension - ESP";
		cur_protocol = EXTH;
		return protocol;

		case 50:
		protocol = "IPv6 Extension - Destination options";
		cur_protocol = EXTH;
		return protocol;

		case 51:
		protocol = "IPv6 Extension - AH";
		cur_protocol = EXTH;
		return protocol;

		case 58:
		protocol = "ICMPv6";
		cur_protocol = ICMPv6;
		return protocol;

		case 60:
		protocol = "IPv6 Extension - Destination options";
		cur_protocol = EXTH;
		return protocol;

		case 135:
		protocol = "IPv6 Extension - Mobility";
		cur_protocol = EXTH;
		return protocol;

		default:
		protocol = "Unknown";
		cur_protocol = UNKNOWN;
		return protocol;
	}
}

// Uses an ICMP type number and returns the code corresponding to that number from a subset of codes.
const char* get_icmpv4_code(int value) {
	const char *code = " ";
	switch(value)
	{
		case 0:
		code = "Echo reply (used to ping)";
		return code;

		case 8:
		code = "Echo request (used to ping)";
		return code;

		default:
		code = "Unknown";
		return code;
	}
}



// Uses an ICMPv6 type number and returns the code corresponding to that number from a subset of codes.
const char* get_icmpv6_code(int value) {
	const char *code = " ";
	switch(value)
	{
		case 134:
		code = "Router Advertisement (NDP)";
		return code;

		default:
		code = "Unknown";
		return code;
	}
}
struct x{
	char from[32];
	char to[32];
	int cnt;
} ip_counter[100];
int i;

 // Prints details of an IPv4 header.
void print_ipv4_header(struct ip* ip_header) {
	printf("From: %s\n", inet_ntoa(ip_header->ip_src)); // inet_ntoa() is deprecated in favour of inet_ntop(), but bypasses the char[] arguments
	printf("To: %s\n", inet_ntoa(ip_header->ip_dst));
	printf("Protocol: %s\n", get_protocol_name(ip_header->ip_p));
	int j;
	for(j=0;j<i;j++){
		if((strcmp(ip_counter[j].from,inet_ntoa(ip_header->ip_src))==0) && (strcmp(ip_counter[j].to,inet_ntoa(ip_header->ip_dst))==0)){
			ip_counter[j].cnt++;
			break;
		}
	}
	if(j==i){
		i++;
		strcpy(ip_counter[i].from,inet_ntoa(ip_header->ip_src));
		stpcpy(ip_counter[i].to,inet_ntoa(ip_header->ip_dst));
		ip_counter[i].cnt=1;
	}
	
}

// Prints details of an IPv6 header.
void print_ipv6_header(struct ipv6* ipv6_header) {
	char srcaddr[32];
	char dstaddr[32];
	inet_ntop(AF_INET6, &ipv6_header->ip_src, srcaddr, sizeof(srcaddr)); // inet_ntop() takes a binary address (both IP versions) and returns in text form
	inet_ntop(AF_INET6, &ipv6_header->ip_dst, dstaddr, sizeof(dstaddr));
	printf("From: %s\n", srcaddr);
	printf("To: %s\n", dstaddr);
	printf("Protocol: %s\n", get_protocol_name(ipv6_header->next_header));
	
	int j;
	for(j=0;j<i;j++){
		if((strcmp(ip_counter[j].from,srcaddr)==0) && (strcmp(ip_counter[j].to,dstaddr)==0)){
			ip_counter[j].cnt++;
			break;
		}
	}
	if(j==i){
		i++;
		strcpy(ip_counter[i].from,srcaddr);
		strcpy(ip_counter[i].to,dstaddr);
		ip_counter[i].cnt=1;
	}
}
// Prints details of a TCP header.
void print_tcp_header(struct tcphdr* tcp_header) {
	printf("Src port: %d\n", ntohs(tcp_header->th_sport)); // ntohs() takes a 16-bit number in TCP/IP network byte order and returns in host byte order
	printf("Dst port: %d\n", ntohs(tcp_header->th_dport));
}

// Prints details of a UDP header.
void print_udp_header(struct udphdr* udp_header) {
	printf("Src port: %d\n", ntohs(udp_header->uh_sport));
	printf("Dst port: %d\n", ntohs(udp_header->uh_dport));
}

// Prints details of an ICMP (v6 too) header.
void print_icmp_header(struct icmp* icmp_header, protocol_ver version) {
	if (version == ICMP) {
		printf("ICMP type %d: %s\n", icmp_header->icmp_type, get_icmpv4_code(icmp_header->icmp_type));
	}
	else if (version == ICMPv6) {
		printf("ICMPv6 type %d: %s\n", icmp_header->icmp_type, get_icmpv6_code(icmp_header->icmp_type));
	}
}


int main(int argc, char **argv)
{
	struct pcap_pkthdr header;
	const u_char *cur_packet;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL) {
		printf("Couldn't open pcap file %s: %s\n", argv[1], errbuf);
	}

	int count = 1; 
	for(i=0;i<100;i++)
	   ip_counter[i].cnt=0;
    i=0;

	// Loop through packets
	while (cur_packet = pcap_next(handle, &header)) {
		bool ipv4_flag = false;
		bool ipv6_flag = false;
		bool ppoe_flag = false;

		printf("# %d\n", count);
		count = count + 1;

		
		int packet_type = ((int) (cur_packet[12]) << 8) | (int) cur_packet[13];

		// Set flags based on ether type.
		switch(packet_type)
		{
			case 2048:
			printf("Ether type: IPv4\n");
			ipv4_flag = true;
			break;

			case 34525:
			printf("Ether type: IPv6\n");
			ipv6_flag = true;
			break;

			case 34916:
			printf("Ether type: PPOE\n");
			ppoe_flag = true;
			break;

			default:
			printf("Unknown ether type.\n");
			break;
		}
		
		// 2. Get header info: from/to address, protocol.
		if (ipv4_flag) {
			cur_packet += 14;
			struct ip *ip_header = (struct ip*) cur_packet;
			print_ipv4_header(ip_header);
		}
		else if (ipv6_flag) {
			cur_packet += 14;
			struct ipv6 *ipv6_header = (struct ipv6*) cur_packet;
			print_ipv6_header(ipv6_header);
		}
		else if (ppoe_flag) {
			cur_packet += 42;
			struct ipv6 *ipv6_header = (struct ipv6*) cur_packet;
			print_ipv6_header(ipv6_header);
		}

		
		// 3. Get packet info: src/dst ports, ICMP info.
		// IPv4
		if (ipv4_flag && cur_protocol == TCP) {
			cur_packet += 20;
			struct tcphdr *tcp_header = (struct tcphdr*) cur_packet;
			print_tcp_header(tcp_header);
		}
		else if (ipv4_flag && cur_protocol == UDP) {
			cur_packet += 20;
			struct udphdr *udp_header = (struct udphdr*) cur_packet;
			print_udp_header(udp_header);
		}
		else if (ipv4_flag && cur_protocol == ICMP) {
			cur_packet += 20;
			struct icmp *icmp_header = (struct icmp*) cur_packet;
			print_icmp_header(icmp_header, ICMP);
		}
		// IPv6
		else if (ipv6_flag && cur_protocol == TCP) {
			cur_packet += 40;
			struct tcphdr *tcp_header = (struct tcphdr*) cur_packet;
			print_tcp_header(tcp_header);
		}
		else if (ipv6_flag && cur_protocol == UDP) {
			cur_packet += 40;
			struct udphdr *udp_header = (struct udphdr*) cur_packet;
			print_udp_header(udp_header);
		}
		else if (ipv6_flag && cur_protocol == ICMPv6) {
			cur_packet += 40;
			struct icmp *icmp_header = (struct icmp*) cur_packet;
			print_icmp_header(icmp_header, ICMPv6);
		}
		
		printf("\n");
	}
	int j=0;
	for(j=1;j<=i;j++){
			printf("(%s,%s) : %d\n",ip_counter[j].from,ip_counter[j].to,ip_counter[j].cnt);
    }
	pcap_close(handle);
	return 0;
}

