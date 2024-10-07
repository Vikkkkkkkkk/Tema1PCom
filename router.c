#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

#define ETHER_IPv4 0x0800
#define ETHER_ARP 0x0806
#define ROUTE_TABLE_DIM 100000
#define ARP_TABLE_DIM 1000

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define OLD_IPv4_PAYLOAD 8
#define MAC_LEN 6

#define MAC_BROADCAST "\xff\xff\xff\xff\xff\xff"

struct route_table_entry *rtable = NULL;
int rtable_length = 0;

struct arp_table_entry *arp_table = NULL;
int arp_table_length = 0;

queue packets_queue;
int packets_queue_len;

struct packet_ipv4 {
	int interface;
	char *payload;
	size_t len;
	uint32_t next_hop;
};

struct TrieNode {
	struct TrieNode *left;
	struct TrieNode *right;
	struct route_table_entry *entry;
};

struct TrieNode *root = NULL;

struct TrieNode *create_trie_node() {
	struct TrieNode *node = malloc(sizeof(struct TrieNode));
	node->left = NULL;
	node->right = NULL;
	node->entry = NULL;
	return node;
}

void insert_trie_node(struct TrieNode *root, struct route_table_entry *entry) {
	struct TrieNode *node = root;
	uint32_t mask = ntohl(entry->mask);
	for (int i = 31; i >= 0; i--) {
		if (mask == 0)
			break;
		uint32_t bit = (ntohl(entry->prefix) >> i) & 1;
		if (bit == 0) {
			if (node->left == NULL)
				node->left = create_trie_node();
			node = node->left;
		}
		else {
			if (node->right == NULL)
				node->right = create_trie_node();
			node = node->right;
		}
		mask = mask << 1;
	}
	node->entry = entry;
}

struct route_table_entry *get_best_route(uint32_t dest_ip) {
	struct TrieNode *node = root;

	for (int i = 31; i >= 0; i--) {
		uint32_t bit = (ntohl(dest_ip) >> i) & 1;
		if (bit == 0) {
			if (node->left == NULL)
				return node->entry;
			node = node->left;
		}
		else {
			if (node->right == NULL)
				return node->entry;
			node = node->right;
		}
	}
	return node->entry;
}

void complete_trie() {
	root = create_trie_node();
	for (int i = 0; i < rtable_length; i++)
		insert_trie_node(root, &rtable[i]);
}

struct arp_table_entry *get_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_table_length; i++)
		if (arp_table[i].ip == ip)
			return &arp_table[i];
	return NULL;
}

void send_icmp_message(int interface, char *buf, size_t *len, uint8_t type, uint8_t code) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	char *data = malloc(sizeof(struct iphdr) + OLD_IPv4_PAYLOAD);
	memcpy(data, ip_hdr, sizeof(struct iphdr) + OLD_IPv4_PAYLOAD);

	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->ttl = 64;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + OLD_IPv4_PAYLOAD);
	ip_hdr->id = 0;
	ip_hdr->protocol = IPPROTO_ICMP;

	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	memset(icmp_hdr, 0, sizeof(struct icmphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = code;

	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), data, sizeof(struct iphdr) + OLD_IPv4_PAYLOAD);
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + OLD_IPv4_PAYLOAD));

	*len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + OLD_IPv4_PAYLOAD;

	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
	struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);

	uint8_t s_mac[MAC_LEN];
	get_interface_mac(best_route->interface, s_mac);
	memcpy(eth_hdr->ether_shost, s_mac, MAC_LEN);
	memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_LEN);

	send_to_link(best_route->interface, buf, *len);
}

void send_icmp_reply(int interface, char *buf, size_t *len) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	char *data = malloc(ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));
	memcpy(data, ip_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));

	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->ttl = 64;

	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	icmp_hdr->type = 0;
	icmp_hdr->code = 0;

	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));

	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), data, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));

	*len = sizeof(struct ether_header) + ntohs(ip_hdr->tot_len);

	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
	struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
	
	uint8_t s_mac[MAC_LEN];
	get_interface_mac(best_route->interface, s_mac);
	memcpy(eth_hdr->ether_shost, s_mac, MAC_LEN);
	memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_LEN);

	send_to_link(best_route->interface, buf, *len);
}

void received_arp_request(int interface, char *buf, size_t len) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

	arp_hdr->op = htons(ARP_REPLY);
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = inet_addr(get_interface_ip(interface));
	memcpy(arp_hdr->tha, arp_hdr->sha, MAC_LEN);
	get_interface_mac(interface, arp_hdr->sha);

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
	get_interface_mac(interface, eth_hdr->ether_shost);

	send_to_link(interface, buf, len);
}

void received_arp_reply(int interface, char *buf, size_t len) {
	struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

	memcpy(arp_table[arp_table_length].mac, arp_hdr->sha, MAC_LEN);
	arp_table[arp_table_length].ip = arp_hdr->spa;
	arp_table_length++;

	for (int i = 0; i < packets_queue_len; i++) {
		struct packet_ipv4 *packet = (struct packet_ipv4 *) queue_deq(packets_queue);
		struct ether_header *eth_hdr = (struct ether_header *) packet->payload;

		if (ntohl(packet->next_hop) == ntohl(arp_hdr->spa)) {
			memcpy(eth_hdr->ether_dhost, arp_hdr->sha, MAC_LEN);
			get_interface_mac(packet->interface, eth_hdr->ether_shost);

			send_to_link(packet->interface, packet->payload, packet->len);

			packets_queue_len--;
		} else
			queue_enq(packets_queue, packet);
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * ROUTE_TABLE_DIM);
	rtable_length = read_rtable(argv[1], rtable);
	complete_trie();

	arp_table = malloc(sizeof(struct arp_table_entry) * ARP_TABLE_DIM);

	packets_queue = queue_create();

	while (1)
	{

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		if (len <= 0)
			continue;

		struct ether_header *eth_hdr = (struct ether_header *)buf;

		if (ntohs(eth_hdr->ether_type) == ETHER_IPv4) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			if (ip_hdr->ttl <= 1) {
				send_icmp_message(interface, buf, &len, 11, 0);
				continue;
			}

			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if (best_route == NULL) {
				send_icmp_message(interface, buf, &len, 3, 0);
				continue;
			}
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
				send_icmp_reply(interface, buf, &len);
				continue;
			}

			uint16_t ip_checksum = ip_hdr->check;
			ip_hdr->check = 0;
			if (htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) != ip_checksum) {
				continue;
			}

			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
			if (arp_entry == NULL) {
				struct packet_ipv4 *packet = malloc(sizeof(struct packet_ipv4));
				struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));

				packet->payload = malloc(len);
				packet->interface = best_route->interface;
				packet->next_hop = best_route->next_hop;
				packet->len = len;
				memcpy(packet->payload, buf, len);
				queue_enq(packets_queue, (void *) packet);
				packets_queue_len++;

				eth_hdr->ether_type = htons(ETHER_ARP);
				get_interface_mac(interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, MAC_BROADCAST, MAC_LEN);

				arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
				get_interface_mac(best_route->interface, arp_hdr->sha);
				arp_hdr->tpa = best_route->next_hop;
				memcpy(arp_hdr->tha, MAC_BROADCAST, MAC_LEN);
				arp_hdr->op = htons(ARP_REQUEST);
				arp_hdr->plen = 4;
				arp_hdr->hlen = MAC_LEN;
				arp_hdr->ptype = htons(ETHER_IPv4);
				arp_hdr->htype = htons(1);

				memcpy(buf + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
				len = sizeof(struct ether_header) + sizeof(struct arp_header);

				send_to_link(best_route->interface, buf, len);

				continue;
			}

			uint8_t s_mac[MAC_LEN];
			get_interface_mac(best_route->interface, s_mac);
			memcpy(eth_hdr->ether_shost, s_mac, MAC_LEN);
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_LEN);

			send_to_link(best_route->interface, buf, len);
		} else if (ntohs(eth_hdr->ether_type) == ETHER_ARP) {
			struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
			if (ntohs(arp_hdr->op) == ARP_REQUEST)
				received_arp_request(interface, buf, len);
			else if (ntohs(arp_hdr->op) == 2)
				received_arp_reply(interface, buf, len);
		}
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
	}
}
