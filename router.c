#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "routing_trie.h"
#include "arp_table.h"

#include <string.h>
#include <arpa/inet.h>

int main(int argc, char* argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Read routing table and store it in a routing trie
	routing_trie rtrie = create_trie();
	read_rtable(argv[1], rtrie);

	// Read ARP table
	struct arp_table arp_table;
	create_arp_table(&arp_table);
	arp_table.len = parse_arp_table("arp_table.txt", arp_table.entries);

	while (1) {

		int interface = 0;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header* eth_hdr = (struct ether_header*)buf;
		struct iphdr* ip_hdr = (struct iphdr*)(buf + sizeof(struct ether_header));

		// Check if destination is this router
		{
			uint32_t interface_ip;
			inet_pton(AF_INET, get_interface_ip(interface), &interface_ip);
			if (interface_ip == ip_hdr->daddr) {
				printf("Package for this device\n");
				continue;
			}
		}

		// Verify checksum
		{
			uint16_t check = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			uint16_t new_check = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));
			if (check != new_check) {
				printf("Incorrect checksum\n");
				continue;
			}
		}

		// Verify TTL
		{
			printf("TTL: %hhd\n", ip_hdr->ttl);
			if (ip_hdr->ttl < 1) {
				printf("No more time to live\n");
				continue;
			}
			ip_hdr->ttl--;
		}

		// Search for routing table
		rtrie_node* route;
		{
			route = get_route(rtrie, ip_hdr->daddr);
			if (!route) {
				printf("Destination unreachable\n");
				continue;
			}
		}

		// Recalculate checksum
		{
			ip_hdr->check = 0;
			uint16_t new_check = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));
			ip_hdr->check = htons(new_check);
		}

		// Prepare L2 header
		{
			uint8_t mac[6];
			get_interface_mac(route->interface, mac);
			memcpy(&eth_hdr->ether_shost, mac, 6 * sizeof(uint8_t));
			struct arp_entry* arp_entry = get_mac_addr(&arp_table, route->next_hop);
			if (!arp_entry) {
				printf("No MAC addr for next-hop\n");
			}
			memcpy(&eth_hdr->ether_dhost, arp_entry->mac, 6 * sizeof(uint8_t));
		}

		// Send package
		send_to_link(route->interface, buf, len);
	}
}

