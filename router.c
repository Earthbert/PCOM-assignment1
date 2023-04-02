#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "routing_trie.h"
#include "arp_table.h"

#include <string.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Read routing table and store it in a routing trie
	routing_trie rtrie = create_trie();
	read_rtable(argv[1], rtrie);

	// Create ARP table
	struct arp_table arp_table;
	create_arp_table(&arp_table);

	queue to_be_handled_q = queue_create();
	queue handled_q = queue_create();

	const uint8_t broadcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,0xFF };

	while (1) {

		int interface = 0;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		// Check if router is L2 dest or frame is broadcasted
		{
			uint8_t mac_addr[6];
			get_interface_mac(interface, mac_addr);
			if (memcmp(eth_hdr->ether_dhost, mac_addr, 6) && memcmp(eth_hdr->ether_dhost, broadcast_mac, 6))
				continue;
		}

		if (__builtin_bswap16(eth_hdr->ether_type) == 0x0800) {
			printf("Received IPV4 request\n");
			// Handle IPv4 package
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// Check if destination is this router
			{
				uint32_t interface_ip;
				inet_pton(AF_INET, get_interface_ip(interface), &interface_ip);
				if (interface_ip == ip_hdr->daddr) {
					// If it is send ICMP response
					if (ip_hdr->protocol != IPPROTO_ICMP)
						continue;
					uint32_t headers_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
					// Save ICMP payload
					uint32_t send_len = len - headers_len;
					char *send_buf = malloc(send_len);
					memcpy(send_buf, buf + headers_len, send_len);

					// Prepare ICMP header
					struct icmphdr *icmp_h = (struct icmphdr *)((char *)ip_hdr + sizeof(struct iphdr));
					icmp_h->type = 0x0;
					icmp_h->code = 0;
					icmp_h->checksum = 0;
					icmp_h->checksum = __builtin_bswap16(checksum((uint16_t *)icmp_h, sizeof(struct icmphdr)));

					// Prepare IP header
					ip_hdr->daddr = ip_hdr->saddr;
					inet_pton(AF_INET, get_interface_ip(interface), &ip_hdr->saddr);
					ip_hdr->ttl = 64;
					ip_hdr->protocol = IPPROTO_ICMP;
					ip_hdr->tot_len = __builtin_bswap16((uint16_t)sizeof(struct iphdr) + sizeof(struct icmphdr) + send_len);
					ip_hdr->check = 0;
					ip_hdr->check = __builtin_bswap16(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

					// Prepare L2 header
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					get_interface_mac(interface, eth_hdr->ether_shost);

					// Copy ICMP payload
					memcpy(buf + headers_len, send_buf, send_len);
					// Send packet
					printf("%d\n", headers_len + send_len);
					send_to_link(interface, buf, headers_len + send_len);
					free(send_buf);
					continue;
				}
			}

			// Verify checksum
			{
				uint16_t check = __builtin_bswap16(ip_hdr->check);
				ip_hdr->check = 0;
				uint16_t new_check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
				if (check != new_check) {
					printf("Incorrect checksum\n");
					continue;
				}
			}

			// Verify TTL
			{
				if (ip_hdr->ttl <= 1) {
					// Save ICMP payload
					uint32_t send_len = sizeof(struct iphdr) + 8;
					char *send_buf = malloc(send_len);
					memcpy(send_buf, ip_hdr, send_len);

					// Prepare ICMP header
					struct icmphdr *icmp_h = (struct icmphdr *)((char *)ip_hdr + sizeof(struct iphdr));
					memset(icmp_h, 0, sizeof(struct icmphdr));
					icmp_h->type = 0xB;
					icmp_h->code = 0;
					icmp_h->checksum = 0;
					icmp_h->checksum = __builtin_bswap16(checksum((uint16_t *)icmp_h, sizeof(struct icmphdr)));

					// Prepare IP header
					ip_hdr->daddr = ip_hdr->saddr;
					inet_pton(AF_INET, get_interface_ip(interface), &ip_hdr->saddr);
					ip_hdr->ttl = 64;
					ip_hdr->protocol = IPPROTO_ICMP;
					ip_hdr->tot_len = __builtin_bswap16((uint16_t)sizeof(struct iphdr) + sizeof(struct icmphdr) + send_len);
					ip_hdr->check = 0;
					ip_hdr->check = __builtin_bswap16(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

					// Prepare L2 header
					uint32_t headers_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					get_interface_mac(interface, eth_hdr->ether_shost);

					// Copy ICMP payload
					memcpy(buf + headers_len, send_buf, send_len);
					// Send packet
					send_to_link(interface, buf, headers_len + send_len);
					free(send_buf);
					continue;
				}
				ip_hdr->ttl--;
			}

			// Search for route
			rtrie_node *route;
			{
				route = get_route(rtrie, ip_hdr->daddr);
				if (!route) {
					// Save ICMP payload
					uint32_t send_len = sizeof(struct iphdr) + 8;
					char *send_buf = malloc(send_len);
					memcpy(send_buf, ip_hdr, send_len);

					// Prepare ICMP header
					struct icmphdr *icmp_h = (struct icmphdr *)((char *)ip_hdr + sizeof(struct iphdr));
					memset(icmp_h, 0, sizeof(struct icmphdr));
					icmp_h->type = 0x3;
					icmp_h->code = 0;
					icmp_h->checksum = 0;
					icmp_h->checksum = __builtin_bswap16(checksum((uint16_t *)icmp_h, sizeof(struct icmphdr)));

					// Prepare IP header
					ip_hdr->daddr = ip_hdr->saddr;
					inet_pton(AF_INET, get_interface_ip(interface), &ip_hdr->saddr);
					ip_hdr->ttl = 64;
					ip_hdr->protocol = IPPROTO_ICMP;
					ip_hdr->tot_len = __builtin_bswap16((uint16_t)sizeof(struct iphdr) + sizeof(struct icmphdr) + send_len);
					ip_hdr->check = 0;
					ip_hdr->check = __builtin_bswap16(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

					// Prepare L2 header
					uint32_t headers_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					get_interface_mac(interface, eth_hdr->ether_shost);

					// Copy ICMP payload
					memcpy(buf + headers_len, send_buf, send_len);
					// Send packet
					send_to_link(interface, buf, headers_len + send_len);
					free(send_buf);
					continue;
				}
			}

			// Recalculate checksum
			{
				ip_hdr->check = 0;
				uint16_t new_check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
				ip_hdr->check = __builtin_bswap16(new_check);
			}

			// Prepare L2 header
			{
				get_interface_mac(route->interface, eth_hdr->ether_shost);
				struct arp_entry *arp_entry = get_mac_addr(&arp_table, route->next_hop);
				if (!arp_entry) {
					// Save packet for later
					packet_t *pack = malloc(sizeof(packet_t));
					pack->buf = malloc(len);
					pack->len = len;
					memcpy(pack->buf, buf, len);
					queue_enq(to_be_handled_q, pack);

					// Send ARP request
					// Prepare L2 header for ARP Request
					get_interface_mac(route->interface, eth_hdr->ether_shost);
					memset(eth_hdr->ether_dhost, 0xFF, 6);
					eth_hdr->ether_type = __builtin_bswap16(0x0806);

					// Prepare ARP header
					{
						struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
						arp_hdr->op = __builtin_bswap16(0x1); // Request
						arp_hdr->htype = __builtin_bswap16(0x1); // Ethernet (10Mb)
						arp_hdr->ptype = __builtin_bswap16(0x0800); // IPv4
						arp_hdr->hlen = 0x6; // MAC dimension
						arp_hdr->plen = 0x4; // IPv4 dimension
						get_interface_mac(route->interface, arp_hdr->sha); // Sender MAC addr
						inet_pton(AF_INET, get_interface_ip(route->interface), &arp_hdr->spa); // Sender IPv4 addr
						memset(arp_hdr->tha, 0x0, 6); // Target MAC Addr
						arp_hdr->tpa = route->next_hop; // Target IPv4 addr
					}
					// Send ARP request
					len = sizeof(struct ether_header) + sizeof(struct arp_header);
					send_to_link(route->interface, buf, len);
					continue;
				}
				memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);
			}

			// Send packet
			send_to_link(route->interface, buf, len);
		} else if (__builtin_bswap16(eth_hdr->ether_type) == 0x0806) {
			// Handle ARP packet
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			if (__builtin_bswap16(arp_hdr->op) == 0x1) {
				// Respond to ARP request
				uint32_t interface_ip;
				inet_pton(AF_INET, get_interface_ip(interface), &interface_ip);
				if (arp_hdr->tpa != interface_ip) {
					continue;
				}
				// Prepare ARP header for response
				arp_hdr->op = __builtin_bswap16(0x2);
				memcpy(arp_hdr->tha, arp_hdr->sha, 6);
				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = interface_ip;
				get_interface_mac(interface, arp_hdr->sha);
				// Prepare L2 header
				get_interface_mac(interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, arp_hdr->tha, 6);

				send_to_link(interface, buf, len);
			} else {
				// Handle ARP response
				// Save response in ARP table
				struct arp_entry recv_arp;
				recv_arp.ip = arp_hdr->spa;
				memcpy(recv_arp.mac, arp_hdr->sha, 6);
				add_arp_entry(&arp_table, &recv_arp);
				// Handle all packets in the queue
				while (!queue_empty(to_be_handled_q)) {
					packet_t *pack = queue_deq(to_be_handled_q);
					struct ether_header *eth_h = (struct ether_header *)pack->buf;
					struct iphdr *ip_h = (struct iphdr *)(pack->buf + sizeof(struct ether_header));
					struct rtrie_node *route = get_route(rtrie, ip_h->daddr);
					struct arp_entry *arp_entry = get_mac_addr(&arp_table, route->next_hop);
					if (!arp_entry) { // If we still don't know MAC addr for packet add it back into queue
						queue_enq(handled_q, pack);
						continue;
					}
					// Send packet with known dest
					memcpy(eth_h->ether_dhost, arp_entry->mac, 6);
					send_to_link(route->interface, pack->buf, pack->len);
					free(pack->buf);
					free(pack);
				}
				queue __swap_q = handled_q;
				handled_q = to_be_handled_q;
				to_be_handled_q = __swap_q;
			}
		} else {
			printf("Received unknown request\n");
		}
	}
}

