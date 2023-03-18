#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "routing_trie.h"
#include <arpa/inet.h>

routing_trie populate_routing_trie(const char* path) {
	struct route_table_entry* rtable = malloc(sizeof(struct route_table_entry) * 80000);
	int nr_entries = read_rtable(path, rtable);

	routing_trie rtrie = create_trie();

	for (int i = 0; i < nr_entries; i++) {
		add_route(rtrie, rtable[i].prefix, rtable[i].next_hop, rtable[i].mask, rtable[i].interface);
	}

	free(rtable);
	return rtrie;
}

int main(int argc, char* argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	// init(argc - 2, argv + 2);

	routing_trie rtrie = populate_routing_trie("rtable0.txt");

	{
		char addr[100];
		while (1) {
			scanf("%s", addr);
			int ip;
			inet_pton(AF_INET, addr, &ip);
			rtrie_node* node = get_route(rtrie, ip);
			if (node) {
				char nexthop[30];
				char mask[30];
				char prefix[30];
				inet_ntop(AF_INET, &node->next_hop, nexthop, 30);
				inet_ntop(AF_INET, &node->mask, mask, 30);
				inet_ntop(AF_INET, &node->prefix, prefix, 30);
				printf("Next-Hop: %s, Interface: %d, Mask: %s, Prefix: %s\n", nexthop, node->interface, mask, prefix);
			}
		}
	}

	// while (1) {

	// 	int interface;
	// 	size_t len;

	// 	interface = recv_from_any_link(buf, &len);
	// 	DIE(interface < 0, "recv_from_any_links");

	// 	struct ether_header* eth_hdr = (struct ether_header*)buf;
	// 	/* Note that packets received are in network order,
	// 	any header field which has more than 1 byte will need to be conerted to
	// 	host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
	// 	sending a packet on the link, */


	// }
}

