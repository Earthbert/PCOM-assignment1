#include "list.h"
#include "util.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>

typedef struct trie_node trie_node;

struct trie_node {
	uint32_t interface;
	uint32_t ip;
	trie_node children[2];
};

struct routing_trie {
	trie_node* root;
};

typedef struct routing_trie* routing_trie;

routing_trie create_trie() {
	routing_trie trie = calloc(1, sizeof(*trie));
	DIE(!trie, "calloc");

	return trie;
}

add_route(char* net_ip, char* ip, char* mask, int interface) {
	uint32_t i_net_ip;
	inet_pton(AF_INET, &net_ip, i_net_ip);
	uint32_t ip;
	inet_pton(AF_INET, &ip, i_net_ip);
	uint32_t mask;
	inet_pton(AF_INET, &mask, i_net_ip);

	
}
