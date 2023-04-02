#include "routing_trie.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>

const uint32_t last_bit_one = 0x80000000;

static rtrie_node *create_node() {
	rtrie_node *node = calloc(1, sizeof(rtrie_node));
	node->interface = NO_INT;
	return node;
}

routing_trie create_trie() {
	routing_trie trie = calloc(1, sizeof(*trie));
	trie->root = create_node();
	return trie;
}

void add_route(routing_trie trie, uint32_t prefix, uint32_t next_hop, uint32_t mask, int interface) {
	rtrie_node *current_node = trie->root;
	uint32_t backup_mask = mask;
	uint32_t backup_prefix = prefix;

	prefix = __builtin_bswap32(prefix);
	mask = __builtin_bswap32(mask);


	while (mask) {
		uint32_t bit = (prefix & last_bit_one) >> 31;
		if (current_node->__children[bit] == NULL)
			current_node->__children[bit] = create_node();

		current_node = current_node->__children[bit];
		prefix = prefix << 1;
		mask = mask << 1;
	}
	current_node->interface = interface;
	current_node->next_hop = next_hop;
	current_node->prefix = backup_prefix;
	current_node->mask = backup_mask;
}

rtrie_node *get_route(routing_trie trie, uint32_t ip) {
	ip = __builtin_bswap32(ip);

	rtrie_node *res = NULL;

	rtrie_node *current_node = trie->root;

	while (1) {
		if (current_node->interface != NO_INT) {
			res = current_node;
		}
		uint32_t bit = (ip & last_bit_one) >> 31;
		if (current_node->__children[bit] == NULL)
			return res;

		current_node = current_node->__children[bit];
		ip = ip << 1;
	}
	return res;
}

