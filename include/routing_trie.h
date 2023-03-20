#ifndef _ROUTING_TRIE_H_
#define _ROUTING_TRIE_H_
#define NO_INT -1

#include <inttypes.h>

typedef struct rtrie_node rtrie_node;

struct __attribute__((__packed__)) rtrie_node {
	uint32_t interface;
	uint32_t next_hop;
	uint32_t mask;
	uint32_t prefix;
	rtrie_node* __children[2];
};

struct routing_trie {
	rtrie_node* root;
};

typedef struct routing_trie* routing_trie;

routing_trie create_trie();

void add_route(routing_trie trie, uint32_t net_ip, uint32_t next_hop, uint32_t mask, int interface);

rtrie_node* get_route(routing_trie trie, uint32_t ip);

#endif // _ROUTING_TRIE_H_