#include <inttypes.h>

#include "lib.h"

struct arp_table {
	struct arp_entry *entries;
	uint32_t len;
	uint32_t __capacity;
};

void create_arp_table(struct arp_table *table);

struct arp_entry* get_mac_addr(struct arp_table *table, uint32_t ip);

void add_arp_entry(struct arp_table *table, struct arp_entry *entry);
