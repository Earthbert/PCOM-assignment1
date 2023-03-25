#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include "lib.h"
#include "arp_table.h"

void create_arp_table(struct arp_table *table) {
	table->__capacity = 50;
	table->len = 0;
	table->entries = malloc(table->__capacity * sizeof(struct arp_entry));
}

struct arp_entry* get_mac_addr(struct arp_table *table, uint32_t ip) {
	for (uint32_t i = 0; i < table->len; i++) {
		if (table->entries[i].ip == ip)
			return &(table->entries[i]);
	}
	return NULL;
}

void add_arp_entry(struct arp_table *table, struct arp_entry *entry) {
	if (table->len >= table->__capacity) {
		table->__capacity += 20;
		table->entries = realloc(table->entries, table->__capacity * sizeof(struct arp_entry));
	}
	table->entries[table->len].ip = entry->ip;
	memcpy(table->entries[table->len].mac, entry->mac, 6 * sizeof(uint8_t));
	table->len++;
}
