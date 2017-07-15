#ifndef __FLOW_TABLE_H__
#define __FLOW_TABLE_H__

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

struct flow_state {
        u16 mss;
        u8 wscale;
        u16 cwnd;
        u16 srtt_us;
        u32 rcv_bytes_total;
        u32 rcv_bytes_ecn;
        u32 dctcp_alpha;
        ktime_t last_wnd_update;
};

struct flow_key {
        u32 local_ip;   /* local IP address */
        u32 remote_ip;  /* remote IP address */
        u16 local_port; /* local TCP port */
        u16 remote_port;        /* remote TCP port */
};

struct flow_entry {
        struct flow_key key;
        struct flow_state state;
        struct hlist_node hlist;
};

struct flow_table {
        struct hlist_head *lists;       /* array of linked lists */
        u8 bits;  /* # of linked lists: 2 ^ bits */
        atomic_t num_flows;     /* total # of flow entries in the table */
        spinlock_t lock;
};

/* initialize a flow table with (1 << bits) linked lists */
bool init_table(struct flow_table *table, u8 bits);
/* insert a flow entry in the table and return true if it succeeds */
bool insert_table(struct flow_table *table, struct flow_entry *flow);
/* search a flow entry in the table */
struct flow_entry *search_table(struct flow_table *table, struct flow_entry *flow);
/* delete a flow entry from the table and return true if it succeeds */
bool delete_table(struct flow_table *table, struct flow_entry *flow);
/* free all resources of the flow table */
void free_table(struct flow_table *table);

#endif
