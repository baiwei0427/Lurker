#ifndef __NET_FUNC_H__
#define __NET_FUNC_H__

#include "flow_table.h"

/* 
 * Parse TCP header to get values for 1) window scale option and 2) MSS option
 * and save results into the flow entry 
 */
void tcp_parse_opt(struct tcphdr *tcph, struct flow_entry *entry);

/*
 * Modify rwnd field of TCP packet
 * return true if modification succeeds
 */
bool tcp_modify_rwnd(struct sk_buff *skb, u16 rwnd);

/* 
 * calculate window in bytes
 * return ceil(wnd_mss * mss >> wscale) 
 */
inline u16 wnd_to_bytes(u16 wnd_mss, u16 mss, u8 wscale);

#endif 