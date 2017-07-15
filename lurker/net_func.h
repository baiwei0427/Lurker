#ifndef __NET_FUNC_H__
#define __NET_FUNC_H__

/* Parse TCP header to get values for 1) window scale option and 2) MSS option */
void parse_tcp_opt(struct tcphdr *tcph);

#endif 