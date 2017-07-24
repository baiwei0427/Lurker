#include <net/tcp.h>
#include "net_func.h"


void tcp_parse_opt(struct tcphdr *tcph, struct flow_entry *entry)
{       
        /* total length of TCP header (include options) */
        unsigned int tcph_len = (unsigned int)(tcph->doff << 2);
        /* start of option data */      
        unsigned char *ptr = (unsigned char *)tcph + sizeof(struct tcphdr);     
        u8 offset, finish = 0;

        while (1) {

                if (*ptr == TCPOPT_MSS) {       /* MSS */
                        entry->state.mss = ntohs(*((u16*)(ptr + 2)));
                        /* *mss_ptr = ntohs(*((u16*)(ptr + 2))); */
                        finish++;

                } else if (*ptr == TCPOPT_WINDOW) {     /* window scaling */
                        entry->state.wscale = *(ptr + 2);
                        /* *wscale_ptr = *(ptr + 2); */
                        finish++;
                }

                if (finish == 2)        /* We have parsed two options */
                        break;

                /* get offset now */
                if (*ptr == TCPOPT_NOP) {
                        offset = 1;
                } else {
                        offset = *(ptr + 1);
                }

                if (ptr + offset >= (unsigned char *)tcph + tcph_len) {
                        break;
                } else {        /* Move to next option */
                        ptr = ptr + offset;
                }
        }

        /* if (finish == 2)
                printk(KERN_INFO "MSS: %hu\nWindow Scale: %d\n", entry->state.mss, entry->state.wscale); */
}

bool tcp_modify_rwnd(struct sk_buff *skb, u16 rwnd)
{
        struct iphdr *iph = ip_hdr(skb);    
        struct tcphdr *tcph = tcp_hdr(skb); 
        /* TCP packet length */
        unsigned int tcp_len = skb->len - (iph->ihl << 2);   

        /* if we can not modify this packet */
        if (unlikely(skb_linearize(skb)))
                return false;
        
        tcph->window = htons(rwnd);
        tcph->check = 0;
        tcph->check = csum_tcpudp_magic(iph->saddr,
                                        iph->daddr,
                                        tcp_len,
                                        iph->protocol,
                                        csum_partial((char *)tcph, tcp_len, 0));
        skb->ip_summed = CHECKSUM_UNNECESSARY;        

        return true;
}

/* return ceil(wnd_mss * mss >> wscale) */
inline u16 wnd_to_bytes(u16 wnd_mss, u16 mss, u8 wscale)
{
        u32 wnd = wnd_mss * mss;
        wnd = (wnd + (1 << wscale) - 1) >> wscale; 
        return (u16)wnd;
}