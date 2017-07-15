#include <net/tcp.h>
#include "net_func.h"

void parse_tcp_opt(struct tcphdr *tcph)
{       
        /* total length of TCP header (include options) */
        unsigned int tcph_len = (unsigned int)(tcph->doff << 2);
        /* start of option data */      
        unsigned char *ptr = (unsigned char *)tcph + sizeof(struct tcphdr);     
        u8 offset, finish = 0;

        while (1) {

                if (*ptr == TCPOPT_MSS) {       /* MSS */
                        printk(KERN_INFO "MSS: %hu\n", ntohs(*((u16*)(ptr + 2))));
                        /* *mss_ptr = ntohs(*((u16*)(ptr + 2))); */
                        finish++;

                } else if (*ptr == TCPOPT_WINDOW) {     /* window scaling */
                        printk(KERN_INFO "Window Scaling: %d\n", *(ptr + 1));
                        /* *wscale_ptr = *(ptr + 1); */
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
}