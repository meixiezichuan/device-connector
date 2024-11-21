// +build ignore

#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "csum.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#ifndef memcpy
 #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define MAX_BACKENDS 10
#define MAX_TCP_LENGTH 1480
#define MIN_REDIRECT_PORT 40000
#define MAX_REDIRECT_PORT 60000
#define MAX_SRC 1024

static __always_inline void ip_from_int(__u32 *buf, __be32 ip) {
    buf[0] = (ip >> 0 ) & 0xFF;
    buf[1] = (ip >> 8 ) & 0xFF;
    buf[2] = (ip >> 16 ) & 0xFF;
    buf[3] = (ip >> 24 ) & 0xFF;
}

static __always_inline void bpf_printk_ip(__be32 ip) {
    __u32 ip_parts[4];
    ip_from_int((__u32 *)&ip_parts, ip);
    bpf_printk("%d.%d.%d.", ip_parts[0], ip_parts[1], ip_parts[2]);
    bpf_printk("%d", ip_parts[3]);
}

static __always_inline __u16 hashToPort(__be32 ip, __u16 port){
    __u8 buf[6];
    buf[0] = (ip >> 0 ) & 0xFF;
    buf[1] = (ip >> 8 ) & 0xFF;
    buf[2] = (ip >> 16 ) & 0xFF;
    buf[3] = (ip >> 24 ) & 0xFF;

    __u32 csum = (buf[2] << 24) + (buf[3] << 16 ) + port;
    __u32 r = csum << 16 | csum >> 16;
    csum = ~csum;
    csum -= r;
    port = (__u16)(csum >> 16);
    port = port % 20001 + MIN_REDIRECT_PORT;
    return port;
}

struct info {
    __u32 addr;
    __u16 port;
    __u8 hwaddr[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct info);
}smap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(value, struct info);
    __type(key, __u16);
}sub SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 3000);
    __type(value, __u8);
    __type(key, __u16);
}dpmap SEC(".maps");


SEC("xdp_redirect")
int xdp_prog_func(struct xdp_md *ctx) {
  // ---------------------------------------------------------------------------
  // Initialize
  // ---------------------------------------------------------------------------
  // bpf_printk("receive packet");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if (data + sizeof(struct ethhdr) > data_end) {
    bpf_printk("ABORTED: bad ethhdr!");
    return XDP_ABORTED;
  }

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    return XDP_PASS;
  }

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
    bpf_printk("ABORTED: bad iphdr!");
    return XDP_ABORTED;
  }

  if (ip->protocol != IPPROTO_TCP){
      return XDP_PASS;
  }

  struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end){
    bpf_printk("ABORTED: bad tcphdr!");
    return XDP_ABORTED;
  }

  // ---------------------------------------------------------------------------
  // Routing
  // ---------------------------------------------------------------------------

  __u32 original_src_ip = ip->saddr;
  __u32 original_dest_ip = ip->daddr;
  __u16 original_src_port = tcp->source;
  __u16 original_dest_port = tcp->dest;

  __u16 dport = bpf_ntohs(original_dest_port);

  __u16 idx0 = 0;
  struct info *s = bpf_map_lookup_elem(&sub, &idx0);
  if (!s) {
      bpf_printk("no sub connector found");
      return XDP_PASS;
  }
  // response from subconnector
  if(ip->saddr == s->addr) {
       // bpf_printk("response got TCP traffic, source address:");
       // bpf_printk_ip(ip->saddr);
       // bpf_printk("response xdp redirect got src port: %d", bpf_ntohs(tcp->source) );
       // bpf_printk("response destination address:");
       // bpf_printk_ip(ip->daddr);
        __u16 sport = bpf_ntohs(original_src_port);
        struct __u8 *di = bpf_map_lookup_elem(&dpmap, &sport);
        if(!di) {
            return XDP_PASS;
        }

        struct info *si = bpf_map_lookup_elem(&smap, &dport);
        if (!si) {
            return XDP_PASS;
        }
        // update src and destination
        ip->daddr = si->addr;
        tcp->dest = si->port;

        // update src ip to local, use src port
        ip->saddr = original_dest_ip;
        // source port use origin port which is devicePort
        //tcp->source = original_src_port;
         // update src mac to local downiface mac
         memcpy(eth->h_source, eth->h_dest, sizeof(eth->h_source));
         memcpy(eth->h_dest, si->hwaddr, sizeof(eth->h_source));

        tcp->check = csum_diff4(original_dest_ip, ip->daddr, tcp->check);
        tcp->check = csum_diff4(original_src_ip, ip->saddr, tcp->check);
        tcp->check = csum_diff4(original_dest_port, tcp->dest, tcp->check);

        update_iph_checksum(ip);

        //  bpf_printk("response updated sport to: %d", bpf_ntohs(tcp->source));
        //  bpf_printk("response updated dport to: %d", bpf_ntohs(tcp->dest));

        //  bpf_printk("response updated saddr to:");
        //  bpf_printk_ip(ip->saddr);
        //  bpf_printk("response updated daddr to:");
        //  bpf_printk_ip(ip->daddr);
        //  bpf_printk("response new source dhwaddr %x:%x:%x:", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
        //  bpf_printk("response new source dhwaddr %x:%x:%x",  eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        //  bpf_printk("response new dest dhwaddr %x:%x:%x:", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
        //  bpf_printk("response new dest dhwaddr %x:%x:%x",  eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        return XDP_TX;
  }
  struct __u8 *di = bpf_map_lookup_elem(&dpmap, &dport);
  if (di) {
         //send request to sub
        // bpf_printk("request got TCP traffic, source address:");
        // bpf_printk_ip(ip->saddr);
        // bpf_printk("reuest xdp redirect got src port: %d", bpf_ntohs(tcp->source) );

        // todo hash sourceip and port to rport
        //__u16 rport = hashToPort(original_src_ip, original_src_port);
	__u16 rport = bpf_ntohs(original_src_port);
        struct info *si = bpf_map_lookup_elem(&smap, &rport);
        if(!si) {
            struct info src_info = {0};
            src_info.addr = ip->saddr;
            src_info.port = tcp->source;
            memcpy(src_info.hwaddr, eth->h_source, sizeof(eth->h_source));
            bpf_map_update_elem(&smap, &rport, &src_info, BPF_ANY);
        }
        // update dest
        ip->daddr = s->addr;
          // update src ip to down downiface, use src port
        ip->saddr = original_dest_ip;
        tcp->source = bpf_htons(rport);
         // update src mac to local mac
        memcpy(eth->h_source, eth->h_dest, sizeof(eth->h_source));
        memcpy(eth->h_dest, s->hwaddr, sizeof(eth->h_dest));

        tcp->check = csum_diff4(original_dest_ip, ip->daddr, tcp->check);
        tcp->check = csum_diff4(original_src_ip, ip->saddr, tcp->check);
        tcp->check = csum_diff4(original_src_port, tcp->source, tcp->check);

        update_iph_checksum(ip);

        //        bpf_printk("request updated sport to: %d", bpf_ntohs(tcp->source));
        //        bpf_printk("request updated dport to: %d", bpf_ntohs(tcp->dest));

        //        bpf_printk("request updated saddr to:");
        //        bpf_printk_ip(ip->saddr);
        //        bpf_printk("request updated daddr to:");
        //        bpf_printk_ip(ip->daddr);
        //        bpf_printk("request new source dhwaddr %x:%x:%x:", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
        //        bpf_printk("request new source dhwaddr %x:%x:%x",  eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        //        bpf_printk("request new dest dhwaddr %x:%x:%x:", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
        //        bpf_printk("request new dest dhwaddr %x:%x:%x",  eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        return XDP_TX;
  }
  return XDP_PASS;
}
