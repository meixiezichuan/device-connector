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

struct info {
    __u32 addr;
    __u16 port;
    __u8 hwaddr[6];
};

struct local {
    __u32 uaddr;
    __u32 daddr;
    __u8 uhwaddr[6];
    __u8 dhwaddr[6];
    __u16 uifindex;
    __u16 difindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __u16);
    __type(value, struct local);
} local SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct info);
}dmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(value, struct info);
    __type(key, __u16);
}pod_proxy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u16);
}port_map SEC(".maps");

SEC("xdp")
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

  struct info *di = bpf_map_lookup_elem(&dmap, &dport);
  if (!di) {
      //bpf_printk("no dst info for port %d", dport);
      return XDP_PASS;
  }

  // check if packet from pod_proxy
  __u16 idx0 = 0;
  struct info *p = bpf_map_lookup_elem(&pod_proxy, &idx0);
  if (!p) {
      //bpf_printk("no pod_proxy found");
      return XDP_PASS;
  }
//bpf_printk("podProxy ip address:");
 //bpf_printk_ip(p->addr);
  //bpf_printk("got TCP traffic, source address:");
  //bpf_printk_ip(ip->saddr);
  //bpf_printk("xdp redirect got src port: %d", bpf_ntohs(tcp->source) );

  if (original_src_ip != p->addr) {
      //bpf_printk("packet not from pod_proxy");
      return XDP_PASS;
  }

  //bpf_printk("destination address:");
  //bpf_printk_ip(ip->daddr);

  struct local *l = bpf_map_lookup_elem(&local, &idx0);
  if (!l) {
      //bpf_printk("no locals found");
      return XDP_PASS;
  }

  __u16 sport = bpf_ntohs(original_src_port);
  bpf_map_update_elem(&port_map, &sport, &dport, BPF_ANY);

  // update dest
  ip->daddr = di->addr;
  tcp->dest = bpf_htons(di->port);
  memcpy(eth->h_dest, di->hwaddr, sizeof(eth->h_source));
  // update src ip to down downiface, use src port
  ip->saddr = l->daddr;
 // update src mac to local downiface mac
  memcpy(eth->h_source, l->dhwaddr, sizeof(eth->h_source));


  bpf_printk("updated sport to: %d", bpf_ntohs(tcp->source));
  bpf_printk("updated dport to: %d", bpf_ntohs(tcp->dest));
    
  bpf_printk("updated saddr to:");
  bpf_printk_ip(ip->saddr);
  bpf_printk("updated daddr to:");
  bpf_printk_ip(ip->daddr);

  bpf_printk("new source dhwaddr %x:%x:%x:", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
  bpf_printk("new source dhwaddr %x:%x:%x",  eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  bpf_printk("new dest dhwaddr %x:%x:%x:", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
  bpf_printk("new dest dhwaddr %x:%x:%x",  eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

  tcp->check = csum_diff4(original_dest_ip, ip->daddr, tcp->check);
  tcp->check = csum_diff4(original_src_ip, ip->saddr, tcp->check);
  tcp->check = csum_diff4(original_dest_port, tcp->dest, tcp->check);

  update_iph_checksum(ip);

  return bpf_redirect(l->difindex, 0);
}

SEC("xdp_redirect_placeholder")
int bpf_redirect_placeholder(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if (data + sizeof(struct ethhdr) > data_end) {
    bpf_printk("ABORTED: bad ethhdr!");
    return XDP_ABORTED;
  }

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    //bpf_printk("PASS: not IP protocol!");
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

    __u16 *device_port = bpf_map_lookup_elem(&port_map, &dport);
    if (!device_port){
        //bpf_printk(" redirect response: no device port found");
        return XDP_PASS;
    }

    struct info *di = bpf_map_lookup_elem(&dmap, device_port);
    if (!di) {
        bpf_printk("redirect response: no dst info for port %d", *device_port);
        return XDP_PASS;
    }
    if (di->addr != ip->saddr) {
        bpf_printk("redirect response: not a response");
        return XDP_PASS;
    }

    __u16 idx0 = 0;
    struct info *p = bpf_map_lookup_elem(&pod_proxy, &idx0);
    if (!p) {
        bpf_printk("no pod_proxy found");
        return XDP_PASS;
    }


    //bpf_printk("redirect place holder receive packet at: %d", dport);
    //bpf_printk("got TCP traffic, source address:");
    //bpf_printk_ip(ip->saddr);
    //bpf_printk("source port: %d", bpf_ntohs(tcp->source));
    //bpf_printk("destination address:");
    //bpf_printk_ip(ip->daddr);

    struct local *l = bpf_map_lookup_elem(&local, &idx0);
    if (!l) {
        bpf_printk("no locals found");
        return XDP_PASS;
    }

//  bpf_printk("redirect place holder source dhwaddr %x:%x:%x:", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
//  bpf_printk("redirect place holder source dhwaddr %x:%x:%x",  eth->h_source[3], eth->h_source[4], eth->h_source[5]);
//  bpf_printk("redirect place holder dest dhwaddr %x:%x:%x:", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
//  bpf_printk("redirect place holder dest dhwaddr %x:%x:%x",  eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
//


  // set destination to pod_proxy
  ip->daddr = p->addr;
  memcpy(eth->h_dest, p->hwaddr, sizeof(eth->h_dest));

  tcp->source = bpf_htons(*device_port);
  ip->saddr = l->uaddr;
  memcpy(eth->h_source, l->uhwaddr, sizeof(eth->h_source));

  //bpf_printk(" place holder updated sport to: %d", bpf_ntohs(tcp->source));
  //bpf_printk("place holder updated dport to: %d", bpf_ntohs(tcp->dest));
  //  
  //bpf_printk("place holder updated saddr to:");
  //bpf_printk_ip(ip->saddr);
  //bpf_printk("place holder updated daddr to:");
  //bpf_printk_ip(ip->daddr);
  //bpf_printk("redirect place holder new source dhwaddr %x:%x:%x:", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
  //bpf_printk("redirect place holder new source dhwaddr %x:%x:%x",  eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  //bpf_printk("redirect place holder new dest dhwaddr %x:%x:%x:", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
  //bpf_printk("redirect place holder new dest dhwaddr %x:%x:%x",  eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
  // update checksum
  tcp->check = csum_diff4(original_dest_ip, ip->daddr, tcp->check);
  tcp->check = csum_diff4(original_src_ip, ip->saddr, tcp->check);
  tcp->check = csum_diff4(original_src_port, tcp->source, tcp->check);

  update_iph_checksum(ip);

  return bpf_redirect(l->uifindex, 0);
}
