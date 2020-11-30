#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <vector>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool prefix_query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
bool exact_query(uint32_t addr, uint32_t len, RoutingTableEntry *entry);
extern void get_all(std::vector<RoutingTableEntry> &all_entry);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

uint8_t packet[2048];
uint8_t output[2048];

const uint32_t RIP_MULITCAST_ADDR = 0x090000e0;
macaddr_t multicast_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};

// for online experiment, don't change
#ifdef ROUTER_R1
// 0: 192.168.1.1
// 1: 192.168.3.1
// 2: 192.168.6.1
// 3: 192.168.7.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0101a8c0, 0x0103a8c0, 0x0106a8c0,
                                           0x0107a8c0};
#elif defined(ROUTER_R2)
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 192.168.8.1
// 3: 192.168.9.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0108a8c0,
                                           0x0109a8c0};
#elif defined(ROUTER_R3)
// 0: 192.168.4.2
// 1: 192.168.5.2
// 2: 192.168.10.1
// 3: 192.168.11.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0204a8c0, 0x0205a8c0, 0x010aa8c0,
                                           0x010ba8c0};
#else

// 自己调试用，你可以按需进行修改，注意字节序
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a,
                                     0x0103000a};
#endif

uint16_t calc_check_sum(uint8_t *packet, int cklen = -1)
{
  uint32_t cksum = 0;
  if (cklen < 0)
    cklen = ((*packet) & 0xf) * 4;
  while (cklen > 0)
  {
    cksum += ((*packet) << 8) + *(packet + 1);
    packet += 2;
    cklen -= 2;
  }
  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);
  return ~cksum;
}

void send_response(uint32_t if_index, uint32_t dst_addr)
{
  struct ip *ip_header = (struct ip *)output;
  struct udphdr *udpHeader = (struct udphdr *)&output[20];
  macaddr_t dst_mac;
  ip_header->ip_v = 4;
  ip_header->ip_hl = 5;
  ip_header->ip_tos = 0;
  ip_header->ip_len = 0;
  ip_header->ip_id = 0;
  ip_header->ip_off = 0;
  ip_header->ip_ttl = 1;
  ip_header->ip_p = 17; // udp
  ip_header->ip_sum = 0;
  ip_header->ip_src.s_addr = addrs[if_index];
  ip_header->ip_dst.s_addr = dst_addr;

  // fill UDP headers
  // src port = 520
  udpHeader->uh_sport = htons(520);
  // dst port = 520
  udpHeader->uh_dport = htons(520);
  udpHeader->check = 0;

  RipPacket resp;
  // fill resp
  resp.command = 2; // response

  std::vector<RoutingTableEntry> table;
  get_all(table);

  uint32_t cnt = 0;
  for (RoutingTableEntry e1 : table)
  {
    if (e1.nexthop == 0 || e1.if_index != if_index)
    { // split horizon
      // assemble RIP
      RipEntry &e2 = resp.entries[cnt];
      e2.addr = e1.addr;
      e2.mask = (1 << e1.len) - 1;
      e2.nexthop = 0;
      e2.metric = e1.metric;
      if (++cnt == 25)
      {
        resp.numEntries = cnt;
        uint32_t tot_len = 20 + 8 + assemble(&resp, &output[28]);
        ip_header->ip_len = htons((uint16_t)tot_len);
        ip_header->ip_sum = 0;
        ip_header->ip_sum = htons(calc_check_sum(output));
        udpHeader->len = htons((uint16_t)(tot_len - 20));
        if (dst_addr == RIP_MULITCAST_ADDR)
        {
          HAL_SendIPPacket(if_index, output, tot_len, multicast_mac);
        }
        else if (HAL_ArpGetMacAddress(if_index, dst_addr, dst_mac) == 0)
        {
          HAL_SendIPPacket(if_index, output, tot_len, dst_mac);
        }
        cnt = 0;
      }
    }
  }
  if (cnt != 0)
  {
    resp.numEntries = cnt;
    uint32_t tot_len = 20 + 8 + assemble(&resp, &output[20 + 8]);

    ip_header->ip_len = htons((uint16_t)tot_len);
    ip_header->ip_sum = 0;
    ip_header->ip_sum = htons(calc_check_sum(output));
    udpHeader->len = htons((uint16_t)(tot_len - 20));

    if (dst_addr == RIP_MULITCAST_ADDR)
    {
      HAL_SendIPPacket(if_index, output, tot_len, multicast_mac);
    }
    else if (HAL_ArpGetMacAddress(if_index, dst_addr, dst_mac) == 0)
    {
      HAL_SendIPPacket(if_index, output, tot_len, dst_mac);
    }
  }
}

void print_table()
{
  std::vector<RoutingTableEntry> table;
  get_all(table);
  uint32_t size = (uint32_t)table.size();
  printf("table: count = %d, last 25 elements = [\n", size);
  for (uint32_t i = size > 25 ? size - 25 : 0; i < size; ++i)
  {
    RoutingTableEntry &e = table[i];
    uint32_t addr = htonl(e.addr), nexthop = htonl(e.nexthop);
    printf("  { addr: %d.%d.%d.%d, mask: %x, nexthop: %d.%d.%d.%d, metric: %d, if_index: %d},\n",
           addr >> 24, addr >> 16 & 0xFF, addr >> 8 & 0xFF, addr & 0xFF,
           htonl((1 << e.len) - 1),
           nexthop >> 24, nexthop >> 16 & 0xFF, nexthop >> 8 & 0xFF, nexthop & 0xFF,
           htonl(e.metric),
           e.if_index);
  }
  printf("]\n");
}

int main(int argc, char *argv[])
{
  printf("begin main\n");
  printf("begin main\n");
  printf("begin main\n");
  printf("begin main\n");
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0)
  {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++)
  {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // network byte order
        .len = 24,                     // host byte order
        .if_index = i,                 // host byte order
        .nexthop = 0,                  // network byte order, means direct
        .metric = htonl(1),
    };
    update(true, entry);
  }

  // send request table to every interface
  uint16_t len = 20 + 8 + 4 + 20;

  // fill IP headers
  struct ip *ip_header = (struct ip *)output;
  struct udphdr *udpHeader = (struct udphdr *)&output[20];

  ip_header->ip_hl = 5;
  ip_header->ip_v = 4;
  ip_header->ip_tos = 0;
  ip_header->ip_len = htons(len);
  ip_header->ip_off = 0;
  ip_header->ip_ttl = 1;
  ip_header->ip_p = 17;
  ip_header->ip_sum = 0;
  ip_header->ip_dst.s_addr = RIP_MULITCAST_ADDR;

  // fill UDP headers
  // src port = 520
  udpHeader->uh_sport = htons(520);
  // dst port = 520
  udpHeader->uh_dport = htons(520);
  udpHeader->len = htons(len - 20);

  RipPacket reqst;
  // fill resp
  reqst.command = 1; // request
  reqst.numEntries = 1;
  reqst.entries[0].addr = 0;
  reqst.entries[0].mask = 0;
  reqst.entries[0].nexthop = 0;
  reqst.entries[0].metric = htonl(16);

  // assemble RIP
  uint32_t rip_len = assemble(&reqst, &output[20 + 8]);
  // checksum calculation for ip and udp
  // if you don't want to calculate udp checksum, set it to zero
  udpHeader->check = 0;

  for (int i = 0; i < N_IFACE_ON_BOARD; i++)
  {
    // construct rip response
    // do the mostly same thing as step 3a.3
    // except that dst_ip is RIP multicast IP 224.0.0.9
    // and dst_mac is RIP multicast MAC 01:00:5e:00:00:09
    ip_header->ip_src.s_addr = addrs[i];
    ip_header->ip_sum = 0;
    ip_header->ip_sum = htons(calc_check_sum(output));
    HAL_SendIPPacket(i, output, len, multicast_mac);
  }
  print_table();

  uint64_t last_time = HAL_GetTicks();
  while (1)
  {
    uint64_t time = HAL_GetTicks();
    // the RFC says 30s interval,
    // but for faster convergence, use 5s here
    if (time > last_time + 5 * 1000)
    {
      // ref. RFC 2453 Section 3.8
      printf("5s Timer\n");
      // HINT: print complete routing table to stdout/stderr for debugging
      // send complete routing table to every interface
      for (int i = 0; i < N_IFACE_ON_BOARD; i++)
      {
        // construct rip response
        // do the mostly same thing as step 3a.3
        // except that dst_ip is RIP multicast IP 2240.0.9
        // and dst_mac is RIP multicast MAC 01:00:5e:00:00:09
        send_response(i, RIP_MULITCAST_ADDR);
      }
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF)
    {
      break;
    }
    else if (res < 0)
    {
      return res;
    }
    else if (res == 0)
    {
      // Timeout
      continue;
    }
    else if (res > sizeof(packet))
    {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res))
    {
      printf("Invalid IP Checksum\n");
      // drop if ip checksum invalid
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet (big endian)
    struct ip *ip_header = (struct ip *)packet;
    src_addr = ip_header->ip_src.s_addr;
    dst_addr = ip_header->ip_dst.s_addr;

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++)
    {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0)
      {
        dst_is_me = true;
        break;
      }
    }
    // handle rip multicast address(224.0.0.9)
    if (dst_addr == RIP_MULITCAST_ADDR)
      dst_is_me = true;

    if (dst_is_me)
    {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip))
      {
        if (rip.command == 1)
        {
          // 3a.3 request, ref. RFC 2453 Section 3.9.1
          // only need to respond to whole table requests in the lab
          send_response(if_index, src_addr);
        }
        else
        {
          // 3a.2 response, ref. RFC 2453 Section 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // HINT: handle nexthop = 0 case
          // HINT: what is missing from RoutingTableEntry?
          // you might want to use `prefix_query` and `update`, but beware of
          // the difference between exact match and longest prefix match.
          // optional: triggered updates ref. RFC 2453 Section 3.10.1
          bool flag = false;
          for (uint32_t i = 0; i < rip.numEntries; ++i)
          {
            uint32_t mask = rip.entries[i].mask;
            uint32_t addr = rip.entries[i].addr & mask;
            uint32_t metric = std::min(htonl(16), rip.entries[i].metric + htonl(1));
            uint32_t len = 0;
            for (int i = 0; i < 32; i++)
            {
              if (0x00000001 & mask)
              {
                mask >>= 1;
                len++;
              }
              else
                break;
            }
            RoutingTableEntry *entry = new RoutingTableEntry();
            if (exact_query(addr, len, entry))
            {
              if (entry->nexthop == src_addr)
              {
                if ((entry->metric = metric) == htonl(16))
                {
                  update(false, *entry);
                  flag = true;
                }
              }
              else if (entry->metric > metric)
              {
                entry->nexthop = src_addr;
                entry->metric = metric;
                entry->if_index = if_index;
                update(true, *entry);
                flag = true;
              }
            }
            else
            {
              RoutingTableEntry entry;
              entry.addr = addr;
              entry.if_index = if_index;
              entry.len = len;
              entry.metric = metric;
              entry.nexthop = src_addr;
              update(true, entry);
              flag = true;
            }
            delete entry;
          }
          if (flag)
            print_table();
        }
      }
      else
      {
        printf("not rip\n");
        // not a rip packet
        // handle icmp echo request packet
        struct ip *ip_header = (struct ip *)packet;
        struct icmphdr *icmp_header = (struct icmphdr *)&packet[ip_header->ip_hl * 4];
        bool flag = false;
        if (ip_header->ip_p == 1 && icmp_header->type == ICMP_ECHO && icmp_header->code == 0)
          flag = true;

        if (flag)
        {
          // construct icmp echo reply
          // reply is mostly the same as request,
          // you need to:
          // 1. swap src ip addr and dst ip addr
          // 2. change icmp `type` in header
          // 3. set ttl to 64
          // 4. re-calculate icmp checksum and ip checksum
          // 5. send icmp packet

          memcpy(output, packet, res);
          ip_header = (struct ip *)output;
          icmp_header = (struct icmphdr *)&output[ip_header->ip_hl * 4];
          // fill IP header
          ip_header->ip_ttl = 64;
          ip_header->ip_src.s_addr = dst_addr;
          ip_header->ip_dst.s_addr = src_addr;

          // fill icmp header
          // icmp type = ICMP Echo Reply
          icmp_header->type = ICMP_ECHOREPLY;
          // icmp code = echo reply
          icmp_header->code = 0;

          // calculate icmp checksum and ip checksum
          ip_header->ip_sum = 0;
          icmp_header->checksum = 0;
          ip_header->ip_sum = calc_check_sum(output);
          icmp_header->checksum = calc_check_sum(&output[ip_header->ip_hl * 4], res - ip_header->ip_hl * 4);
          // send icmp packet
          HAL_SendIPPacket(if_index, output, res, src_mac);
        }
      }
    }
    else
    {
      // 3b.1 dst is not me
      // check ttl
      uint8_t ttl = packet[8];
      if (ttl <= 1)
      {
        // send icmp time to live exceeded to src addr
        // fill IP header
        struct ip *ip_header = (struct ip *)output;
        ip_header->ip_v = 4;
        ip_header->ip_hl = 5;
        // set tos = 0, id = 0, off = 0, ttl = 64, p = 1(icmp), src and dst
        ip_header->ip_tos = 0;
        ip_header->ip_len = htons(56);
        ip_header->ip_id = 0;
        ip_header->ip_off = 0;
        ip_header->ip_ttl = 64;
        ip_header->ip_p = 1; // icmp
        ip_header->ip_sum = 0;
        ip_header->ip_src.s_addr = dst_addr;
        ip_header->ip_dst.s_addr = src_addr;

        // fill icmp header
        struct icmphdr *icmp_header = (struct icmphdr *)&output[20];
        // icmp type = Time Exceeded
        icmp_header->type = ICMP_TIME_EXCEEDED;
        // icmp code = TTL expired in transit
        icmp_header->code = 0;
        // fill unused fields with zero
        icmp_header->checksum = 0;
        icmp_header->un.gateway = 0;

        // append "ip header and first 8 bytes of the original payload"
        memcpy(&output[28], packet, 28);
        // calculate icmp checksum and ip checksum
        ip_header->ip_sum = calc_check_sum(output);
        icmp_header->checksum = calc_check_sum(&output[20], 36);
        // send icmp packet
        HAL_SendIPPacket(if_index, output, 56, src_mac);
      }
      else
      {
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if;
        if (prefix_query(dst_addr, &nexthop, &dest_if))
        {
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0)
          {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0)
          {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          }
          else
          {
            // not found
            // you can drop it
            printf("ARP not found for nexthop %x\n", nexthop);
          }
        }
        else
        {
          // not found
          // send ICMP Destination Network Unreachable
          printf("IP not found in routing table for src %x dst %x\n", src_addr, dst_addr);
          // send icmp destination net unreachable to src addr
          // fill IP header
          struct ip *ip_header = (struct ip *)output;
          ip_header->ip_v = 4;
          ip_header->ip_hl = 5;
          // set tos = 0, id = 0, off = 0, ttl = 64, p = 1(icmp), src and dst
          ip_header->ip_tos = 0;
          ip_header->ip_len = htons(56);
          ip_header->ip_id = 0;
          ip_header->ip_off = 0;
          ip_header->ip_ttl = 64;
          ip_header->ip_p = 1; // icmp
          ip_header->ip_sum = 0;
          ip_header->ip_src.s_addr = dst_addr;
          ip_header->ip_dst.s_addr = src_addr;

          // fill icmp header
          struct icmphdr *icmp_header = (struct icmphdr *)&output[20];
          // icmp type = Destination Unreachable
          icmp_header->type = ICMP_DEST_UNREACH;
          // icmp code = Destination Network Unreachable
          icmp_header->code = 0;
          // fill unused fields with zero
          icmp_header->checksum = 0;
          icmp_header->un.gateway = 0;

          // append "ip header and first 8 bytes of the original payload"
          memcpy(&output[28], packet, 28);
          // calculate icmp checksum and ip checksum
          ip_header->ip_sum = calc_check_sum(output);
          icmp_header->checksum = calc_check_sum(&output[20], 36);
          // send icmp packet
          HAL_SendIPPacket(if_index, output, 56, src_mac);
        }
      }
    }
  }
  return 0;
}
