#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/*
  在头文件 rip.h 中定义了结构体 `RipEntry` 和 `RipPacket` 。
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for
  request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;
  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的
  IP 包。 由于 RIP 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在
  RipPacket 中额外记录了个数。 需要注意这里的地址都是用 **网络字节序（大端序）**
  存储的，1.2.3.4 在小端序的机器上被解释为整数 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 RIP 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回
 * true；否则返回 false
 *
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len
 * 时，把传入的 IP 包视为不合法。 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output)
{
  int header_len = ((*packet) & 0xf) * 4;
  if (header_len > len)
    return false;
  const uint8_t *data = packet + header_len + 8;
  if ((*data != 1) && (*data != 2))
    return false;

  output->command = *data;
  if (*(data + 1) != 2)
    return false;
  if (*(data + 2) != 0 || *(data + 3) != 0)
    return false;

  output->numEntries = (len - header_len - 8 - 4) / 20;
  const uint8_t *entry_array = data + 4;
  for (int i = 0; i < output->numEntries; ++i)
  {
    const uint8_t *entry = entry_array + i * 20;
    if (*entry != 0)
      return false;
    if (((output->command == 1) && (*(entry + 1) != 0)) ||
        ((output->command == 2) && (*(entry + 1) != 2)))
      return false;

    if (*(entry + 2) != 0 || *(entry + 3) != 0)
      return false;

    output->entries[i].addr = *(uint32_t *)(entry + 4);

    uint32_t mask = *(uint32_t *)(entry + 8);
    if ((mask & (mask + 1)) != 0)
      return false;
    output->entries[i].mask = mask;

    output->entries[i].nexthop = *(uint32_t *)(entry + 12);

    uint32_t metric = *(uint32_t *)(entry + 16);
    uint32_t test = (metric << 16) + (metric >> 16);                // 3412
    test = ((test & 0x00ff00ff) << 8) + ((test & 0xff00ff00) >> 8); // 4321
    if (test < 1 || test > 16)
      return false;
    output->entries[i].metric = metric;
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 *
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括
 * Version、Zero、Address Family 和 Route Tag 这四个字段 你写入 buffer
 * 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer)
{
  *buffer = rip->command;
  *(buffer + 1) = 2;
  *(buffer + 2) = 0;
  *(buffer + 3) = 0;
  for (int i = 0; i < rip->numEntries; ++i)
  {
    uint8_t *entry = buffer + 4 + 20 * i;
    *entry = 0;
    if (rip->command == 1)
    {
      *(entry + 1) = 0;
    }
    else
    {
      *(entry + 1) = 2;
    }
    *(entry + 2) = 0;
    *(entry + 3) = 0;
    uint32_t *p32 = (uint32_t *)(entry + 4);
    *p32 = rip->entries[i].addr;
    p32 = (uint32_t *)(entry + 8);
    *p32 = rip->entries[i].mask;
    p32 = (uint32_t *)(entry + 12);
    *p32 = rip->entries[i].nexthop;
    p32 = (uint32_t *)(entry + 16);
    *p32 = rip->entries[i].metric;
  }
  return 4 + 20 * rip->numEntries;
}
