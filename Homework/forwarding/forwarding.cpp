#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// 在 checksum.cpp 中定义
extern bool validateIPChecksum(uint8_t *packet, size_t len);

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以调用 checksum 题中的 validateIPChecksum 函数，
 *        编译的时候会链接进来。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len)
{
  if (validateIPChecksum(packet, len))
  {
    *(packet + 8) -= 1;
    uint8_t *head = packet;

    uint32_t cksum = 0;
    *(head + 10) = 0;
    *(head + 11) = 0;
    int cklen = ((*packet) & 0xf) * 4;
    while (cklen > 0)
    {
      cksum += ((*packet) << 8) + *(packet + 1);
      packet += 2;
      cklen -= 2;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    cksum = ~cksum;

    *(head + 10) = cksum >> 8;
    *(head + 11) = cksum & 0xff;
    return true;
  }
  else
  {
    return false;
  }
}