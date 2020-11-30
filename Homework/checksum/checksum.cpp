#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len)
{
    unsigned long cksum = 0;
    int cklen = ((*packet) & 0xf) * 4;
    while (cklen > 0)
    {
        cksum += ((*packet) << 8) + (*(packet + 1));
        packet += 2;
        cklen -= 2;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return cksum == 0xffff;
}
