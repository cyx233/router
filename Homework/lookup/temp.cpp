#include "router.h"
#include <stdint.h>
#include <stdlib.h>

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/
struct Node
{
    uint32_t nexthop = 0;
    Node *cnode[2] = {nullptr, nullptr};
};

struct DictTree
{
    Node *root = new Node();
    void insert(RoutingTableEntry entry)
    {
        uint32_t addr = entry.addr;
        int len = entry.len;
        Node *cur = root;
        addr = ((addr & 0xffff) << 16) | (addr >> 16);                  // 2143
        addr = ((addr & 0x00ff00ff) << 8) | ((addr & 0xff00ff00) >> 8); //1234
        for (int i = 0; i < len; ++i)
        {
            int choose = (addr & 0x80000000) == 0;
            if (!cur->cnode[choose])
                cur->cnode[choose] = new Node();
            cur = cur->cnode[choose];
            addr = addr << 1;
        }
        cur->nexthop = entry.nexthop;
    }
    void remove(RoutingTableEntry entry)
    {
    }

    Node *query(uint32_t addr, bool is_strict)
    {
        Node *cur = root;
        addr = ((addr & 0xffff) << 16) | (addr >> 16);                  // 2143
        addr = ((addr & 0x00ff00ff) << 8) | ((addr & 0xff00ff00) >> 8); //1234
        Node *result = nullptr;
        result = cur;
        for (int i = 0; i < 32; i++)
        {
            int choose = (addr & 0x80000000) == 0;
            if (!cur->cnode[choose])
            {
                if (is_strict)
                    cur = nullptr;
                break;
            }
            cur = cur->cnode[choose];
            if (cur->nexthop)
            {
                result = cur;
            }
            addr <<= 1;
        }
        if (is_strict)
            return cur;
        else
            return result;
    }
};
/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len **精确** 匹配。
 */
DictTree tree;

void init(int n, int q, const RoutingTableEntry *a)
{
    tree.root = new Node();
    for (int i = 0; i < n; ++i)
    {
        tree.insert(a[i]);
    }
}

unsigned query(unsigned addr)
{
    return tree.query(addr, false)->nexthop;
}
