#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>

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
  bool end = false;
  Node *cnode[2] = {nullptr, nullptr};
  RoutingTableEntry entry;
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
    addr = ((addr & 0x00ff00ff) << 8) | ((addr & 0xff00ff00) >> 8); // 1234
    for (int i = 0; i < len; ++i)
    {
      int choose = !((addr & 0x80000000) == 0);
      if (!cur->cnode[choose])
        cur->cnode[choose] = new Node();
      cur = cur->cnode[choose];
      addr = addr << 1;
    }
    cur->entry = entry;
    cur->end = true;
  }

  void remove(RoutingTableEntry entry)
  {
    Node *target = query(entry.addr, entry.len, true);
    if (target)
    {
      target->end = false;
    }
  }

  Node *query(uint32_t addr, uint32_t len, bool is_strict)
  {
    Node *cur = root;
    addr = ((addr & 0xffff) << 16) | (addr >> 16);                  // 2143
    addr = ((addr & 0x00ff00ff) << 8) | ((addr & 0xff00ff00) >> 8); //1234
    Node *result = nullptr;
    result = cur;
    for (int i = 0; i < len; i++)
    {
      int choose = !((addr & 0x80000000) == 0);
      if (!cur->cnode[choose])
      {
        if (is_strict)
          cur = nullptr;
        break;
      }
      cur = cur->cnode[choose];
      if (cur->end == true)
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
  void get_all(Node *cur, std::vector<RoutingTableEntry> &all_entry)
  {
    if (cur->end)
      all_entry.push_back(cur->entry);
    if (cur->cnode[0])
      get_all(cur->cnode[0], all_entry);
    if (cur->cnode[1])
      get_all(cur->cnode[1], all_entry);
  }
};

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len **精确** 匹配。
 */
DictTree tree;
void update(bool insert, RoutingTableEntry entry)
{
  if (insert)
  {
    tree.insert(entry);
  }
  else
  {
    tree.remove(entry);
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，网络字节序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入 * @return 查到则返回 true ，没查到则返回 false
 */
bool prefix_query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index)
{
  Node *target = tree.query(addr, 32, false);
  if (target)
  {
    *nexthop = target->entry.nexthop;
    *if_index = target->entry.if_index;
    return true;
  }
  return false;
}

bool exact_query(uint32_t addr, uint32_t len, RoutingTableEntry *entry)
{
  Node *target = tree.query(addr, len, true);
  if (target)
  {
    *entry = target->entry;
    return true;
  }
  return false;
}

void get_all(std::vector<RoutingTableEntry> &all_entry)
{
  tree.get_all(tree.root, all_entry);
}