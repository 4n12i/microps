#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "arp.h"

/* IP header */
struct ip_hdr {
    uint8_t vhl; /* version (4bit) + IP header length (4bit) */
    uint8_t tos; /* type of service */
    uint16_t total;
    uint16_t id;
    uint16_t offset; /* flag (3bit) + fragment offset (13bit) */
    uint8_t ttl; /* time to live */
    uint8_t protocol; /* protocol number */
    uint16_t sum; /* header checksum */
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[];
};

/* IPの上位のプロトコルを管理するための構造体 */
struct ip_protocol {
    struct ip_protocol *next;
    uint8_t type;
    void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);
};

/* 経路情報 */
struct ip_route {
    struct ip_route *next;
    ip_addr_t network; /* network address*/
    ip_addr_t netmask; /* subnetmask */
    ip_addr_t nexthop; /* 次の中継先のアドレス（なければ IP_ADDR_ANY）*/
    struct ip_iface *iface; /* この経路への送信に使うインタフェース */
};

const ip_addr_t IP_ADDR_ANY       = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

/* NOTE: If you want to add/delete the entries after `net_run()`, you need to protect these lists with a mutex. */
static struct ip_iface *ifaces;
static struct ip_protocol *protocols; /* 登録されているプロトコルのリスト */
static struct ip_route *routes; /* 経路情報のリスト（ルーティングテーブル） */

/* string to binary */
int
ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

/* binary to string */
char *
ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

/* string to binary */
int
ip_endpoint_pton(const char *p, struct ip_endpoint *n)
{
    char *sep;
    char addr[IP_ADDR_STR_LEN] = {};
    long int port;

    sep = strrchr(p, ':');
    if (!sep) {
        return -1;
    }
    memcpy(addr, p, sep - p);
    if (ip_addr_pton(addr, &n->addr) == -1) {
        return -1;
    }
    port = strtol(sep+1, NULL, 10);
    if (port <= 0 || port > UINT16_MAX) {
        return -1;
    }
    n->port = hton16(port);
    return 0;
}

/* binary to string */
char *
ip_endpoint_ntop(const struct ip_endpoint *n, char *p, size_t size)
{
    size_t offset;

    ip_addr_ntop(n->addr, p, size);
    offset = strlen(p);
    snprintf(p + offset, size - offset, ":%d", ntoh16(n->port));
    return p;
}

static void
ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    hlen = hl << 2; /* hlen >> 2 (hl) & 0xf0 = hdr->vhl, (hdr->vhl << 4) & 0xf0 */
    fprintf(stderr, "       vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "       tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total);
    fprintf(stderr, "     total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "        id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "    offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "       ttl: %u\n", hdr->ttl);
    fprintf(stderr, "  protocol: %u\n", hdr->protocol);
    fprintf(stderr, "       sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "       src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "       dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
# ifdef HEXDUMP
    hexdump(stderr, data, len);
# endif
    funlockfile(stderr);
}

/* NOTE: must not be call after net_run() */
/* 経路情報の登録 */
static struct ip_route *
ip_route_add(ip_addr_t network, ip_addr_t netmask, ip_addr_t nexthop, struct ip_iface *iface)
{
    struct ip_route *route;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];
    char addr4[IP_ADDR_STR_LEN];

    /* EXERCISE 17-1: 経路情報への登録 */
    /* 新しい経路情報を作成してルーティングテーブルへ追加する（必要な情報はすべて引数で受け取っている） */
    route = memory_alloc(sizeof(*route));
    if (!route) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    route->network = network;
    route->netmask = netmask;
    route->nexthop = nexthop;
    route->iface = iface;
    route->next = routes;
    routes = route;

    infof("route added: network=%s, netmask=%s, nexthop=%s, iface=%s dev=%s", 
        ip_addr_ntop(route->network, addr1, sizeof(addr1)), 
        ip_addr_ntop(route->netmask, addr2, sizeof(addr2)), 
        ip_addr_ntop(route->nexthop, addr3, sizeof(addr3)), 
        ip_addr_ntop(route->iface->unicast, addr4, sizeof(addr4)), 
        NET_IFACE(iface)->dev->name
    );
    return route;
}

/* 経路情報の検索 */
static struct ip_route *
ip_route_lookup(ip_addr_t dst)
{
    struct ip_route *route, *candidate = NULL;

    for (route = routes; route; route = route->next) {
        if ((dst & route->netmask) == route->network) {
            if (!candidate || ntoh32(candidate->netmask) < ntoh32(route->netmask)) {
                candidate = route;
            }
        }
    }
    return candidate;
}

/* NOTE: must not be call after net_run() */
/* デフォルトゲートウェイの登録 */
int
ip_route_set_default_gateway(struct ip_iface *iface, const char *gateway)
{
    ip_addr_t gw;

    if (ip_addr_pton(gateway, &gw) == -1) {
        errorf("ip_addr_pton() failure, addr=%s", gateway);
        return -1;
    }
    if (!ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, iface)) {
        errorf("ip_route_add() failure");
        return -1;
    }
    return 0;
}

struct ip_iface *
ip_route_get_iface(ip_addr_t dst)
{
    struct ip_route *route;

    route = ip_route_lookup(dst);
    if (!route) {
        return NULL;
    }
    return route->iface;
}

struct ip_iface * 
ip_iface_alloc(const char *unicast, const char *netmask) 
{
    struct ip_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    /* EXERCISE: Set address information for IP interface. */
    if (ip_addr_pton(unicast, &iface->unicast) == -1) {
        errorf("[iface->unicast] ip_addr_pton() failure");
        memory_free(iface);
        return NULL;
    }
    if (ip_addr_pton(netmask, &iface->netmask) == -1) {
        errorf("[iface->netmask] ip_addr_pton() failure");
        memory_free(iface);
        return NULL;
    }
    iface->broadcast = (iface->unicast & iface->netmask) | ~(iface->netmask);
    
    return iface;
}

/* NOTE: Must not be call after `net_run()`. */
int
ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    /* EXERCISE: Registering an IP interface. */
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }

    /* EXERCISE 17-2: インタフェース登録時にそのネットワーク宛の経路情報を自動で登録する */
    if (!ip_route_add(iface->unicast & iface->netmask, iface->netmask, IP_ADDR_ANY, iface)) {
        errorf("ip_route_add() failure");
        return -1;
    }

    iface->next = ifaces;
    ifaces = iface;

    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name, 
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)), 
        ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)), 
        ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
    return 0;
}

struct ip_iface *
ip_iface_select(ip_addr_t addr)
{
    /* EXERCISE: Finding IP Interfaces. */
    struct ip_iface *entry;

    for (entry = ifaces; entry; entry = entry->next) {
        if (entry->unicast == addr) {
            break;
        }
    }

    return entry;
}

/* NOTE: Must not be call after `net_run()`. */
/* プロトコルの登録 */
int 
ip_protocol_register(uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)) 
{
    struct ip_protocol *entry;

    /* EXERCISE 9-1: 重複登録の確認 */
    for (entry = protocols; entry; entry = entry->next) {
        if (entry->type == type) {
            errorf("already exists, type=%u", entry->type);
            return -1;
        }
    }

    /* EXERCISE 9-2: プロトコルの登録 */
    entry = memory_alloc(sizeof(*entry));
    if (!entry){
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->type = type;
    entry->handler = handler;
    protocols = entry;
    
    infof("registered, type=%u", entry->type);
    return 0;
}

static void 
ip_input(const uint8_t *data, size_t len, struct net_device *dev) 
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

    struct ip_protocol *proto;

    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }
    hdr = (struct ip_hdr *)data;

    /* EXERCISE: Validating IP datagrams. */
    v = hdr->vhl >> 4;
    if (v != IP_VERSION_IPV4) {
        errorf("ip version error: v=%u", v);
        return;
    }
    hlen = (hdr->vhl & 0x0f) << 2; 
    if (len < hlen) {
        errorf("header length error: len=%zu < hlen=%u", len, hlen);
        return;
    }
    total = ntoh16(hdr->total);
    if (len < total) {
        errorf("total length error: len=%zu < total=%u", len, total);
        return;
    }
    if (cksum16((uint16_t *)data, hlen, 0) != (uint16_t)0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, hlen, -hdr->sum)));
        return;
    }
    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff) {
        errorf("fragments does not support");
        return;
    }

    /* EXERCISE: Filtering IP datagrams. */
    iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (!iface) {
        errorf("net_device_get_iface() failure");
        return;
    }
    
    if (hdr->dst != iface->unicast && hdr->dst != IP_ADDR_BROADCAST && hdr->dst != ((iface->unicast & iface->netmask) | ~(iface->netmask))) {
        return;
    }

    debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
    ip_dump(data, total);

    /* EXERCISE 9-3: プロトコルの検索 */
    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == hdr->protocol) {
            proto->handler((uint8_t *)hdr + hlen, total - hlen, hdr->src, hdr->dst, iface);
            return;
        }
    }

    /* unsupported protocol */
}

/* デバイスからの送信 */
static int 
ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {}; /* hardware address */

    int ret;

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) { /* ARPによるアドレス解決が必要なデバイスのための処理 */
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) { /* 宛先がブロードキャストIPアドレスの場合にはARPによるアドレス解決は行わずにそのデバイスのブロードキャストHWアドレスを使う */
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        } else {
            /* EXERCISE 14-5: arp_resolve()を呼び出してアドレスを解決する */
            ret = arp_resolve(NET_IFACE(iface), dst, hwaddr);
            if (ret != ARP_RESOLVE_FOUND) {
                return ret;
            }
        }
    }

    /* EXERCISE 8-4: */
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr); /* インタフェースに紐づくデバイスからIPデータグラムを送信 */
}

/* IPデータグラムの生成 */
static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, ip_addr_t nexthop, uint16_t id, uint16_t offset)
{
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *)buf;

    /* EXERCISE 8-3: IPデータグラムの生成 */
    hlen = IP_HDR_SIZE_MIN;
    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2); /* オプションなし */
    hdr->tos = 0;
    total = hlen + len;
    hdr->total = hton16(total);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->ttl = 0xff; /* 255 */
    hdr->protocol = protocol;
    hdr->sum = 0;
    hdr->src = src;
    hdr->dst = dst;
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);
    memcpy(hdr + 1, data, len); /* IPヘッダの直後にデータを配置する */

    debugf("dev=%s, dst=%s, protocol=%u, len=%u", 
        NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);
    return ip_output_device(iface, buf, total, nexthop); /* 生成したIPデータグラムを実際にデバイスから送信するための関数に渡す */
}

/* IPの出力関数 */
static uint16_t
ip_generate_id(void)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);
    return ret;
}

ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_route *route;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    ip_addr_t nexthop;
    uint16_t id;

    if (src == IP_ADDR_ANY && dst == IP_ADDR_BROADCAST) {
        errorf("source address is required for broadcast addresses");
        return -1;
    }
    route = ip_route_lookup(dst);
    if (!route) {
        errorf("no route to host, addr=%s", ip_addr_ntop(dst, addr, sizeof(addr)));
        return -1;
    }
    iface = route->iface;
    if (src != IP_ADDR_ANY && src != iface->unicast) {
        errorf("unable to output with specified source address, addr=%s", ip_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }
    nexthop = (route->nexthop != IP_ADDR_ANY) ? route->nexthop : dst;
    /* フラグメンテーションをサポートしないので、MTUを超える場合はエラーを返す */
    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("too long, dev=%s, mtu=%u < %zu", 
            NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }
    id = ip_generate_id(); /* IPデータグラムのIDを採番 */
    /* IPデータグラムを生成して出力するための関数を呼び出す */
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, nexthop, id, 0) == -1) {
        errorf("ip_output_core() failure");
        return -1;
    }
    return len;
}

int 
ip_init(void) 
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}