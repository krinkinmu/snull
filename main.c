#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>

#define SNULL_RX_INTR 1
#define SNULL_TX_INTR 2
#define SNULL_TIMEOUT 5

#define SNULLS        2

struct snull_packet {
	struct list_head head;
	struct net_device *dev;
	int len;
	u8 data[ETH_DATA_LEN];
};

struct snull_priv {
	struct net_device_stats stats;
	int status;
	struct list_head pool;
	struct list_head recv;
	int tx_len;
	struct sk_buff *tx_skb;
	spinlock_t lock;
};

static int pool_size = 8;
module_param(pool_size, int, 0);

static int timeout = SNULL_TIMEOUT;
module_param(timeout, int, 0);

static struct net_device *snull_dev[SNULLS];


static struct snull_packet *S_PACKET(struct list_head *entry)
{ return list_entry(entry, struct snull_packet, head); }

static void snull_pool_setup(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	int i;

	INIT_LIST_HEAD(&priv->pool);
	for (i = 0; i != pool_size; ++i) {
		struct snull_packet *pkt = kmalloc(sizeof(*pkt), GFP_KERNEL);

		if (pkt == NULL) {
			netdev_warn(dev, "Ran out of memory\n");
			return;
		}
		pkt->dev = dev;
		list_add(&pkt->head, &priv->pool);
	}
}

static void snull_pool_teardown(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, &priv->pool)
		kfree(S_PACKET(pos));
}

static struct snull_packet *snull_packet_get(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct snull_packet *pkt;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = list_first_entry(&priv->pool, struct snull_packet, head);
	list_del(&pkt->head);
	if (list_empty(&priv->pool)) {
		netdev_info(dev, "pool is empty\n");
		netif_stop_queue(dev);
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

static void snull_packet_release(struct snull_packet *pkt)
{
	struct net_device *dev = pkt->dev;
	struct snull_priv *priv = netdev_priv(dev);
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	list_add(&pkt->head, &priv->pool);
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(dev))
		netif_wake_queue(dev);
}

static void __snull_dev_enqueue(struct snull_priv *priv,
			struct snull_packet *pkt)
{ list_add_tail(&pkt->head, &priv->recv); }

static void snull_dev_enqueue(struct net_device *dev, struct snull_packet *pkt)
{
	struct snull_priv *priv = netdev_priv(dev);
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	__snull_dev_enqueue(priv, pkt);
	spin_unlock_irqrestore(&priv->lock, flags);
}

static struct snull_packet *__snull_dev_dequeue(struct snull_priv *priv)
{
	struct snull_packet *pkt;

	pkt = list_first_entry_or_null(&priv->recv, struct snull_packet, head);
	if (pkt)
		list_del(&pkt->head);
	return pkt;
}

/*
static struct snull_packet *snull_dev_dequeue(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	struct snull_packet *pkt;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = __snull_dev_dequeue(priv);
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}
*/

static void snull_dev_rx(struct net_device *dev, struct snull_packet *pkt)
{
	struct snull_priv *priv = netdev_priv(dev);
	struct sk_buff *skb;

	skb = netdev_alloc_skb_ip_align(dev, pkt->len);
	if (!skb) {
		netdev_warn(dev, "low on mem, packet dropped\n");
		priv->stats.rx_dropped++;
		return;
	}

	memcpy(skb_put(skb, pkt->len), pkt->data, pkt->len);
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += pkt->len;
	netif_rx(skb);
}

static void snull_dev_interrupt(int irq, void *cookie, struct pt_regs *regs)
{
	struct net_device *dev = cookie;
	struct snull_priv *priv = netdev_priv(dev);
	struct snull_packet *pkt = NULL;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	if (priv->status & SNULL_RX_INTR) {
		pkt = __snull_dev_dequeue(priv);
		if (pkt)
			snull_dev_rx(dev, pkt);
	}
	if (priv->status & SNULL_TX_INTR) {
		priv->stats.rx_packets++;
		priv->stats.tx_bytes += priv->tx_len;
		/*
			universal version of dev_kfree_skb, there are also
			irq/non-irq specific versions
		*/
		dev_kfree_skb_any(priv->tx_skb);
	}
	priv->status = 0;
	spin_unlock_irqrestore(&priv->lock, flags);

	if (pkt)
		snull_packet_release(pkt);
}

static void snull_dev_tx(struct net_device *dev, char *buf, int len)
{
	struct iphdr *ih;
	struct net_device *dst;
	struct snull_priv *priv;
	u32 *saddr, *daddr;
	struct snull_packet *pkt;

	ih = (struct iphdr *)(buf + sizeof(struct ethhdr));
	saddr = &ih->saddr;
	daddr = &ih->daddr;

	((u8 *)saddr)[2] ^= 1;
	((u8 *)daddr)[2] ^= 1;

	ih->check = 0;
	ih->check = ip_fast_csum((u8 *)ih, ih->ihl);

	dst = snull_dev[dev == snull_dev[0] ? 1 : 0];
	pkt = snull_packet_get(dev);
	pkt->len = len;
	memcpy(pkt->data, buf, len);
	snull_dev_enqueue(dst, pkt);

	priv = netdev_priv(dst);
	priv->status |= SNULL_RX_INTR;
	snull_dev_interrupt(0, dst, NULL);

	priv = netdev_priv(dev);
	priv->status |= SNULL_TX_INTR;
	snull_dev_interrupt(0, dev, NULL);
}

static int snull_device_open(struct net_device *dev)
{
	netdev_info(dev, "snull_device_open\n");
	memcpy(dev->dev_addr, "\0SNUL0", ETH_ALEN);
	if (dev == snull_dev[1])
		dev->dev_addr[ETH_ALEN - 1]++;
	netif_start_queue(dev);
	return 0;
}

static int snull_device_stop(struct net_device *dev)
{
	netdev_info(dev, "snull_device_stop\n");
	netif_stop_queue(dev);
	return 0;
}

static netdev_tx_t snull_device_start_xmit(struct sk_buff *skb,
			struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);
	char *data, shortpkt[ETH_ZLEN];
	int len;

	data = skb->data;
	len = skb->len;
	if (len < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		len = ETH_ZLEN;
		data = shortpkt;
	}
	dev->trans_start = jiffies;
	priv->tx_len = len;
	priv->tx_skb = skb;

	snull_dev_tx(dev, data, len);
	return NETDEV_TX_OK;
}

static void snull_device_tx_timeout(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);

	/*
		lockups should not happen for snull, but actually pretty
		normal for real hardware devices. So this code does
		nothing, but real code should take care of locked device.
	*/
	if (netif_queue_stopped(dev))
		netif_wake_queue(dev);
	priv->stats.tx_errors++;
}

static struct net_device_stats *snull_device_get_stats(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);

	return &priv->stats;
}

static const struct net_device_ops snull_device_ops = {
	.ndo_open = snull_device_open,
	.ndo_stop = snull_device_stop,
	.ndo_start_xmit = snull_device_start_xmit,
	.ndo_tx_timeout = snull_device_tx_timeout,
	.ndo_get_stats = snull_device_get_stats
};

static int snull_header_create(struct sk_buff *skb, struct net_device *dev,
			unsigned short type,
			const void *daddr, const void *saddr, unsigned len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb, ETH_HLEN);

	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN - 1] ^= 1;
	return dev->hard_header_len;
}

static const struct header_ops snull_header_ops = {
	.create = snull_header_create
};

static void snull_netdevice_init(struct net_device *dev)
{
	struct snull_priv *priv = netdev_priv(dev);

	ether_setup(dev);
	dev->watchdog_timeo = timeout;
	dev->netdev_ops = &snull_device_ops;
	dev->header_ops = &snull_header_ops;
	/*
	  commit 34324dc2bf27c17730 ("net: remove NETIF_F_NO_CSUM feature bit")
	*/
	dev->features |= NETIF_F_HW_CSUM;
	dev->flags |= IFF_NOARP;

	memset(priv, 0, sizeof(*priv));
	spin_lock_init(&priv->lock);
	INIT_LIST_HEAD(&priv->recv);
	snull_pool_setup(dev);
}

static void snull_cleanup(void)
{
	int i;

	for (i = 0; i != SNULLS; ++i) {
		if (snull_dev[i]) {
			unregister_netdev(snull_dev[i]);
			snull_pool_teardown(snull_dev[i]);
			free_netdev(snull_dev[i]);
		}
	}
}

static int __init snull_init(void)
{
	int i, ret = -ENOMEM;

	snull_dev[0] = alloc_netdev(sizeof(struct snull_priv), "sn%d",
		NET_NAME_UNKNOWN, snull_netdevice_init);
	snull_dev[1] = alloc_netdev(sizeof(struct snull_priv), "sn%d",
		NET_NAME_UNKNOWN, snull_netdevice_init);

	if (!snull_dev[0] || !snull_dev[1])
		goto out;

	ret = -ENODEV;
	for (i = 0; i != SNULLS; ++i) {
		struct net_device *dev = snull_dev[i];
		int res;

		if ((res = register_netdev(dev))) {
			netdev_err(dev, "error %d while registering \"%s\"\n",
				res, dev->name);
			goto out;
		}
	}

	return 0;
out:
	snull_cleanup();
	return ret;
}

static void __exit snull_exit(void)
{ snull_cleanup(); }

module_init(snull_init);
module_exit(snull_exit);
MODULE_LICENSE("GPL");
