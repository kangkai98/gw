from scapy.all import Ether, IP, TCP, Raw, wrpcap


def make_pkt(ts, src, dst, sport, dport, payload):
    p = Ether()/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,seq=1,ack=1)/Raw(load=payload.encode())
    p.time = ts
    return p

pkts = []
t = 1000.0
client = "10.0.0.2"
server = "1.2.3.4"

# 第一次问答
pkts.append(make_pkt(t, client, server, 5555, 443, 'prompt: 你好，介绍一下你自己'))
t += 0.2
pkts.append(make_pkt(t, server, client, 443, 5555, 'data: 你好'))
t += 0.2
pkts.append(make_pkt(t, server, client, 443, 5555, 'data: 我是一个AI助手。'))

# 间隔 > 2s
t += 3.0
pkts.append(make_pkt(t, client, server, 5555, 443, 'prompt: 帮我写一段python'))
t += 0.3
pkts.append(make_pkt(t, server, client, 443, 5555, 'data: 好的'))
t += 0.5
pkts.append(make_pkt(t, server, client, 443, 5555, 'data: 这里是一段示例代码'))

# 其他噪声流
pkts.append(make_pkt(1000.1, '10.0.0.9', '8.8.8.8', 12345, 53, 'dns'))

wrpcap('sample_ai.pcap', pkts)
print('sample_ai.pcap generated')
