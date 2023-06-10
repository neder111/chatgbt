import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

from datetime import datetime

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep
from random import randrange, choice

class MyTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h1 = self.addHost('h1', cpu=1.0/20, mac="00:00:00:00:00:01", ip="10.0.0.1/24")
        h2 = self.addHost('h2', cpu=1.0/20, mac="00:00:00:00:00:02", ip="10.0.0.2/24")
        h3 = self.addHost('h3', cpu=1.0/20, mac="00:00:00:00:00:03", ip="10.0.0.3/24")
        h4 = self.addHost('h4', cpu=1.0/20, mac="00:00:00:00:00:04", ip="10.0.0.4/24")

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(s1, s3)
        self.addLink(s2, s3)

def ip_generator():
    ip = ".".join(["10", "0", "0", str(randrange(1, 5))])
    return ip

class CollectTrainingStatsApp(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)
        
        # Define the file names
        self.normal_traffic_file = "Normal_traffic.csv"
        self.ddos_attacks_file = "DDoS_attacks.csv"

    # Asynchronous message
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(10)

    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for stat in body:
            if 'ipv4_src' not in stat.match or 'ipv4_dst' not in stat.match:
                continue

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']

            if 'tcp_src' in stat.match and 'tcp_dst' in stat.match:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']
            elif 'udp_src' in stat.match and 'udp_dst' in stat.match:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']
            else:
                tp_src = 'N/A'
                tp_dst = 'N/A'

            icmp_code = stat.match.get('icmpv4_code', 'N/A')
            icmp_type = stat.match.get('icmpv4_type', 'N/A')

            packet_count_per_second = stat.packet_count / 10
            packet_count_per_nsecond = stat.packet_count / 10**9
            byte_count_per_second = stat.byte_count / 10
            byte_count_per_nsecond = stat.byte_count / 10**9

            threshold = 1000

            with open(self.normal_traffic_file, "a+") as file0:
                with open(self.ddos_attacks_file, "a+") as file1:
                    if stat.packet_count > threshold:  # DDoS attack
                        file1.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                                    .format(timestamp, ev.msg.datapath.id, stat.cookie, ip_src, tp_src, ip_dst, tp_dst,
                                            stat.match['ip_proto'], icmp_code, icmp_type,
                                            stat.duration_sec, stat.duration_nsec,
                                            stat.idle_timeout, stat.hard_timeout,
                                            stat.flags, stat.packet_count, stat.byte_count,
                                            packet_count_per_second, packet_count_per_nsecond,
                                            byte_count_per_second, byte_count_per_nsecond, 1))
                    else:  # Normal traffic
                        file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                                    .format(timestamp, ev.msg.datapath.id, stat.cookie, ip_src, tp_src, ip_dst, tp_dst,
                                            stat.match['ip_proto'], icmp_code, icmp_type,
                                            stat.duration_sec, stat.duration_nsec,
                                            stat.idle_timeout, stat.hard_timeout,
                                            stat.flags, stat.packet_count, stat.byte_count,
                                            packet_count_per_second, packet_count_per_nsecond,
                                            byte_count_per_second, byte_count_per_nsecond, 1))

def startNetwork():
    topo = MyTopo()
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)
    net.start()

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')

    # Start MQTT broker on h1 (DHT11 sensor)
    h1.cmd('mosquitto -d')

    print("--------------------------------------------------------------------------------")
    print("Performing DDoS Attacks")
    print("--------------------------------------------------------------------------------")

    # ICMP (Ping) Flood to H3
    src = choice([h1, h2])
    src.cmd("timeout 20s hping3 -c 1500 -d 120 --flood --rand-source --icmp 10.0.0.3")

    # UDP Flood to H3 (MQTT)
    src = h4  # Attacker
    src.cmd("timeout 20s hping3 -c 1500 -d 120 -S -w 64 -p 1883 --flood --rand-source 10.0.0.3")

    # TCP-SYN Flood to H3 (MQTT)
    src.cmd("timeout 20s hping3 -c 1500 -d 120 -S -w 64 -p 1883 --flood --rand-source 10.0.0.3")

    # Slow DDoS Attack to H3 (MQTT)
    src.cmd("timeout 20s hping3 -c 500 -d 120 -S -w 64 -p 1883 --flood --rand-source --faster 10.0.0.3")

    sleep(5)  # Wait for the DDoS attacks to complete

    print("--------------------------------------------------------------------------------")
    print("Generating Normal Traffic")
    print("--------------------------------------------------------------------------------")

    # Start coffee maker (h2) as a subscriber to the MQTT topic
    h2.cmd('mosquitto_sub -h 10.0.0.1 -t temperature &')

    # Publish temperature data from DHT11 sensor (h1) to the MQTT topic
    h1.cmd('mosquitto_pub -h 10.0.0.1 -t temperature -m "25"')

    sleep(5)  # Wait for the MQTT communication to complete

    print("--------------------------------------------------------------------------------")

    net.stop()

if __name__ == '__main__':
    start = datetime.now()
    setLogLevel('info')
    startNetwork()
    end = datetime.now()
    print(end - start)
