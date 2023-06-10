from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep
from datetime import datetime
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