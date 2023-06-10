from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep

from datetime import datetime
from random import randrange, choice

class MyTopo( Topo ):

    def build( self ):

        s1 = self.addSwitch( 's1', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        h1 = self.addHost( 'h1', cpu=1.0/20,mac="00:00:00:00:00:01", ip="10.0.0.1/24" )
        h2 = self.addHost( 'h2', cpu=1.0/20, mac="00:00:00:00:00:02", ip="10.0.0.2/24" )
        h3 = self.addHost( 'h3', cpu=1.0/20, mac="00:00:00:00:00:03", ip="10.0.0.3/24" )    

        s2 = self.addSwitch( 's2', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        h4 = self.addHost( 'h4', cpu=1.0/20, mac="00:00:00:00:00:04", ip="10.0.0.4/24" )
        #h5 = self.addHost( 'h5', cpu=1.0/20, mac="00:00:00:00:00:05", ip="10.0.0.5/24" )
        #h6 = self.addHost( 'h6', cpu=1.0/20, mac="00:00:00:00:00:06", ip="10.0.0.6/24" )

        s3 = self.addSwitch( 's3', cls=OVSKernelSwitch, protocols='OpenFlow13' )

                # Add links

        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
    

        self.addLink( h3, s2 )
        self.addLink( h4, s2 )
      

        self.addLink( s1, s3 )
        self.addLink( s2, s3 )
      

        def ip_generator():

    ip = ".".join(["10","0","0",str(randrange(1,5))])
    return ip
        
def startNetwork():

    #print "Starting Network"
    topo = MyTopo()
    #net = Mininet( topo=topo, host=CPULimitedHost, link=TCLink, controller=None )
    #net.addController( 'c0', controller=RemoteController, ip='192.168.43.55', port=6653 )

    c0 = RemoteController('c0', ip='192.168.0.101', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)

    net.start()
    
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
   
    
    hosts = [h1, h2, h3, h4]    
    print("--------------------------------------------------------------------------------")    
    print("Generating traffic ...")    
    h1.cmd('cd /home/mininet/webserver')
    h1.cmd('python -m SimpleHTTPServer 80 &')
    h1.cmd('iperf -s -p 5050 &')
    h1.cmd('iperf -s -u -p 5051 &')
    sleep(2)
    for h in hosts:
        h.cmd('cd /home/mininet/Downloads')
    for i in range(600):
        
        print("--------------------------------------------------------------------------------")    
        print("Iteration n {} ...".format(i+1))
        print("--------------------------------------------------------------------------------") 
        
        for j in range(10):
            src = choice(hosts)
            dst = ip_generator()
            
            if j <9:
                print("generating ICMP traffic between %s and h%s and TCP/UDP traffic between %s and h1" % (src,((dst.split('.'))[3]),src))
                src.cmd("ping {} -c 100 &".format(dst))
                src.cmd("iperf -p 5050 -c 10.0.0.1")
                src.cmd("iperf -p 5051 -u -c 10.0.0.1")
            else:
                print("generating ICMP traffic between %s and h%s and TCP/UDP traffic between %s and h1" % (src,((dst.split('.'))[3]),src))
                src.cmd("ping {} -c 100".format(dst))
                src.cmd("iperf -p 5050 -c 10.0.0.1")
                src.cmd("iperf -p 5051 -u -c 10.0.0.1")
            
            print("%s Downloading index.html from h1" % src)
            src.cmd("wget http://10.0.0.1/index.html")
            print("%s Downloading test.zip from h1" % src)
            src.cmd("wget http://10.0.0.1/test.zip")
        
        h1.cmd("rm -f *.* /home/mininet/Downloads")
        
    print("--------------------------------------------------------------------------------")  
    
    # CLI(net)
    net.stop()

if __name__ == '__main__':
    
    start = datetime.now()
    
    setLogLevel( 'info' )
    startNetwork()
    
    end = datetime.now()
    
    print(end-start)
