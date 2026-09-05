"""Exercise the production bridge renderer against a real VLAN-aware bridge."""
import importlib.machinery
import json
import os
import subprocess
import select
import sys
import time

from packet_paths import run, ns

policy = importlib.machinery.SourceFileLoader("bridge_policy", "ansible/roles/network-isolation-host/files/boetticher-network-isolation").load_module()


def main():
    if not os.path.exists("/.dockerenv"):
        raise RuntimeError("isolated container required")
    fixture=json.load(open(sys.argv[1],encoding="utf-8"))
    config=fixture["host_isolation"]
    namespaces=["switch","gateway","one","two","physical"]
    ports={"gateway":("tap100i3","10.10.40.1",config["gateway_mac"]),"one":("veth501i0","10.10.40.101","02:00:00:05:00:01"),"two":("veth502i0","10.10.40.102","02:00:00:05:00:02"),"physical":("trunk0","10.10.40.103","02:00:00:05:00:03")}
    bindings=[{"port":p,"ip":ip,"mac":mac} for name,(p,ip,mac) in ports.items() if name!="gateway"]
    clients=[{"port":b["port"],"mac":b["mac"]} for b in bindings]

    def apply():
        rules=policy.render(config,"tap100i3",bindings,{},clients,"trunk0",anchors={config["gateway_mac"]:"tap100i3"})
        ns("switch","nft","-c","-f","-",input=rules)
        ns("switch","nft","-f","-",input=rules)

    def ping(source,target,allowed):
        result=ns(source,"ping","-c","1","-W","1",target,check=False)
        if (result.returncode==0)!=allowed:
            raise AssertionError(f"{source}->{target} expected allowed={allowed}: {result.stderr} {result.stdout}")
        print(f"PASS bridge {source}->{target} {'allowed' if allowed else 'blocked'}",flush=True)

    def observed(namespace, packet_filter, sender):
        child=subprocess.Popen(["ip","netns","exec",namespace,"timeout","2","tcpdump","-l","-nn","-i","eth0","-c","1",packet_filter],stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            ready,_,_=select.select([child.stderr],[],[],0.2)
            if ready and b"listening on" in child.stderr.readline():
                break
        else:
            child.kill();child.communicate()
            raise AssertionError("packet capture did not become ready")
        sender()
        output,_=child.communicate(timeout=3)
        return bool(output.strip())

    def assert_blocked_frame(label,namespace,packet_filter,sender):
        ns("switch","nft","delete","table","bridge",policy.TABLE)
        if not observed(namespace,packet_filter,sender):
            raise AssertionError(label+" baseline packet was not observed")
        apply()
        ns("gateway","ip","neigh","flush","dev","eth0")
        if observed(namespace,packet_filter,sender):
            raise AssertionError(label+" crossed the protected bridge")
        apply()
        ping("one","10.10.40.1",True)
        print("PASS bridge "+label+" blocked with positive capture control",flush=True)

    try:
        for name in namespaces:
            run("ip","netns","add",name)
            ns(name,"ip","link","set","lo","up")
        ns("switch","ip","link","add","vmbr1","type","bridge","vlan_filtering","1")
        ns("switch","ip","link","set","vmbr1","up")
        for name,(port,ip,mac) in ports.items():
            peer="p"+str(len(port))+name[:3]
            run("ip","link","add",port,"type","veth","peer","name",peer)
            run("ip","link","set",port,"netns","switch")
            run("ip","link","set",peer,"netns",name)
            ns("switch","ip","link","set",port,"master","vmbr1")
            ns("switch","ip","link","set",port,"up")
            ns("switch","bridge","vlan","del","dev",port,"vid","1")
            ns(name,"ip","link","set",peer,"name","eth0")
            ns(name,"ip","link","set","eth0","address",mac)
            ns(name,"ip","link","set","eth0","up")
            device="eth0"
            if name=="physical":
                ns("switch","bridge","vlan","add","dev",port,"vid","40")
                ns(name,"ip","link","add","link","eth0","name","eth0.40","type","vlan","id","40")
                ns(name,"ip","link","set","eth0.40","up")
                device="eth0.40"
            else:
                ns("switch","bridge","vlan","add","dev",port,"vid","40","pvid","untagged")
            ns(name,"ip","addr","add",ip+"/24","dev",device)
            ns(name,"ip","-6","addr","add","fd40::"+ip.split(".")[-1]+"/64","dev",device)
        # Establish peer reachability and neighbor caches before restrictions.
        ping("one","10.10.40.102",True)
        ping("physical","10.10.40.101",True)
        for source in ("one","two","physical"):
            apply()
            ping(source,"10.10.40.1",True)
        for source,target in (("one","10.10.40.102"),("physical","10.10.40.101"),("one","10.10.40.103")):
            apply()
            ping(source,target,False)
        # A forged source address cannot inherit another client's lease.
        spoof_sender="""import socket,struct
def checksum(data):
 total=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
 while total>>16: total=(total&65535)+(total>>16)
 return (~total)&65535
icmp=struct.pack('!BBHHH',8,0,0,1234,1)
icmp=icmp[:2]+struct.pack('!H',checksum(icmp))+icmp[4:]
ip=struct.pack('!BBHHHBBH4s4s',0x45,0,28,1234,0,64,1,0,socket.inet_aton('10.10.40.102'),socket.inet_aton('10.10.40.1'))
ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind(('eth0',0));s.send(bytes.fromhex('0200000001040200000500010800')+ip+icmp)
"""
        assert_blocked_frame("forged lease","gateway","icmp and src host 10.10.40.102 and dst host 10.10.40.1",lambda:ns("one","python3","-c",spoof_sender))
        arp_sender="""import socket,struct
src=bytes.fromhex('020000050001'); forged=bytes.fromhex('020000000104')
arp=struct.pack('!HHBBH',1,0x800,6,4,1)+forged+socket.inet_aton('10.10.40.101')+bytes(6)+socket.inet_aton('10.10.40.1')
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind(('eth0',0));s.send(bytes.fromhex('ffffffffffff')+src+struct.pack('!H',0x806)+arp)
"""
        assert_blocked_frame("forged ARP sender","gateway","arp and src host 10.10.40.101",lambda:ns("one","python3","-c",arp_sender))
        dhcp_sender="""import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'eth0\\0');s.bind(('10.10.40.101',67));s.sendto(b'bounded-rogue-dhcp-test',('10.10.40.255',68))
"""
        assert_blocked_frame("rogue DHCP broadcast","two","udp src port 67 and dst port 68",lambda:ns("one","python3","-c",dhcp_sender))
        ra_sender="""import socket,struct
src=socket.inet_pton(socket.AF_INET6,'fe80::101');dst=socket.inet_pton(socket.AF_INET6,'ff02::1')
body=struct.pack('!BBHBBHII',134,0,0,64,0,0,0,0)
pseudo=src+dst+struct.pack('!I3xB',len(body),58)+body
total=sum(struct.unpack('!'+str(len(pseudo)//2)+'H',pseudo))
while total>>16: total=(total&65535)+(total>>16)
body=body[:2]+struct.pack('!H',(~total)&65535)+body[4:]
header=struct.pack('!IHBB',6<<28,len(body),58,255)+src+dst
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind(('eth0',0));s.send(bytes.fromhex('33330000000102000005000186dd')+header+body)
"""
        assert_blocked_frame("rogue RA multicast","two","icmp6 and ip6[40] == 134",lambda:ns("one","python3","-c",ra_sender))
        apply()
        ping("one","fd40::102",False)
        # A dead observer cannot leave indefinitely valid forwarding grants.
        apply()
        time.sleep(5.2)
        ping("one","10.10.40.1",False)
        apply()
        ping("one","10.10.40.1",True)
        print("PASS bridge timeout and renewal",flush=True)
    finally:
        for name in reversed(namespaces):
            run("ip","netns","del",name,check=False)


if __name__=="__main__":
    main()
