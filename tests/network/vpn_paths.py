"""Real WireGuard, routing, DNS and existing-flow fault tests in local netns."""
import base64
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time

import jinja2
from packet_paths import run, ns, link, probe

ENV=jinja2.Environment(undefined=jinja2.StrictUndefined)
ENV.filters["to_json"]=json.dumps


def template(path,variables):
    return ENV.from_string(Path(path).read_text()).render(**variables)+"\n"


def private_key(namespace,interface,key,extra):
    read,write=os.pipe()
    try:
        os.write(write,key.encode()+b"\n")
        os.close(write);write=-1
        result=subprocess.run(["ip","netns","exec",namespace,"wg","set",interface,"private-key",f"/proc/self/fd/{read}",*extra],capture_output=True,text=True,pass_fds=(read,))
        if result.returncode: raise RuntimeError("WireGuard key configuration failed: "+result.stderr)
    finally:
        os.close(read)
        if write>=0: os.close(write)


def main():
    if not os.path.exists("/.dockerenv"): raise RuntimeError("disposable container required")
    fixture=json.load(open(sys.argv[1],encoding="utf-8"))
    names=["gw","arr","vpn","provider","core"]
    children=[]
    captures=[]
    fixtures=Path("/tmp/vpn-fixture")
    fixtures.mkdir(mode=0o700,exist_ok=True)
    fixture["airvpn_client"]=fixture["host_isolation"]["selected"][0]
    gateway_up=template("ansible/roles/firewall/templates/boetticher-policy-routing-up.j2",fixture)
    gateway_down=template("ansible/roles/firewall/templates/boetticher-policy-routing-down.j2",fixture)
    router_rules=template("ansible/roles/airvpn/templates/airvpn.nft.j2",fixture)
    client_rules=template("ansible/roles/airvpn-client/templates/client.nft.j2",fixture)

    def start(namespace,program,*args):
        process=subprocess.Popen(["ip","netns","exec",namespace,"python3","-u","-c",program,*args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append(process)
        return process

    def line(process,timeout=4):
        ready,_,_=select.select([process.stdout],[],[],timeout)
        if not ready: raise AssertionError("fixture process did not respond")
        value=process.stdout.readline().strip()
        if not value: raise AssertionError("fixture exited: "+process.stderr.read())
        return value

    def send(process,value):
        process.stdin.write(value+"\n");process.stdin.flush()
        return line(process)

    def dns(source,server,name,allowed=True,port=53):
        code="""import socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1);s.connect((sys.argv[1],int(sys.argv[3])))
q=b''.join(bytes([len(x)])+x.encode() for x in sys.argv[2].split('.'))+b'\\0'
s.send(b'\\x12\\x34\\x01\\0\\0\\x01'+bytes(6)+q+b'\\0\\x01\\0\\x01')
try:
 d=s.recv(4096)
 assert d[:2]==b'\\x12\\x34' and d[3]&15==0 and struct.unpack('!H',d[6:8])[0]>0
 print(socket.inet_ntoa(d[-4:]))
except Exception: sys.exit(1)
"""
        result=ns(source,"python3","-c",code,server,name,str(port),check=False)
        if (result.returncode==0)!=allowed: raise AssertionError(f"DNS {source} @{server}:{port} {name} expected={allowed}: {result.stderr}")
        print(f"PASS DNS {source} @{server}:{port} {name} {'answered' if allowed else 'blocked'}",flush=True)
        return result.stdout.strip()

    def tcp(source,address,port,allowed):
        result=ns(source,"python3","-c","import socket,sys;socket.create_connection((sys.argv[1],int(sys.argv[2])),1).close()",address,str(port),check=False)
        if (result.returncode==0)!=allowed: raise AssertionError(f"TCP {source}->{address}:{port}: {result.stderr}")
        print(f"PASS TCP {source}->{address}:{port} {'allowed' if allowed else 'blocked'}",flush=True)

    def capture(packet_filter):
        process=subprocess.Popen(["ip","netns","exec","gw","tcpdump","-U","-nn","-i","wan0","-s","96","-w","-",packet_filter],stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            ready,_,_=select.select([process.stderr],[],[],0.1)
            if ready and b"listening on" in process.stderr.readline(): break
        else: raise AssertionError("WAN capture not ready")
        captures.append(process)
        return process

    def packets(process):
        process.send_signal(signal.SIGINT)
        data,error=process.communicate(timeout=3)
        if process.returncode: raise AssertionError(error.decode())
        if len(data)<24: raise AssertionError("invalid packet capture")
        endian="<" if data[:4] in (b"\xd4\xc3\xb2\xa1",b"\x4d\x3c\xb2\xa1") else ">"
        offset,count=24,0
        while offset+16<=len(data):
            length=struct.unpack(endian+"I",data[offset+8:offset+12])[0]
            offset+=16+length;count+=1
        if offset!=len(data): raise AssertionError("truncated PCAP")
        return count

    try:
        for name in names:
            run("ip","netns","add",name);ns(name,"ip","link","set","lo","up")
        link("gw","wan0","192.168.4.5/24","provider","home","192.168.4.1/24")
        link("gw","servers0","10.10.20.1/24","arr","eth0","10.10.20.110/24")
        link("gw","transit0","10.10.5.1/24","vpn","eth0","10.10.5.20/24")
        link("gw","infra0","10.10.10.1/24","core","eth0","10.10.10.10/24")
        ns("arr","ip","link","set","eth0","address","02:00:00:00:02:10")
        ns("vpn","ip","link","set","eth0","address","02:00:00:03:01:04")
        ns("core","ip","addr","add","10.10.10.40/24","dev","eth0")
        for interface,address in [("sandbox0","10.10.40.1/24"),("trusted0","10.10.30.1/24"),("mgmt0","10.10.99.1/24")]:
            ns("gw","ip","link","add",interface,"type","dummy");ns("gw","ip","addr","add",address,"dev",interface);ns("gw","ip","link","set",interface,"up")
        for address in ("8.8.4.4/32","8.8.8.8/32","1.1.1.1/32","10.128.0.1/32"):
            ns("provider","ip","addr","add",address,"dev","lo")
        for name,gateway in [("arr","10.10.20.1"),("vpn","10.10.5.1"),("core","10.10.10.1"),("gw","192.168.4.1")]: ns(name,"ip","route","add","default","via",gateway)
        for name in ("gw","vpn"):
            ns(name,"sysctl","-w","net.ipv4.ip_forward=1","net.ipv4.conf.all.rp_filter=0")
        ns("gw","nft","-f","-",input=fixture["gateway"])
        ns("arr","nft","-f","-",input=client_rules)
        ns("vpn","nft","-f","-",input=router_rules)
        ns("gw","sh","-s",input=gateway_up);ns("gw","sh","-s",input=gateway_up)
        rules=json.loads(ns("gw","ip","-j","rule").stdout)
        for priority in (10000,10001):
            if sum(r.get("priority")==priority for r in rules)!=1: raise AssertionError("policy rules are not idempotent")
        client_key=run("wg","genkey").stdout.strip();server_key=run("wg","genkey").stdout.strip()
        client_public=run("wg","pubkey",input=client_key).stdout.strip();server_public=run("wg","pubkey",input=server_key).stdout.strip()
        ns("provider","ip","link","add","wg-provider","type","wireguard")
        private_key("provider","wg-provider",server_key,["listen-port","1637","peer",client_public,"allowed-ips","10.174.1.2/32"])
        ns("provider","ip","addr","add","10.174.1.1/24","dev","wg-provider");ns("provider","ip","link","set","wg-provider","up")
        ns("vpn","ip","rule","add","priority","50","not","fwmark","51820","table","51820")
        def tunnel_up():
            ns("vpn","ip","link","add","airvpn0","type","wireguard")
            private_key("vpn","airvpn0",client_key,["fwmark","51820","peer",server_public,"allowed-ips","0.0.0.0/0","endpoint","8.8.4.4:1637","persistent-keepalive","1"])
            ns("vpn","ip","addr","add","10.174.1.2/24","dev","airvpn0");ns("vpn","ip","link","set","airvpn0","up")
            ns("vpn","ip","route","replace","default","dev","airvpn0","table","51820")
            ns("vpn","sh","images/airvpn/runtime/airvpn-routes-up")
        tunnel_up()
        echo_program="""import socket,threading,time,sys
label=sys.argv[1]
def serve(port,udp=False):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);s.bind(('8.8.8.8' if udp and label=='provider' else '0.0.0.0',port))
 if udp:
  while True:
   data,peer=s.recvfrom(4096);s.sendto(data,peer)
 s.listen()
 while True:
  c,_=s.accept()
  def connection(c):
   with c:
    while True:
     data=c.recv(4096)
     if not data:return
     c.sendall(data)
  threading.Thread(target=connection,args=(c,),daemon=True).start()
for port,udp in [(8081,False),(8082,True),(443,False),(9443,False),(19532,False)]: threading.Thread(target=serve,args=(port,udp),daemon=True).start()
print('READY',flush=True);time.sleep(300)
"""
        for name in ("provider","core"): assert line(start(name,echo_program,name))=="READY"
        tcp("provider","1.1.1.1",443,True);tcp("core","10.10.10.10",9443,True)
        dns_program="""import socket,struct,sys,threading,time
label=sys.argv[1]
def serve(address,port):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((address,port))
 while True:
  d,peer=s.recvfrom(4096);offset=12;labels=[]
  while d[offset]:
   length=d[offset];labels.append(d[offset+1:offset+1+length].decode());offset+=length+1
  name='.'.join(labels)
  with open('/tmp/vpn-fixture/'+label+'-dns.log','a') as f:f.write(name+' '+peer[0]+'\\n')
  answer='10.10.10.20' if name.endswith('.lab.home.arpa') and label=='core' else '8.8.8.8'
  packet=d[:2]+b'\\x81\\x80\\0\\x01\\0\\x01'+bytes(4)+d[12:offset+5]+b'\\xc0\\x0c\\0\\x01\\0\\x01'+struct.pack('!IH',0,4)+socket.inet_aton(answer)
  s.sendto(packet,peer)
for address in (['10.10.10.10'] if label=='core' else ['10.128.0.1','1.1.1.1']):
 for port in ([53,5353] if label=='core' else [53]):threading.Thread(target=serve,args=(address,port),daemon=True).start()
print('READY',flush=True);time.sleep(300)
"""
        for name in ("provider","core"): assert line(start(name,dns_program,name))=="READY"
        dns_config=fixtures/"dnsmasq.conf";dns_config.write_text(template("ansible/roles/airvpn/templates/dnsmasq.conf.j2",fixture))
        dnsmasq=subprocess.Popen(["ip","netns","exec","vpn","dnsmasq","--keep-in-foreground","--conf-file="+str(dns_config)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        children.append(dnsmasq);time.sleep(0.2)
        if dnsmasq.poll() is not None: raise AssertionError(dnsmasq.stderr.read().decode())
        leaked=capture("host 8.8.8.8 and (tcp port 8081 or udp port 8082)")
        encrypted=capture("udp port 1637")
        flow_program="""import socket,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if sys.argv[1]=='udp' else socket.SOCK_STREAM);s.settimeout(2);s.connect(('8.8.8.8',8082 if sys.argv[1]=='udp' else 8081))
def exchange(token):
 deadline=time.monotonic()+2
 try:
  s.sendall(token)
  data=b''
  while time.monotonic()<deadline:
   data+=s.recv(4096)
   if token in data:return 'OK'
 except OSError:pass
 return 'BLOCK'
assert exchange(b'baseline')=='OK'
print('READY',flush=True)
for line in sys.stdin:
 print(exchange(line.strip().encode()),flush=True)
"""
        flows=[start("arr",flow_program,kind) for kind in ("tcp","udp")]
        for index,flow in enumerate(flows):
            assert line(flow)=="READY"
            print('PASS public flow ready '+('TCP' if index==0 else 'UDP'),flush=True)
        print("PASS selected TCP and UDP public traffic traverses WireGuard",flush=True)
        assert dns("arr","10.10.5.20","private1.lab.home.arpa")=="10.10.10.20"
        assert dns("arr","10.10.5.20","up.example.com")=="8.8.8.8"
        dns("core","10.10.10.10","control.example.com",True,53)
        dns("arr","10.10.10.10","bypass.example.com",False,53)
        dns("arr","10.10.10.10","bypass.lab.home.arpa",False,5353)
        dns("arr","1.1.1.1","bypass.example.com",False,53)
        tcp("arr","1.1.1.1",443,False)
        tcp("arr","192.168.4.1",443,False)
        tcp("arr","10.10.10.10",9443,True);tcp("arr","10.10.10.40",19532,True)
        ns("gw","sh","-s",input=gateway_down)
        for flow in flows: assert send(flow,"route-loss")=="BLOCK"
        ns("gw","sh","-s",input=gateway_up)
        for flow in flows: assert send(flow,"route-restored")=="OK"
        ns("vpn","ip","link","del","airvpn0")
        for flow in flows: assert send(flow,"tunnel-removed")=="BLOCK"
        dns("arr","10.10.5.20","down.example.com",False)
        dns("arr","10.10.5.20","private2.lab.home.arpa",True)
        core_queries=(fixtures/"core-dns.log").read_text()
        if "down.example.com" in core_queries: raise AssertionError("public DNS fell back to core")
        tunnel_up()
        for flow in flows: assert send(flow,"tunnel-restored")=="OK"
        ns("vpn","sysctl","-w","net.ipv4.ip_forward=0")
        if ns("vpn","nft","-f","-",input="invalid firewall syntax",check=False).returncode==0: raise AssertionError("invalid firewall accepted")
        for flow in flows: assert send(flow,"firewall-load-failed")=="BLOCK"
        ns("vpn","nft","list","table","inet","boetticher_airvpn")
        ns("vpn","nft","-f","-",input=router_rules);ns("vpn","sysctl","-w","net.ipv4.ip_forward=1")
        for flow in flows: assert send(flow,"firewall-restored")=="OK"
        if packets(leaked)!=0: raise AssertionError("selected payload crossed HOME unencrypted")
        if packets(encrypted)==0: raise AssertionError("no encrypted provider transport was captured")
        print("PASS route loss, tunnel removal, failed firewall load and existing TCP/UDP recovery",flush=True)
        print("PASS HOME capture contains provider transport and no selected payload",flush=True)
    finally:
        for process in captures+children:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        for name in reversed(names):run("ip","netns","del",name,check=False)


if __name__=="__main__":main()
