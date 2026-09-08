//go:build linux

package tailnet

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestKernelPacketPolicy(t *testing.T) {
	if os.Getenv("BOETTICHER_TAILNET_PACKET_TEST") != "1" {
		t.Skip("explicit isolated container packet test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("packet test requires container root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("run only in the disposable offline test container")
	}
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
	}
	for _, pair := range [][2]string{{"tailscale0", "btcrsrc"}, {"eth0", "btcrdst"}} {
		run("ip", "link", "add", pair[0], "type", "veth", "peer", "name", pair[1])
		owned := pair[0]
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", owned).Run() })
		run("ip", "link", "set", pair[0], "up")
		run("ip", "link", "set", pair[1], "up")
	}
	run("ip", "link", "set", "tailscale0", "address", "02:00:00:00:01:01")
	run("ip", "link", "set", "btcrsrc", "address", "02:00:00:00:01:02")
	run("ip", "link", "set", "eth0", "address", "02:00:00:00:02:01")
	run("ip", "link", "set", "btcrdst", "address", "02:00:00:00:02:02")
	run("ip", "addr", "add", "198.18.0.1/30", "dev", "tailscale0")
	run("ip", "addr", "add", "10.10.5.10/24", "dev", "eth0")
	run("ip", "route", "add", "default", "via", "10.10.5.1", "dev", "eth0")
	run("ip", "neigh", "replace", "10.10.5.1", "lladdr", "02:00:00:00:02:02", "nud", "permanent", "dev", "eth0")
	// The on-link denied transit target also needs a working neighbour.
	run("ip", "neigh", "replace", "10.10.5.11", "lladdr", "02:00:00:00:02:02", "nud", "permanent", "dev", "eth0")
	run("ip", "neigh", "replace", "198.18.0.2", "lladdr", "02:00:00:00:01:02", "nud", "permanent", "dev", "tailscale0")
	run("ip", "-6", "addr", "add", "fd00:1::1/64", "dev", "tailscale0", "nodad")
	run("ip", "-6", "addr", "add", "fd00:2::1/64", "dev", "eth0", "nodad")
	run("ip", "-6", "route", "add", "2001:db8::/32", "via", "fd00:2::2", "dev", "eth0")
	run("ip", "-6", "neigh", "replace", "fd00:2::2", "lladdr", "02:00:00:00:02:02", "nud", "permanent", "dev", "eth0")
	run("ip", "-6", "neigh", "replace", "fd00:1::2", "lladdr", "02:00:00:00:01:02", "nud", "permanent", "dev", "tailscale0")
	for _, key := range []string{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "net.ipv6.conf.tailscale0.forwarding", "net.ipv6.conf.eth0.forwarding"} {
		value, err := exec.Command("sysctl", "-n", key).Output()
		if err != nil || string(value) != "1\n" {
			t.Fatalf("container must start with --sysctl %s=1", key)
		}
	}
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.nft")
	nat := filepath.Join(dir, "nat.nft")
	if err := os.WriteFile(policy, []byte(GuestPolicy()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nat, []byte("table ip btcr_test_nat {\n chain post {\n type nat hook postrouting priority srcnat;\n oifname \"eth0\" masquerade\n }\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run("nft", "-f", nat)
	// No namespace administration or security-profile override is used. Peer
	// addresses exist only in packets, so the real kernel FORWARD path is tested.
	command := exec.Command("python3", "-c", packetHarness, policy)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("kernel packets: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

const packetHarness = `
import socket,struct,select,time,subprocess,sys
def checksum(b):
    if len(b)%2:b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b))
    while s>>16:s=(s&65535)+(s>>16)
    return (~s)&65535
mac=lambda s:bytes.fromhex(s.replace(':',''))
left=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));left.bind(('btcrsrc',0))
right=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));right.bind(('btcrdst',0))
def frame(src,dst,sp,dp,proto,payload=b'btcr',reply=False,v6=False):
    family=socket.AF_INET6 if v6 else socket.AF_INET
    a,b=socket.inet_pton(family,src),socket.inet_pton(family,dst)
    if proto==17: body=struct.pack('!HHHH',sp,dp,8+len(payload),0)+payload
    else: body=struct.pack('!HHIIBBHHH',sp,dp,100 if not reply else 200,101 if reply else 0,80,18 if reply else 2,4096,0,0)
    pseudo=a+b+(struct.pack('!I3xB',len(body),proto) if v6 else struct.pack('!BBH',0,proto,len(body)))
    c=checksum(pseudo+body)
    at=6 if proto==17 else 16
    body=body[:at]+struct.pack('!H',c or 65535)+body[at+2:]
    if v6: ip=struct.pack('!IHBB',6<<28,len(body),proto,64)+a+b
    else:
        ip=struct.pack('!BBHHHBBH',69,0,20+len(body),1,0,64,proto,0)+a+b
        ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    eth=mac('02:00:00:00:02:01' if reply else '02:00:00:00:01:01')+mac('02:00:00:00:02:02' if reply else '02:00:00:00:01:02')+struct.pack('!H',34525 if v6 else 2048)
    return eth+ip+body
def parse(p):
    if len(p)<42:return None
    kind=struct.unpack('!H',p[12:14])[0]
    if kind==2048:
        pos=14+(p[14]&15)*4;proto=p[23]
        src,dst=socket.inet_ntoa(p[26:30]),socket.inet_ntoa(p[30:34]);v6=False
    elif kind==34525:
        pos=54;proto=p[20]
        src,dst=socket.inet_ntop(socket.AF_INET6,p[22:38]),socket.inet_ntop(socket.AF_INET6,p[38:54]);v6=True
    else:return None
    if proto not in (6,17) or len(p)<pos+8:return None
    sp,dp=struct.unpack('!HH',p[pos:pos+4])
    return src,dst,sp,dp,proto,v6
def attempt(dst,dp,proto,port):
    v6=':' in dst;client='fd00:1::2' if v6 else '198.18.0.2'
    for s in (left,right):
        s.setblocking(False)
        while True:
            try:s.recv(65535)
            except BlockingIOError:break
    left.send(frame(client,dst,port,dp,proto,v6=v6))
    deadline=time.monotonic()+0.35;seen=None
    while time.monotonic()<deadline:
        ready,_,_=select.select([left,right],[],[],max(0,deadline-time.monotonic()))
        for s in ready:
            p,addr=s.recvfrom(65535)
            if addr[2]==socket.PACKET_OUTGOING:continue
            value=parse(p)
            if not value:continue
            src,target,sp,dport,protocol,is6=value
            if s is right and target==dst and dport==dp and protocol==proto:
                seen=src
                right.send(frame(dst,src,dp,sp,proto,reply=True,v6=is6))
            if s is left and src==dst and target==client and dport==port and protocol==proto:
                expected=client if v6 else '10.10.5.10'
                assert seen==expected,('incorrect SNAT',seen,expected)
                return True
    return False
# Independent expectations, never generated from the policy's allow-list.
cases=[]
for proto in (6,17):
    for dst,allow in [('10.10.20.250',True),('10.10.30.250',True),('192.168.4.1',False),('10.10.10.250',False),('10.10.99.250',False),('10.10.40.250',False),('10.10.5.11',False),('10.10.77.250',False),('8.8.8.8',False)]:
        cases.append((dst,41991,proto,allow))
    cases.append(('10.10.5.1',53,proto,True))
    cases.append(('2001:db8:20::250',41991,proto,False))
cases.append(('10.10.5.1',123,17,True))
for i,(dst,port,proto,_) in enumerate(cases):
    assert attempt(dst,port,proto,45000+i),('positive control failed',dst,port,proto)
subprocess.run(['nft','-f',sys.argv[1]],check=True)
# Reuse flows established by controls: denied forwards must stay denied even
# when conntrack still has an existing entry.
for i,(dst,port,proto,allowed) in enumerate(cases):
    got=attempt(dst,port,proto,45000+i)
    assert got==allowed,('policy mismatch',dst,port,proto,allowed,got)
print('PASS: %d independent TCP/UDP/IPv6 cases, positive controls, SNAT return, existing-flow denial'%len(cases))
`
