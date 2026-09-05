"""Real Linux namespace tests; all public-looking addresses are local fixtures.

Run only inside the disposable network-test container. No host networking or
lab connectivity is used. Kernel rules come from the Go production renderer.
"""
import json
import os
import subprocess
import sys
import time


def run(*args, input=None, check=True):
    result = subprocess.run(args, input=input, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"{args}: {result.stderr}")
    return result


def ns(name, *args, **kwargs):
    return run("ip", "netns", "exec", name, *args, **kwargs)


def link(left, lname, lip, right, rname, rip):
    run("ip", "link", "add", lname, "type", "veth", "peer", "name", rname)
    for namespace, name, ip in [(left, lname, lip), (right, rname, rip)]:
        run("ip", "link", "set", name, "netns", namespace)
        ns(namespace, "ip", "addr", "add", ip, "dev", name)
        ns(namespace, "ip", "link", "set", name, "up")


def probe(source, target, allowed, port=8080):
    result = ns(source, "curl", "--noproxy", "*", "--connect-timeout", "1", "--max-time", "2", "-fsS", f"http://{target}:{port}/", check=False)
    if (result.returncode == 0) != allowed:
        raise AssertionError(f"{source} -> {target}:{port}: expected allowed={allowed}, rc={result.returncode}, stderr={result.stderr}")
    print(f"PASS {source} -> {target}:{port} {'allowed' if allowed else 'blocked'}", flush=True)


def main():
    if not os.path.exists("/.dockerenv"):
        raise RuntimeError("run this harness in its disposable container")
    fixture = json.load(open(sys.argv[1], encoding="utf-8"))
    names = ["gw", "sandbox", "public", "arr", "vpn"]
    children = []
    try:
        for name in names:
            run("ip", "netns", "add", name)
            ns(name, "ip", "link", "set", "lo", "up")
        link("gw", "sandbox0", "10.10.40.1/24", "sandbox", "sand", "10.10.40.101/24")
        link("gw", "wan0", "192.168.4.5/24", "public", "home", "192.168.4.1/24")
        link("gw", "servers0", "10.10.20.1/24", "arr", "client", "10.10.20.110/24")
        link("gw", "transit0", "10.10.5.1/24", "vpn", "eth0", "10.10.5.20/24")
        ns("arr", "ip", "link", "set", "client", "address", "02:00:00:00:02:10")
        for iface, ip in [("infra0","10.10.10.1/24"),("trusted0","10.10.30.1/24"),("mgmt0","10.10.99.1/24")]:
            ns("gw","ip","link","add",iface,"type","dummy")
            ns("gw","ip","addr","add",ip,"dev",iface)
            ns("gw","ip","link","set",iface,"up")
        ns("public","ip","addr","add","8.8.8.8/32","dev","lo")
        ns("public","ip","addr","add","8.8.4.4/32","dev","lo")
        for name, gateway in [("sandbox","10.10.40.1"),("arr","10.10.20.1"),("vpn","10.10.5.1"),("gw","192.168.4.1")]:
            ns(name,"ip","route","add","default","via",gateway)
        ns("gw","sysctl","-w","net.ipv4.ip_forward=1")
        server=subprocess.Popen(["ip","netns","exec","public","python3","-m","http.server","8080","--bind","0.0.0.0"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        children.append(server)
        # Prove the destination service before testing a negative policy.
        for _ in range(30):
            if ns("public","curl","-fsS","http://8.8.8.8:8080",check=False).returncode==0: break
            time.sleep(0.05)
        else: raise AssertionError("fixture HTTP server did not start")
        ns("gw","nft","-c","-f","-",input=fixture["gateway"])
        ns("gw","nft","-f","-",input=fixture["gateway"])
        probe("sandbox","8.8.8.8",True)
        for target in ["192.168.4.1","10.10.5.1","10.10.10.1","10.10.20.1","10.10.30.1","10.10.99.1","10.10.40.1"]:
            probe("sandbox",target,False)
        # A missing selected-source route must never use ordinary WAN egress.
        probe("arr","8.8.8.8",False)
        probe("arr","192.168.4.1",False)
        print("PASS isolated gateway kernel packet paths",flush=True)
    finally:
        for child in children:
            child.terminate()
            child.wait(timeout=3)
        for name in reversed(names):
            run("ip","netns","del",name,check=False)


if __name__ == "__main__":
    main()
