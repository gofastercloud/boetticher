import ipaddress,json,os,socket,ssl,struct,sys

request=json.load(sys.stdin)
result={"completed":False,"ok":False}
try:
    kind=request["kind"]
    target=request["target"]
    port=int(request["port"])
    if kind not in ("tcp","tls","dns","ntp") or not 1<=port<=65535:
        raise ValueError("unsupported bounded probe")
    address=socket.gethostbyname(target)
    ipaddress.IPv4Address(address)
    if kind in ("tcp","tls"):
        with socket.create_connection((address,port),timeout=2) as conn:
            if kind=="tls":
                with ssl.create_default_context().wrap_socket(conn,server_hostname=request["server_name"]):
                    result["ok"]=True
            else:
                result["ok"]=True
    else:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as conn:
            conn.settimeout(2)
            conn.connect((address,port))
            if kind=="dns":
                nonce=os.urandom(2)
                labels=request["query"].rstrip(".").split(".")
                if not all(0<len(label.encode("ascii"))<=63 for label in labels):
                    raise ValueError("invalid query")
                packet=nonce+b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                packet+=b"".join(bytes([len(label)])+label.encode("ascii") for label in labels)+b"\x00\x00\x01\x00\x01"
                conn.send(packet)
                data=conn.recv(4096)
                result["ok"]=len(data)>=12 and data[:2]==nonce and data[2]&0x80!=0 and data[3]&15==0 and struct.unpack("!H",data[6:8])[0]>0
            else:
                nonce=os.urandom(8)
                conn.send(b"\x23"+bytes(39)+nonce)
                data=conn.recv(512)
                result["ok"]=len(data)>=48 and data[0]&7==4 and 1<=data[1]<=15 and data[24:32]==nonce
    result["completed"]=True
except (TimeoutError,ConnectionError,OSError) as error:
    result["completed"]=True
    result["detail"]=type(error).__name__
except Exception:
    result["detail"]="probe validation or execution failed"
json.dump(result,sys.stdout)
print()
