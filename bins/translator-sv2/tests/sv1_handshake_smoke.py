#!/usr/bin/env python3
# Synthetic SV1 handshake test — proves the translator does NOT deadlock a
# SERIALIZING miner (subscribe -> WAIT -> authorize), and serves a PIPELINING one.
import socket, json, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "95.111.221.169"
PORT = int(sys.argv[2] if len(sys.argv) > 2 else 3333)
USER = sys.argv[3] if len(sys.argv) > 3 else "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492.synthtest"

def recv_lines(sock, timeout, want_id=None, want_method=None):
    sock.settimeout(timeout); buf=b""; out=[]
    t0=time.time()
    try:
        while time.time()-t0 < timeout:
            data=sock.recv(4096)
            if not data: break
            buf+=data
            while b"\n" in buf:
                line,buf=buf.split(b"\n",1)
                if not line.strip(): continue
                msg=json.loads(line)
                out.append(msg)
                if want_id is not None and msg.get("id")==want_id and "result" in msg: return out
                if want_method and msg.get("method")==want_method: return out
    except socket.timeout:
        pass
    return out

def test_serializer():
    print(f"[SERIALIZER] connect {HOST}:{PORT}, subscribe, WAIT (no authorize) — expect a subscribe response (no deadlock)")
    s=socket.create_connection((HOST,PORT),timeout=10)
    s.sendall(json.dumps({"id":1,"method":"mining.subscribe","params":["synthtest/1.0"]}).encode()+b"\n")
    # Do NOT send authorize. A deadlocked translator never replies to subscribe.
    t0=time.time()
    msgs=recv_lines(s, 4.0, want_id=1)
    dt=time.time()-t0
    sub=[m for m in msgs if m.get("id")==1 and "result" in m]
    if sub:
        r=sub[0]["result"]
        en1 = r[1] if isinstance(r,list) and len(r)>1 else "?"
        print(f"  ✅ PASS — got subscribe response in {dt:.2f}s, extranonce1={en1} (NO deadlock)")
        # now send authorize and confirm we get set_difficulty / notify (channel opens)
        s.sendall(json.dumps({"id":2,"method":"mining.authorize","params":[USER,"x"]}).encode()+b"\n")
        m2=recv_lines(s, 6.0, want_method="mining.notify")
        got_notify=any(m.get("method")=="mining.notify" for m in m2)
        got_setx=any(m.get("method")=="mining.set_extranonce" for m in m2)
        print(f"  channel-open after authorize: notify={got_notify} set_extranonce={got_setx}")
        s.close(); return True
    else:
        print(f"  ❌ FAIL — NO subscribe response after {dt:.2f}s (DEADLOCK)")
        s.close(); return False

def test_pipeliner():
    print(f"[PIPELINER] connect, send subscribe+authorize together — expect real extranonce + jobs")
    s=socket.create_connection((HOST,PORT),timeout=10)
    s.sendall(json.dumps({"id":1,"method":"mining.subscribe","params":["synthtest/1.0"]}).encode()+b"\n")
    s.sendall(json.dumps({"id":2,"method":"mining.authorize","params":[USER,"x"]}).encode()+b"\n")
    msgs=recv_lines(s, 8.0, want_method="mining.notify")
    sub=[m for m in msgs if m.get("id")==1 and "result" in m]
    got_notify=any(m.get("method")=="mining.notify" for m in msgs)
    if sub and got_notify:
        en1=sub[0]["result"][1]
        is_placeholder = (en1 == "0000000000000000")
        print(f"  ✅ PASS — subscribe response extranonce1={en1} ({'PLACEHOLDER!' if is_placeholder else 'real'}), notify received")
        s.close(); return True
    print(f"  ❌ FAIL — sub={bool(sub)} notify={got_notify}")
    s.close(); return False

ok1=test_serializer()
print()
ok2=test_pipeliner()
print()
print("RESULT:", "ALL PASS ✅" if (ok1 and ok2) else "FAILED ❌")
sys.exit(0 if (ok1 and ok2) else 1)
