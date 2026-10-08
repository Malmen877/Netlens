#!/usr/bin/env python3
"""Generates the time-series parts of the fixtures (syslog.log and the
matching `show logging` / `show log messages` outputs) so timestamps stay
consistent. Static show outputs are hand-written files. Re-run from the crate
root: python3 tools/gen_syslog.py"""
from datetime import datetime, timedelta
import random, os

ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "..", "examples", "troubleshoot")
D = lambda *a: datetime(2026, 10, 8, *a)


def ios_dev(ts):  # device timestamp: service timestamps log datetime msec show-timezone
    return ts.strftime("%b ") + f"{ts.day:2d}" + ts.strftime(" %H:%M:%S.") + f"{ts.microsecond // 1000:03d} UTC"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def ios_files(scen, host, events, seq0, header):
    events.sort()
    syslog, buf = [], []
    for i, (ts, msg) in enumerate(events):
        seq = seq0 + i
        line = f"{seq:06d}: {ios_dev(ts)}: {msg}"
        buf.append(line)
        srv = (ts + timedelta(milliseconds=2)).strftime("%Y-%m-%dT%H:%M:%S.") + \
            f"{(ts + timedelta(milliseconds=2)).microsecond // 1000:03d}+00:00"
        syslog.append(f"{srv} {host} {line}")
    write(f"{ROOT}/ios/{scen}/syslog.log", "\n".join(syslog) + "\n")
    write(f"{ROOT}/ios/{scen}/show_logging.txt", header.format(n=len(events) + 380) + "\n".join(buf) + "\n")


IOS_LOG_HEADER = """Syslog logging: enabled (0 messages dropped, 3 messages rate-limited, 0 flushes, 0 overruns, xml disabled, filtering disabled)

No Active Message Discriminator.


No Inactive Message Discriminator.


    Console logging: disabled
    Monitor logging: level debugging, 0 messages logged, xml disabled,
                     filtering disabled
    Buffer logging:  level informational, {n} messages logged, xml disabled,
                    filtering disabled
    Exception Logging: size (4096 bytes)
    Count and timestamp logging messages: disabled
    Persistent logging: disabled

No active filter modules.

    Trap logging: level informational, {n} message lines logged
        Logging to 192.0.2.50  (udp port 514, audit disabled,
              link up),
              {n} message lines logged,
              0 message lines rate-limited,
              0 message lines dropped-by-MD,
              xml disabled, sequence number enabled
              filtering disabled
        Logging Source-Interface:       VRF Name:
        Loopback0

Log Buffer (65536 bytes):

"""

# ---------------------------------------------------------------- ios/bgp-flap-mtu
P = "198.51.100.2"
ev = [
    (D(6, 40, 12, 604000), "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: noc-akarlsson] [Source: 192.0.2.50] [localport: 22] at 06:40:12 UTC Thu Oct 8 2026"),
    (D(6, 40, 35, 118000), "%CLEAR-5-COUNTERS: Clear counter on interface GigabitEthernet0/0/1 by noc-akarlsson on vty0 (192.0.2.50)"),
    (D(6, 51, 58, 402000), "%LINK-3-UPDOWN: Interface GigabitEthernet0/0/1, changed state to down"),
    (D(6, 51, 58, 405000), "%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0/1, changed state to down"),
    (D(6, 51, 58, 411000), f"%BGP-5-NBR_RESET: Neighbor {P} reset (Interface flap)"),
    (D(6, 51, 58, 413000), f"%BGP-5-ADJCHANGE: neighbor {P} Down Interface flap"),
    (D(6, 51, 58, 414000), f"%BGP_SESSION-5-ADJCHANGE: neighbor {P} IPv4 Unicast topology base removed from session  Interface flap"),
    (D(6, 55, 1, 877000), "%LINK-3-UPDOWN: Interface GigabitEthernet0/0/1, changed state to up"),
    (D(6, 55, 2, 879000), "%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0/1, changed state to up"),
    (D(7, 4, 51, 220000), "%SYS-6-LOGOUT: User noc-akarlsson has exited tty session 2(192.0.2.50)"),
]
t, snap = D(6, 55, 33, 204000), D(7, 21, 47)
while t < snap:
    ev.append((t, f"%BGP-5-ADJCHANGE: neighbor {P} Up"))
    d = t + timedelta(seconds=180, milliseconds=5)
    if d < snap:
        ev += [
            (d, f"%BGP-3-NOTIFICATION: sent to neighbor {P} 4/0 (hold time expired) 0 bytes"),
            (d + timedelta(milliseconds=1), f"%BGP-5-NBR_RESET: Neighbor {P} reset (BGP Notification sent)"),
            (d + timedelta(milliseconds=3), f"%BGP-5-ADJCHANGE: neighbor {P} Down BGP Notification sent"),
            (d + timedelta(milliseconds=4), f"%BGP_SESSION-5-ADJCHANGE: neighbor {P} IPv4 Unicast topology base removed from session  BGP Notification sent"),
        ]
    t = d + timedelta(seconds=31)
ios_files("bgp-flap-mtu", "sto-edge-rtr01", ev, 2791, IOS_LOG_HEADER)

# ---------------------------------------------------------------- ios/ospf-exstart-mtu
N = "Process 10, Nbr 203.0.113.21 on GigabitEthernet0/0/2 from"
ev = [
    (D(6, 9, 51, 330000), "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: rancid] [Source: 192.0.2.60] [localport: 22] at 06:09:51 UTC Thu Oct 8 2026"),
    (D(6, 9, 58, 12000), "%SYS-6-LOGOUT: User rancid has exited tty session 2(192.0.2.60)"),
    (D(6, 14, 7, 331000), f"%OSPF-5-ADJCHG: {N} FULL to DOWN, Neighbor Down: Dead timer expired"),
]
t, snap = D(6, 14, 12, 902000), D(6, 41, 22)
while t < snap:
    ev.append((t, f"%OSPF-5-ADJCHG: {N} DOWN to INIT, Received Hello"))
    ev.append((t + timedelta(milliseconds=3), f"%OSPF-5-ADJCHG: {N} INIT to 2WAY, 2-Way Received"))
    ev.append((t + timedelta(milliseconds=4), f"%OSPF-5-ADJCHG: {N} 2WAY to EXSTART, AdjOK?"))
    d = t + timedelta(seconds=125, milliseconds=410)
    if d < snap:
        ev.append((d, f"%OSPF-5-ADJCHG: {N} EXSTART to DOWN, Neighbor Down: Too many retransmissions"))
    t = d + timedelta(seconds=9, milliseconds=388)
ios_files("ospf-exstart-mtu", "osl-dist-rtr02", ev, 18402, IOS_LOG_HEADER)

# ---------------------------------------------------------------- ios/interface-errdisabled
ev = [
    (D(7, 58, 40, 117000), "%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/31, changed state to up"),
    (D(7, 58, 39, 109000), "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/31, changed state to up"),
    (D(8, 3, 11, 310000), "%ILPOWER-7-DETECT: Interface Gi1/0/12: Power Device detected: IEEE PD"),
    (D(8, 3, 11, 912000), "%ILPOWER-5-POWER_GRANTED: Interface Gi1/0/12: Power granted"),
    (D(8, 3, 15, 441000), "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/12, changed state to up"),
    (D(8, 3, 16, 448000), "%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/12, changed state to up"),
    (D(8, 3, 17, 902000), "%SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port GigabitEthernet1/0/12 with BPDU Guard enabled. Disabling port."),
    (D(8, 3, 17, 903000), "%PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/12, putting Gi1/0/12 in err-disable state"),
    (D(8, 3, 18, 905000), "%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/12, changed state to down"),
    (D(8, 3, 19, 902000), "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/12, changed state to down"),
    (D(8, 3, 19, 951000), "%ILPOWER-5-IEEE_DISCONNECT: Interface Gi1/0/12: PD removed"),
    (D(8, 47, 2, 518000), "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: helpdesk-lnielsen] [Source: 192.0.2.71] [localport: 22] at 08:47:02 UTC Thu Oct 8 2026"),
    (D(8, 47, 30, 6000), "%SYS-6-LOGOUT: User helpdesk-lnielsen has exited tty session 1(192.0.2.71)"),
]
ios_files("interface-errdisabled", "cph-acc-sw07", ev, 30117, IOS_LOG_HEADER)

# ---------------------------------------------------------------- eos/bgp-flap-crc
host = "ams-leaf-sw03"
S = "peer 192.0.2.0 (VRF default AS 64600)"
rnd = random.Random(42)
ev = [(D(7, 7, 42), "ConfigAgent: %SYS-5-CONFIG_E: Enter configuration mode from console by noc-pvdberg on vty3 (192.0.2.50)"),
      (D(7, 7, 49), "Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet47 (P2P_ams-spine-sw01_Ethernet3/1), changed state to down"),
      (D(7, 7, 49), f"Bgp: %BGP-5-ADJCHANGE: {S} old state Established event Stop new state Idle"),
      (D(7, 7, 55), "Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet47 (P2P_ams-spine-sw01_Ethernet3/1), changed state to up"),
      (D(7, 8, 1), f"Bgp: %BGP-5-ADJCHANGE: {S} old state OpenConfirm event RecvKeepAlive new state Established"),
      (D(7, 8, 3), "ConfigAgent: %SYS-5-CONFIG_I: Configured from console by noc-pvdberg on vty3 (192.0.2.50)")]
t, snap = D(7, 12, 30), D(9, 22, 35)
flaps = []
while True:
    t += timedelta(seconds=rnd.randint(180, 520))
    if t > D(9, 21, 43):
        break
    flaps.append(t)
flaps[-1] = D(9, 21, 43)
for f in flaps:
    ev += [(f, f"Bgp: %BGP-3-NOTIFICATION: sent to neighbor 192.0.2.0 (VRF default AS 64600) 4/0 (Hold Timer Expired Error) 0 bytes"),
           (f, f"Bgp: %BGP-5-ADJCHANGE: {S} old state Established event HoldTimerExpired new state Idle"),
           (f + timedelta(seconds=11), f"Bgp: %BGP-5-ADJCHANGE: {S} old state OpenConfirm event RecvKeepAlive new state Established")]
print("eos flaps", len(flaps), "last up", flaps[-1] + timedelta(seconds=11))
ev.sort()
lines = [f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')} {host} {m}" for ts, m in ev]
write(f"{ROOT}/eos/bgp-flap-crc/syslog.log", "\n".join(lines) + "\n")
write(f"{ROOT}/eos/bgp-flap-crc/show_logging.txt", """Syslog logging: enabled
    Buffer logging: level debugging
    Console logging: level errors
    Persistent logging: disabled
    Monitor logging: level errors
    Synchronous logging: disabled
    Trap logging: level informational
    Logging to '192.0.2.50' port 514 in VRF MGMT via udp
    Sequence numbers: disabled
    Syslog facility: local7
    Hostname format: Hostname only
    Repeat logging interval: disabled
    Repeat messages: disabled
    Root login logging: disabled

Facility                   Severity            Effective Severity
--------------------       -------------       ------------------
aaa                        debugging           debugging
accounting                 debugging           debugging
bgp                        debugging           debugging

Log Buffer:
""" + "\n".join(lines) + "\n")

# ---------------------------------------------------------------- junos/bgp-auth-mismatch
host = "fra-pe-mx01"
ev = [
    (D(9, 28, 40), "sshd[47702]: Accepted publickey for noc-mweber from 192.0.2.80 port 51022 ssh2: ED25519 SHA256:EXAMPLEfixtureFINGERPRINT0000000000000000"),
    (D(9, 28, 41), "mgd[48211]: UI_LOGIN_EVENT: User 'noc-mweber' login, class 'j-super-user' [48211], ssh-connection '192.0.2.80 51022 192.0.2.10 22', client-mode 'cli'"),
    (D(9, 30, 55), "mgd[48211]: UI_DBASE_LOGIN_EVENT: User 'noc-mweber' entering configuration mode"),
    (D(9, 31, 2), "mgd[48211]: UI_COMMIT: User 'noc-mweber' requested 'commit' operation (comment: CHG-31120 rotate CUST-ACME md5 keys)"),
    (D(9, 31, 4), "mgd[48211]: UI_COMMIT_COMPLETED: commit complete"),
    (D(9, 31, 9), "mgd[48211]: UI_DBASE_LOGOUT_EVENT: User 'noc-mweber' exiting configuration mode"),
    (D(9, 31, 31), "kernel: tcp_auth_ok: Packet from 203.0.113.9:179 wrong MD5 digest"),
    (D(9, 32, 1), "kernel: tcp_auth_ok: Packet from 203.0.113.9:179 wrong MD5 digest"),
    (D(9, 32, 31), "kernel: tcp_auth_ok: Packet from 203.0.113.9:179 wrong MD5 digest"),
    (D(9, 32, 35), "rpd[2041]: bgp_hold_timeout:4065: NOTIFICATION sent to 203.0.113.9 (External AS 64530): code 4 (Hold Timer Expired Error), Reason: holdtime expired for 203.0.113.9 (External AS 64530), socket buffer sndcc: 19 rcvcc: 0 TCP state: 4, snd_una: 2918823411 snd_nxt: 2918823430 snd_wnd: 16384 rcv_nxt: 1022377219 rcv_adv: 1022393603, hold timer out 90s, hold timer remain 0s"),
    (D(9, 32, 35), "rpd[2041]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 203.0.113.9 (External AS 64530) changed state from Established to Idle (event HoldTime) (instance master)"),
    (D(9, 33, 12), "mgd[48211]: UI_LOGOUT_EVENT: User 'noc-mweber' logout"),
]
t = D(9, 32, 48)
port = 52114
while t < D(11, 14, 40):
    ev.append((t, f"kernel: tcp_auth_ok: Packet from 203.0.113.9:{port} wrong MD5 digest"))
    port += rnd.randint(3, 40)
    t += timedelta(seconds=rnd.choice([30, 30, 31, 60, 120]))
ev.append((D(10, 15, 0), "/usr/sbin/cron[61722]: (root) CMD (newsyslog)"))
ev.append((D(10, 47, 13), "chassisd[3011]: CHASSISD_SNMP_TRAP7: SNMP trap generated: Fan/Blower Speed changed (jnxFruContentsIndex 4, jnxFruL1Index 1, jnxFruL2Index 0, jnxFruL3Index 0, jnxFruName Fan Tray 0 Fan 0, jnxFruType 13, jnxFruSlot 0)"))
ev.sort(key=lambda e: e[0])
lines = [f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}  {host} {m}" for ts, m in ev]
base = f"{ROOT}/junos/bgp-auth-mismatch"
write(f"{base}/syslog.log", "\n".join(lines) + "\n")
write(f"{base}/show_log_messages.txt", "\n".join(lines) + "\n")
write(f"{base}/show_log_messages_match_tcp_auth.txt", "\n".join(l for l in lines if "tcp_auth" in l) + "\n")
print("junos tcp_auth lines", sum("tcp_auth" in l for l in lines))
