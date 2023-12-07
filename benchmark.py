# from os import kill
import sys
import math
import numpy as np
from scapy.all import *
import subprocess
import socket
import time
import random
from scipy import stats
from decimal import *
from datetime import datetime


# define your glbals here
MF_RCV_IFACE = "eno3"
MF_FWD_IFACE = "enp5s0f0"
MF_PUBLIC_IP = "155.98.38.25"
MF_FWD_MAC = "00:10:18:56:b0:58"
SERVER_MAC = "00:24:e8:77:a7:d8"
LENGTH = 3
SURICATA_PATH = "/users/Aidan_W/suricata-6.0.2"
CLIENT_IFACE = "eno3"
CLIENT_MAC = "00:24:e8:79:29:7b"
MF_RCV_MAC = "00:24:e8:79:33:99"


def parse_stats(prev_pkts, cur_pkts, setup):
    global LENGTH
    prev_pkts_lst = prev_pkts.decode("utf-8").split("\n")
    cur_pkts_lst = cur_pkts.decode("utf-8").split("\n")
    prev_rx = 0
    prev_tx = 0
    rcv_inface = MF_RCV_IFACE
    fwd_inface = MF_FWD_IFACE

    for p in prev_pkts_lst:
        if rcv_inface in p:
            prev_rx = Decimal(p.split()[2])
            break
    for p in prev_pkts_lst:
        if fwd_inface in p:
            prev_tx = Decimal(p.split()[6])
            break
    cur_rx = 0
    cur_tx = 0
    for c in cur_pkts_lst:
        if rcv_inface in c:
            cur_rx = Decimal(c.split()[2])
            break
    for c in cur_pkts_lst:
        if fwd_inface in c:
            cur_tx = Decimal(c.split()[6])
            break

    rcv_pkts = (cur_rx - prev_rx) / LENGTH
    fwd_pkts = (cur_tx - prev_tx) / LENGTH
    #print(cur_tx)
    #print(prev_tx)
   # print(fwd_pkts)

    return rcv_pkts, fwd_pkts

def parse_stats_server(prev_pkts, cur_pkts, setup):
    global LENGTH
    prev_pkts_lst = prev_pkts.decode("utf-8").split("\n")
    cur_pkts_lst = cur_pkts.decode("utf-8").split("\n")
    prev_rx = 0
    prev_tx = 0
    rcv_inface = "eno3"
    

    for p in prev_pkts_lst:
        if rcv_inface in p:
            prev_rx = Decimal(p.split()[2])
            break

    cur_rx = 0
    cur_tx = 0
    for c in cur_pkts_lst:
        if rcv_inface in c:
            cur_rx = Decimal(c.split()[2])
            break


    rcv_pkts = (cur_rx - prev_rx) / LENGTH

    #print(cur_tx)
    #print(prev_tx)
    # print(fwd_pkts)
    return rcv_pkts
    

def run_nf(nf, limit, setup, threads=2):
    ip = MF_PUBLIC_IP
    rcv_inface = MF_RCV_IFACE
    fwd_inface = MF_FWD_IFACE
    mf_mac = MF_FWD_MAC
    dst_mac = SERVER_MAC
    username = "Aidan_W"
    key = "id_ed25519"
    suricata_conf = "suricata.yaml"
    rules = "emerging-malware.rules"
    SURICATA_PATH = "/users/Aidan_W/suricata-6.0.2"

    if nf == "SNORT2_RL":
        subprocess.run(
            [
                "ssh",
                "-i",
                f"/users/{username}/.ssh/{key}",
                f"{username}@{ip}",
                "sudo",
                "sysctl",
                "-w",
                "net.ipv4.ip_forward=0",
            ]
        )
        subprocess.Popen(
            [
                "ssh",
                "-i",
                f"/users/{username}/.ssh/{key}",
                f"{username}@{ip}",
                "sudo",
                "taskset",
                "-c",
                "3",
                f"{SNORT_PATH}/bin/snort",
                "-Q",
                "-A",
                "none",
                "-q",
                "-c",
                f"{SNORT_PATH}/etc/{snort_conf}",
                "-i",
                f"{rcv_inface}:{fwd_inface}",
            ]
        )
    elif nf == "SUR_RL":
        print("going to start suricata")
        subprocess.run(
            [
                "ssh",
                "-i",
                f"/users/{username}/.ssh/{key}",
                f"{username}@{ip}",
                "sudo",
                "sysctl",
                "-w",
                "net.ipv4.ip_forward=1",
            ]
        )

        subprocess.run(
            [
                "ssh",
                 "-i",
                f"/users/{username}/.ssh/{key}",
                f"{username}@{ip}",
                "sudo",
                "iptables",
                "-I",
                "FORWARD",
                "-i",
                rcv_inface,
                "-o",
                fwd_inface,
                "-j",
                "NFQUEUE",
            ]
        )
        subprocess.Popen(
            [
                "ssh",
                 "-i",
                f"/users/{username}/.ssh/{key}",
                f"{username}@{ip}",
                "sudo",
                f"{SURICATA_PATH}/bin/suricata",
                "-c",
                f"{SURICATA_PATH}/{suricata_conf}",
                "-q",
                "0",
                "-v",
                "--runmode",
                "workers",
                "-s",
                f"{SURICATA_PATH}/{rules}",
            ]
        )
        print("balls1")
    elif nf == "SUR_BL":
        subprocess.run(
            [
                "ssh",
                "-i",
                f"/users/{username}/.ssh/{key}",
                f"{username}@{ip}",
                "sudo",
                "sysctl",
                "-w",
                "net.ipv4.ip_forward=1",
            ]
        )
        subprocess.run(
            [
                "ssh",
                "-i",
                f"/users/{username}/.ssh/{key}",
                f"{username}@{ip}",
                "sudo",
                "iptables",
                "-I",
                "FORWARD",
                "-i",
                rcv_inface,
                "-o",
                fwd_inface,
                "-j",
                "NFQUEUE",
            ]
        )
        subprocess.Popen(
            [
                "ssh",
                "-i",
                f"/users/{username}/.ssh/{key}",
                f"{username}@{ip}",
                "sudo",
                f"{SURICATA_PATH}/bin/suricata",
                "-c",
                f"{SURICATA_PATH}/suricata/{suricata_conf}",
                "-q",
                "0",
                "-v",
                "--runmode",
                "workers",
                "-s",
                f"{SURICATA_PATH}/suricata.rules",
            ]
        )

    # sudo ./bin/snort -Q -c etc/snort.conf -i eth2:eth3 --daq-dir /usr/local/lib/daq
    elif nf == "DNF":
        delay_val = float(limit) / 1000000
        filename = f"/users/{username}/click/conf/delay-nf/delay_nf-{limit}us.click"
        generate_delay_nf(delay_val, filename, rcv_inface, fwd_inface, mf_mac, dst_mac)
        subprocess.Popen(
            [
                "scp",
                "-i",
                f"/users/{username}/.ssh/{key}",
                f"{filename}",
                f"{username}@{ip}:{filename}",
            ]
        )
        subprocess.Popen(
            [
                "ssh",
                "-i",
                f"/users/{username}/.ssh/{key}",
                f"{username}@{ip}",
                "sudo",
                f"/users/{username}/click/bin/click",
                filename,
            ]
        )
        print("started click")

    time.sleep(1)


def kill_nf(nf, setup):
    ip = "10.81.1.2"
    username = "Aidan_W"
    key = "id_ed25519"
    ip = MF_PUBLIC_IP
    SURICATA_PATH = "/users/Aidan_W/suricata-6.0.2"
    SNORT_PATH = (
        "/proj/cloudmigration-PG0/akashaf/my_ext_storage/snort_src/snort-2.9.19"
    )

    try:
        if nf == "SUR_RL" or nf == "SUR_BL":
            output = subprocess.check_output(
                [
                    "ssh",
                     "-i",
                f"/users/{username}/.ssh/{key}",
                    f"{username}@{ip}",
                    "sudo",
                    "killall",
                    f"{SURICATA_PATH}/bin/suricata",
                ]
            )
            subprocess.run(
                [
                    "ssh",
                     "-i",
                f"/users/{username}/.ssh/{key}",
                    f"{username}@{ip}",
                    "sudo",
                    "sysctl",
                    "-w",
                    "net.ipv4.ip_forward=0",
                ]
            )
            subprocess.run(
                [
                    "ssh",
                     "-i",
                f"/users/{username}/.ssh/{key}",
                    f"{username}@{ip}",
                    "sudo",
                    "iptables",
                    "-F",
                ]
            )
        elif nf == "SNORT2_RL":
            if nf == "SNORT2_RL":
                output = subprocess.check_output(
                    [
                        "ssh",
                        "-i",
                        f"/users/{username}/.ssh/{key}",
                        f"{username}@{ip}",
                        "sudo",
                        "killall",
                        f"{SNORT_PATH}/bin/snort",
                    ]
                )
            else:
                output = subprocess.check_output(
                    [
                        "ssh",
                        "-i",
                        f"/users/{username}/.ssh/{key}",
                        f"{username}@{ip}",
                        "sudo",
                        "killall",
                        "snort",
                    ]
                )
            output = subprocess.check_output(
                [
                    "ssh",
                    "-i",
                    f"/users/{username}/.ssh/{key}",
                    f"{username}@{ip}",
                    "sudo",
                    "killall",
                    "screen",
                ]
            )
        else:
            output = subprocess.check_output(
                [
                    "ssh",
                    "-i",
                    f"/users/{username}/.ssh/{key}",
                    f"{username}@{ip}",
                    "sudo",
                    "killall",
                    "click",
                ]
            )
            output = subprocess.check_output(
                [
                    "ssh",
                    "-i",
                    f"/users/{username}/.ssh/{key}",
                    f"{username}@{ip}",
                    "sudo",
                    "killall",
                    "screen",
                ]
            )
    except subprocess.CalledProcessError as err:
        print(err)
    time.sleep(3)


def send_traffic(rate, proto, nf, limit, setup, threads):
    global LENGTH
    # start the nf first
    run_nf(nf, limit, setup, threads)

    ip = MF_PUBLIC_IP
    client_inface = CLIENT_IFACE
    server_ip = "155.98.38.32"
    mf_mac = MF_RCV_MAC
    src_mac = CLIENT_MAC
    src_ip = "10.1.1.20"
    dst_ip = "192.16.1.2"
    key = "id_ed25519"
    server_mac = SERVER_MAC
    username = "Aidan_W"

    # get the current netstat stats

    # print(stats)
    time.sleep(10)
    drops = 0
    no_drops = 0

    pkts = []
    dst_mac = mf_mac
    if nf == "SNORT2_RL":
        dst_mac = server_mac

    proto = "UDP"
    
    src_ip_flag = 0
    for i in range(100):
        # + str(random.randint(20,22))

        data = "X" * 30
        if src_ip_flag == 0:
            src_ip = "10.1.1.21"
            src_ip_flag = 1
        else:
            src_ip_flag = 0
            src_ip = "10.1.1.20"
        pkt = Ether(dst=dst_mac, src=src_mac) / IP(dst=dst_ip, src=src_ip)
        if proto == "UDP":
            pkt = pkt / UDP(dport=12345, sport=6666) / Raw(load=data)
        else:
            pkt = pkt / TCP(dport=12345, flags="S", seq=1, sport=6666) / Raw(load=data)
        pkts.append(pkt)

    # rate  = pps
    # probe_len = no. of loops to send 100 pkts for 5 seconds at rate r
    # if sending r pkts in one second, then i'll need to loop r/100 for 100 pkts to send for 1 sec
    # multiply this with 5 to send for 5 seconds
    # so total packets that I am sending it 100*5*probe_len
    # total packets to send = rate*5
    # probe length = (rate*5)/100

    probe_len = math.floor((LENGTH * rate) / 100)
    
    prev_stats = subprocess.check_output(
        ["ssh",  "-i",
                f"/users/{username}/.ssh/{key}",f"{username}@155.98.38.25", "sudo", "netstat", "-i"]
    )
    server_prev_stats = subprocess.check_output(["ssh",  "-i",
                f"/users/{username}/.ssh/{key}", f"{username}@{server_ip}", "sudo", "netstat", "-i"])
  
    print(f"sending {probe_len*100} packets at rate {rate}")
    sendpfast(
        pkts,
        pps=rate,
        loop=probe_len,
        parse_results=1,
        iface=CLIENT_IFACE,
        file_cache=True,
    )
   # modify these so that they show netstat result of server, not nf
    # get current rate from mf node
    time.sleep(1)
    cur_stats = subprocess.check_output(
        ["ssh",  "-i",
                f"/users/{username}/.ssh/{key}", f"{username}@{ip}", "sudo", "netstat", "-i"]
    )
    
    server_cur_stats = subprocess.check_output(["ssh",  "-i",
                f"/users/{username}/.ssh/{key}", f"{username}@{server_ip}", "sudo", "netstat", "-i"])
    print("done sending packets")

    time.sleep(1)
    # kill the mitigation function
    kill_nf(nf, setup)
    time.sleep(30)
    
    rcv_rate, fwd_rate = parse_stats(prev_stats, cur_stats, setup)
    
    server_rcv_rate = parse_stats_server(server_prev_stats, server_cur_stats, setup)

    rcv_rate = max(rcv_rate, server_rcv_rate)

    if (rcv_rate - fwd_rate) > 1000:
        drops += 1
        print(rcv_rate, fwd_rate, drops, no_drops)

    else:
        no_drops += 1
        print(rcv_rate, fwd_rate, drops, no_drops)

    return drops, no_drops, rcv_rate


def binary_search(min_rate, max_rate, proto, rcv_rate, nf, limit, setup, threads):
    if max_rate - min_rate < 100:
        return min_rate, rcv_rate
    send_rate = math.floor((min_rate + max_rate) / 2)
    drops, no_drops, rcv_rate = send_traffic(
        send_rate, proto, nf, limit, setup, threads
    )
    print(f"drops: {drops}, no drops: {no_drops}, rcv_rate: {rcv_rate}" )
    time.sleep(10)
    if (
        drops > no_drops
    ):  # it means it is bottlenecked, increasing rate to decrease rate to find the max rate / min rate at which this holds
        bottleneck_rate, mf_side_rate = binary_search(
            min_rate, send_rate, proto, rcv_rate, nf, limit, setup, threads
        )
    elif (
        no_drops > drops
    ):  # it means it is not bottlenecked, decreasing rate to increase rate to find the bottleneck
        bottleneck_rate, mf_side_rate = binary_search(
            send_rate, max_rate, proto, rcv_rate, nf, limit, setup, threads
        )

    return bottleneck_rate, mf_side_rate


def search(min_rate, max_rate):
    bottleneck_found = 0
    send_rate = math.floor((min_rate + max_rate) / 2)
    while True:
        drops, no_drops = send_traffic(send_rate)
        time.sleep(20)
        if (
            drops > no_drops
        ):  # it means it is bottlenecked, increasing rate to decrease rate to find the max rate / min rate at which this holds
            send_rate = send_rate - 50
            bottleneck_found = 1
        elif (
            no_drops > drops
        ):  # it means it is not bottlenecked, decreasing rate to increase rate to find the bottleneck
            if bottleneck_found:
                # this means i found the bottleneck at which if I further increasing delay, the rcv and fwd rate  becomes equal
                print(f"bottleneck is {send_rate}")
                return send_rate
            send_rate = send_rate + 50

    return send_rate


def main(min_rate, max_rate, nf, limit, setup, threads):
    sender_side_bottlenecks = []
    mf_side_bottlenecks = []
    proto = "UDP"
    if nf == "SUR" or nf == "SNORT1" or nf == "SUR_RL" or nf == "SNORT2_RL":
        proto = "TCP"
    for i in range(5):
        print("enter sender side bottleneck")
        sender_side_bottleneck, mf_side_bottleneck = binary_search(
            min_rate, max_rate, proto, 0, nf, limit, setup, threads
        )
        print("exit sender side bottleneck")
        kill_nf(nf, setup)
        sender_side_bottlenecks.append(sender_side_bottleneck)
        mf_side_bottlenecks.append(mf_side_bottleneck)
        print(
            np.mean(sender_side_bottlenecks),
            np.median(sender_side_bottlenecks),
            stats.mode(sender_side_bottlenecks)[0],
            sender_side_bottlenecks,
            i,
        )
        time.sleep(120)
    print(
        np.mean(sender_side_bottlenecks),
        np.median(sender_side_bottlenecks),
        stats.mode(sender_side_bottlenecks)[0],
        sender_side_bottlenecks,
    )

    return sender_side_bottlenecks, mf_side_bottlenecks


if __name__ == "__main__":
    if len(sys.argv) < 1:
        print("USAGE: sudo python3 <filename> <nf_type> <limit>")
        exit(0)
    nf_type = sys.argv[1]
    limit = sys.argv[2]
    min_rate = float(sys.argv[3])
    max_rate = float(sys.argv[4])
    setup = sys.argv[5]
    threads = 1
    if nf_type == "MDNF":
        threads = int(sys.argv[6])
    dt = datetime.today().strftime("%Y-%m-%d-%H_%M")
    path = "/my_ext_storage"
    if setup == "b18" or setup == "b16" or setup == "b18_one_sided":
        path = "/proj/SDNNFV/akashaf/my_ext_storage"
    if setup == "wisc" or setup == "wisc-cl" or setup == "wisc2":
        path = ""
    if setup == "el":
        path = "/proj/CloudMigration/akashaf/my_ext_storage"
    f = open(f"bottlenecks_{nf_type}_{limit}_{dt}_{setup}", "w")

    sender_side_bottleneck, mf_side_bottleneck = main(
        min_rate, max_rate, nf_type, limit, setup, threads
    )

    f.write(
        f"{limit} sender "
        + ",".join(map(str, sender_side_bottleneck))
        + " median="
        + str(np.median(sender_side_bottleneck))
        + " std="
        + str(np.std(sender_side_bottleneck))
        + "\n"
    )
    f.write(
        f"{limit} mf "
        + ",".join(map(str, mf_side_bottleneck))
        + " median="
        + str(np.median(mf_side_bottleneck))
        + " std="
        + str(np.std(mf_side_bottleneck))
        + "\n"
    )
    f.close()

    # cur_rate = low rate + high rate / 2
    # if drops -> cur rate = low_rate + cur_rate / 2
    # if no drops -> cur rate = cur_rate + high rate / 2
    
    # blacklist: 53588.0 59892.0 63604 [63604, 29423, 63604, 59892, 51417] 4
# 53588.0 59892.0 63604 [63604, 29423, 63604, 59892, 51417]

#1.827212242182302e-05 1.3e-05 1.0862097600881123e-05
