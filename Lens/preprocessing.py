#!/usr/bin/env python3
'''
Step 1
[pcap file] -> [flow extraction] -> [anonymize] -> [hex form] -> [Tokenization]

'''

import argparse
import json
import hashlib
import os 
from pathlib import Path

from scapy.utils import RawPcapReader
from scapy.all import Ether, IP, IPv6, TCP, UDP, Dot1Q

# -------------------------------------------------------------
# 0. Tokenization Settings
# -------------------------------------------------------------
SPECIAL_TOKENS = ["<pad>", "</s>", "<unk>", "<tsk>", "<head>", "<pkt>"]
PAD_ID, EOS_ID, UNK_ID, TSK_ID, HEAD_ID, PKT_ID = range(6)

# 65,536 4-hex tokens (hx0000~hxFFFF)
HEX16K = [f"hx{v:04X}" for v in range(0x10000)]

def build_vocab():
    id_to_token = list(SPECIAL_TOKENS) + HEX16K
    token_to_id = {tok: i for i, tok in enumerate(id_to_token)}
    return token_to_id, id_to_token

def save_vocab(path, id_to_token):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"id_to_token": id_to_token}, f, ensure_ascii=False)

def load_vocab(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    id_to_token = data["id_to_token"]
    token_to_id = {tok: i for i, tok in enumerate(id_to_token)}
    return token_to_id, id_to_token


# -------------------------------------------------------------
# 1. Generate Flow Key (IPv4/IPv6 5-tuple first, OR L2)
# - flow key must be created by parsing the pre-anonymized bytes
# -------------------------------------------------------------

def make_flow_key(pkt):
    try:
        if IP in pkt:
            ip = pkt[IP]
            proto = 0; sport = 0; dport = 0
            if TCP in pkt:
                proto = 6
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = 17
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
            return ("IPv4", ip.src, ip.dst, proto, sport, dport)
        if IPv6 in pkt:
            ip6 = pkt[IPv6]
            proto = 0; sport = 0; dport = 0
            if TCP in pkt:
                proto = 6
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = 17
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
            return ("IPv6", ip6.src, ip6.dst, proto, sport, dport)
        eth = pkt[Ether]
        return ("L2", eth.src, eth.dst, int(eth.type))
    except Exception:
        return ("UNKNOWN",)


# # of VLAN layer / Ethernet header length
def count_vlan_layers(pkt):
    n = 0
    try:
        cur = pkt
        while cur is not None and cur.haslayer(Dot1Q):
            n += 1
            cur = cur.getlayer(Dot1Q).payload
    except Exception:
        n = 0
    return n

def ethernet_header_len(pkt):
    return 14 + 4 * count_vlan_layers(pkt)

# L3/L4 header length estimation

def l3_l4_header_len(pkt):
    ip_len = 0
    l4_len = 0
    try:
        if IP in pkt:
            ip = pkt[IP]
            if hasattr(ip, 'ihl') and ip.ihl:
                ip_len = int(ip.ihl) * 4
            else:
                ip_len = 20
            if TCP in pkt:
                tcp = pkt[TCP]
                if hasattr(tcp, 'dataofs') and tcp.dataofs:
                    l4_len = int(tcp.dataofs) * 4
                else:
                    l4_len = 20
            elif UDP in pkt:
                l4_len = 8
        elif IPv6 in pkt:
            ip_len = 40
            if TCP in pkt:
                tcp = pkt[TCP]
                if hasattr(tcp, 'dataofs') and tcp.dataofs:
                    l4_len = int(tcp.dataofs) * 4
                else:
                    l4_len = 20
            elif UDP in pkt:
                l4_len = 8
    except Exception:
        ip_len = 0; l4_len = 0
    return ip_len, l4_len

# -------------------------------------------------------------
# 2. Anonymize: IPv4/IPv6 address, TCP/UDP port into 0
# - The checksum field is removed, forcing the scapy to recalculate it.
# - For the L2-only frames like ARP, since there are no IPs or ports here there's nothin to anonymize in this case. (pass)
# -------------------------------------------------------------

def anonymize_packet(pkt):
    q = pkt.copy()
    try:
        if IP in q:
            q[IP].src = "0.0.0.0"
            q[IP].dst = "0.0.0.0"
            if hasattr(q[IP], 'chksum'):
                del q[IP].chksum
            if TCP in q:
                q[TCP].sport = 0
                q[TCP].dport = 0
                if hasattr(q[TCP], 'chksum'):
                    del q[TCP].chksum
            if UDP in q:
                q[UDP].sport = 0
                q[UDP].dport = 0
                if hasattr(q[UDP], 'chksum'):
                    del q[UDP].chksum
        elif IPv6 in q:
            q[IPv6].src = "::"
            q[IPv6].dst = "::"
            if TCP in q:
                q[TCP].sport = 0
                q[TCP].dport = 0
                if hasattr(q[TCP], 'chksum'):
                    del q[TCP].chksum
            if UDP in q:
                q[UDP].sport = 0
                q[UDP].dport = 0
                if hasattr(q[UDP], 'chksum'):
                    del q[UDP].chksum
    except Exception:
        pass
    return q

# -------------------------------------------------------------
# 3. Hex form : Anonymized packet byte → (header_hex, payload_hex)
# -------------------------------------------------------------

def packet_to_hex_parts(pkt):
    q = anonymize_packet(pkt)    # Anonymize first
    raw = bytes(q)               # Scapy automatically recalculated the checksum field if it's empty when bytes(q)
    eth_len = ethernet_header_len(q)
    ip_len, l4_len = l3_l4_header_len(q)
    header_end = eth_len + ip_len + l4_len # header length
    if header_end > len(raw):
        header_end = len(raw)
    header_hex = raw[:header_end].hex()    # header
    payload_hex = raw[header_end:].hex()   # payload
    return header_hex, payload_hex

# Hash flow_id 

def key_to_flow_id(key_tuple):
    s = json.dumps(key_tuple, ensure_ascii=False)
    return hashlib.sha256(s.encode()).hexdigest()[:16]

# -------------------------------------------------------------
# Main pipeline : RawPcapReader → Flow dict
# -------------------------------------------------------------

def process_pcap_to_flows(pcap_path, max_packets_per_flow=3, label_csv=None, label_map=None, show=0):
    flows = {}
    total = 0

    labels = None
    if label_csv and os.path.exists(label_csv):
        import pandas as pd
        df_label = pd.read_csv(label_csv, header=None, names=["idx", "label", "y_desc"]) 
        if label_map is None:
            label_map = {"Normal": 0, "Abnormal": 1}
        df_label["y"] = df_label["label"].map(label_map)
        labels = df_label["y"].values 
        print("Loaded labels: {} records".format(len(labels)))

    reader = RawPcapReader(str(pcap_path))
    for i, (payload, meta) in enumerate(reader):
        total += 1
        try:
            pkt = Ether(payload)
        except Exception:
            continue

        # 1) flow key (before anonymize)
        key = make_flow_key(pkt)
        if key not in flows:
            flows[key] = []
        if len(flows[key]) >= max_packets_per_flow:
            continue

        # 2) anonymize + hex form
        hhex, phex = packet_to_hex_parts(pkt)

        rec = {"header_hex": hhex, "payload_hex": phex}
        if labels is not None and i < len(labels):
            rec["y"] = int(labels[i])
            rec["idx"] = i
        flows[key].append(rec)

    reader.close()

    # test
    if show > 0:
        c = 0
        for k, pkts in flows.items():
            print("[PREVIEW] flow_id=", key_to_flow_id(k), "| packets=", len(pkts))
            if pkts:
                first = pkts[0]
                print("  header_hex(64 words):", first["header_hex"][:64], "...")
                print("  payload_hex(64 words):", first["payload_hex"][:64], "...")
                if "y" in first:
                    print("  label(y)=", first["y"], ", idx=", first.get("idx"))
            c += 1
            if c >= show:
                break

    print("Parsed packets: {} | flows: {}".format(total, len(flows)))
    return flows

# -------------------------------------------------------------
# 4. Tokenization (revising...)
# -------------------------------------------------------------

def hex_to_hx_tokens(hex_str):
    # Convert hex string into a list of hxABCD tokens, splitting it into 2-byte(=4-hex) units
    # If the length is not divisible by 4, pad the end with '00'
    # e.g., '012345' -> ['hx0123', 'hx4500']
    if hex_str is None or len(hex_str) == 0:
        return []
    s = hex_str.lower()
    if len(s) % 2 == 1: # for safety : although .hex() is even number
        s += '0'
    # 2-byte token
    rem = len(s) % 4
    if rem != 0:
        s += '0' * (4 - rem)
    tokens = []
    for i in range(0, len(s), 4):
        chunk = s[i:i+4]
        tokens.append('hx' + chunk.upper())
    return tokens

def packets_to_token_sequence(packets, max_tokens=None):
    # session flow packet list(header_hex/payload_hex) -> token sequence
    # format : [<pkt>, <head>, hx...., ..., hx...., <pkt>, <head>, ...]
    # If max_tokens is given, the excess in truncated.
    seq = []
    for p in packets:
        seq.append("<pkt>")
        seq.append("<head>")
        seq += hex_to_hx_tokens(p.get("header_hex", ""))
        if max_tokens is not None and len(seq) >= max_tokens:
            seq = seq[:max_tokens]
            break
    return seq

def tokens_to_ids(tokens, token_to_id):
    ids = []
    for t in tokens:
        ids.append(token_to_id.get(t, UNK_ID))
    return ids 



def save_flows_jsonl(flows, out_path, emit_tokens=False, emit_ids=False, max_tokens=None, vocab_path="hex16k_vocab.json", save_vocab=False):
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)


    # Prepare vocab
    if os.path.exists(vocab_path):
        token_to_id, id_to_token = load_vocab(vocab_path)
        print(f"Loaded vocab: {vocab_path} (size={len(id_to_token)})")
    else:
        token_to_id, id_to_token = build_vocab()   
        if save_vocab:
            save_vocab(vocab_path, id_to_token)
            print(f"Saved new vocab: {vocab_path} (size={len(id_to_token)})")
        else:
            print(f"Using in-memory vocab (size={len(id_to_token)})")

    n = 0
    with out_path.open("w", encoding="utf-8") as f:
        for key, pkts in flows.items():
            rec = {
                "flow_id": key_to_flow_id(key),
                "num_packets": len(pkts),
                "packets": pkts,
            }
            if emit_tokens or emit_ids:
                toks = packets_to_token_sequence(pkts, max_tokens=max_tokens)
                if emit_tokens:
                    rec["input"] = " ".join(toks)
                if emit_ids:
                    rec["input_ids"] = tokens_to_ids(toks, token_to_id)
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    print("Saved {} flows → {}".format(n, out_path))


# -------------------------------------------------------------
# CLI
# -------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="input PCAP path")
    ap.add_argument("--out", required=True, help="output JSONL path")
    ap.add_argument("--max-packets", type=int, default=3, help="# of maximum packets per flow")
    ap.add_argument("--max-tokens", type=int, default=2048, help="# of maximum tokens per flow")
    ap.add_argument("--emit-tokens", action="store_true", help="print 공백 구분 토큰 문자열 'input' field")
    ap.add_argument("--emit-ids", action="store_true", help="print integer ID array 'input_ids' field")
    ap.add_argument("--vocab", default="hex16k_vocab.json", help="vocab JSON path")
    ap.add_argument("--save-vocab", action="store_true", help="store as file if no vocab")
    ap.add_argument("--show", type=int, default=0, help="# of example flow")
    args = ap.parse_args()


    flows = process_pcap_to_flows(
        pcap_path=args.pcap,
        max_packets_per_flow=args.max_packets,
        show=args.show,
    )

    save_flows_jsonl(
        flows,
        out_path=args.out,
        emit_tokens=args.emit_tokens,
        emit_ids=args.emit_ids,
        max_tokens=args.max_tokens,
        vocab_path=args.vocab,
        save_vocab=args.save_vocab,
    )

if __name__ == "__main__":
    main()

