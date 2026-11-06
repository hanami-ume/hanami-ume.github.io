"""离线 PCAP 摘要：列出明文 HTTP 请求/响应所在帧号，并标出疑似手机号、身份证号。
用法：python3 pcap_summary.py 文件.pcap      （仅标准库；只解析 Ethernet/IPv4/TCP 经典 pcap）"""
import re, struct, sys

W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
def id_valid(s):
    if not re.fullmatch(r"\d{17}[\dX]", s): return False
    return "10X98765432"[sum(int(a) * b for a, b in zip(s[:17], W)) % 11] == s[17]

def frames(path):
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    if magic != 0xA1B2C3D4: sys.exit("只支持小端经典 pcap（不支持 pcapng，可在 Wireshark 另存为 pcap）")
    off, n = 24, 0
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack("<IIII", data[off:off + 16]); off += 16
        n += 1; yield n, data[off:off + incl]; off += incl

def main(path):
    for no, f in frames(path):
        if len(f) < 54 or f[12:14] != b"\x08\x00" or f[23] != 6: continue
        ihl = (f[14] & 15) * 4; ip = f[14:14 + ihl]
        src, dst = ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20]))
        t = 14 + ihl; sport, dport = struct.unpack("!HH", f[t:t + 4]); doff = (f[t + 12] >> 4) * 4
        payload = f[t + doff:]
        if not payload: continue
        text = payload.decode("utf-8", "replace")
        first = text.split("\r\n", 1)[0]
        print(f"帧 {no:>3}  {src}:{sport} -> {dst}:{dport}  {first}")
        body = text.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in text else ""
        for m in re.findall(r"(?<!\d)1[3-9]\d{9}(?!\d)", body):
            print(f"        ! 疑似明文手机号: {m}")
        for m in re.findall(r"(?<![\dA-Za-z])\d{17}[\dX](?![\dA-Za-z])", body):
            print(f"        ! 18 位数字串: {m}  校验位{'正确' if id_valid(m) else '错误'}")

if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit(__doc__)
    main(sys.argv[1])
