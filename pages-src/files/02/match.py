"""L02 练习脚本：把每条签名分别用 4 把公钥验签。只需要补全 TODO 处的一行。"""
import json
import gm

keys = json.load(open("public_keys.json", encoding="utf-8"))
sigs = json.load(open("signatures.json", encoding="utf-8"))

def parse_pub(h):
    assert h.startswith("04") and len(h) == 130
    return int(h[2:66], 16), int(h[66:], 16)

for sig in sigs:
    r, s = int(sig["rs"][:64], 16), int(sig["rs"][64:], 16)
    for k in keys:
        pub = parse_pub(k["public_key"])
        e_field = int(sig["e"], 16)                              # 方式一：使用记录的 e 字段
        e_raw = int.from_bytes(sig["M"].encode("utf-8"), "big")  # 方式二：直接用消息本身（缺陷实现）
        # TODO（可选）：方式三，按规范重新计算 e = SM3(ZA || M)，提示：gm.e_standard(...)
        print(sig["id"], "key", k["key_id"],
              "e字段:", gm.verify_e(e_field, r, s, pub),
              "消息本身:", gm.verify_e(e_raw, r, s, pub))
