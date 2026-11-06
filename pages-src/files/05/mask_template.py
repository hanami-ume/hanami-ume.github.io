"""L05 骨架：补全 TODO 后运行，生成 cleaned.csv 并打印 MD5。"""
import csv, re, hashlib, datetime

W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
C = "10X98765432"

def id_ok(s):
    if not re.fullmatch(r"\d{17}[\dX]", s):
        return False
    try:
        datetime.date(int(s[6:10]), int(s[10:12]), int(s[12:14]))
    except ValueError:
        return False
    # TODO: 计算校验码并与 s[17] 比较
    return True

def phone_ok(p):
    return re.fullmatch(r"1[3-9]\d{9}", p) is not None

rows = list(csv.DictReader(open("senders.csv", encoding="utf-8")))
keep, removed = [], []
for r in rows:
    if r["consent"] == "Y" and phone_ok(r["phone"]) and id_ok(r["id_card"]):
        keep.append(r)
    else:
        removed.append(int(r["id"]))
print("剔除:", "_".join(map(str, sorted(removed))))

keep.sort(key=lambda r: int(r["id"]))
lines = ["id,name,phone,id_card"]
for r in keep:
    name = r["name"][0] + "*" * (len(r["name"]) - 1)
    phone = r["phone"]  # TODO: 保留前3后4
    idc = r["id_card"]  # TODO: 保留前6后4
    lines.append(",".join([r["id"], name, phone, idc]))
data = ("\r\n".join(lines) + "\r\n").encode("utf-8")
open("cleaned.csv", "wb").write(data)
print("MD5:", hashlib.md5(data).hexdigest())
