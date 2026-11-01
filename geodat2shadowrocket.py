#!/usr/bin/env python3
"""
geodat2shadowrocket — конвертер geosite.dat / geoip.dat (формат V2Ray/Xray)
в rule-set файлы для Shadowrocket (iOS).

Источник по умолчанию: https://github.com/runetfreedom/russia-v2ray-rules-dat

Без внешних зависимостей (только стандартная библиотека Python 3.8+).

Примеры:
  # список категорий
  python3 geodat2shadowrocket.py --list geosite
  python3 geodat2shadowrocket.py --list geoip

  # по файлу на категорию
  python3 geodat2shadowrocket.py geosite:ru-blocked geoip:ru-blocked geosite:youtube

  # объединённый список: имя=категория+категория
  python3 geodat2shadowrocket.py "telegram=geosite:telegram+geoip:telegram"

  # фильтр по атрибутам: @attr — только с атрибутом, @!attr — без него
  python3 geodat2shadowrocket.py "ads=geosite:category-ads-all@ads"

  # + готовый shadowrocket.conf с RULE-SET на ваш хостинг
  python3 geodat2shadowrocket.py -o out \\
      --base-url https://raw.githubusercontent.com/USER/REPO/rules \\
      --policy ads=REJECT --final DIRECT \\
      "ads=geosite:category-ads-all" geosite:ru-blocked geoip:ru-blocked
"""

import argparse
import ipaddress
import os
import sys
import urllib.request
from collections import OrderedDict

DEFAULT_GEOSITE = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
DEFAULT_GEOIP = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat"

# Domain.Type в routercommon.proto
T_PLAIN, T_REGEX, T_DOMAIN, T_FULL = 0, 1, 2, 3


# ---------------------------------------------------------------- protobuf ---

def _varint(buf, pos):
    result = shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, pos
        shift += 7


def _fields(buf, start=0, end=None):
    """Итератор (field_no, wire_type, value) по сообщению protobuf.
    Для length-delimited value = (begin, end) — срез без копирования."""
    pos = start
    end = len(buf) if end is None else end
    while pos < end:
        key, pos = _varint(buf, pos)
        fno, wt = key >> 3, key & 7
        if wt == 0:
            val, pos = _varint(buf, pos)
        elif wt == 2:
            ln, pos = _varint(buf, pos)
            val = (pos, pos + ln)
            pos += ln
        elif wt == 1:
            val = buf[pos:pos + 8]
            pos += 8
        elif wt == 5:
            val = buf[pos:pos + 4]
            pos += 4
        else:
            raise ValueError(f"неподдерживаемый wire type {wt}")
        yield fno, wt, val


def index_dat(buf):
    """{ИМЯ_КАТЕГОРИИ_lower: (begin, end)} для GeoSiteList/GeoIPList (поле 1)."""
    idx = {}
    for fno, wt, val in _fields(buf):
        if fno != 1 or wt != 2:
            continue
        b, e = val
        for f2, w2, v2 in _fields(buf, b, e):
            if f2 == 1 and w2 == 2:
                idx[bytes(buf[v2[0]:v2[1]]).decode().lower()] = (b, e)
                break
    return idx


def parse_geosite(buf, span):
    """-> список (type, value, set(attrs))"""
    out = []
    for fno, wt, val in _fields(buf, *span):
        if fno != 2 or wt != 2:
            continue
        dtype, value, attrs = T_PLAIN, "", set()
        for f, w, v in _fields(buf, *val):
            if f == 1 and w == 0:
                dtype = v
            elif f == 2 and w == 2:
                value = bytes(buf[v[0]:v[1]]).decode()
            elif f == 3 and w == 2:
                for fa, wa, va in _fields(buf, *v):
                    if fa == 1 and wa == 2:
                        attrs.add(bytes(buf[va[0]:va[1]]).decode().lower())
        out.append((dtype, value, attrs))
    return out


def parse_geoip(buf, span):
    """-> (список ip_network, reverse_match)"""
    nets, reverse = [], False
    for fno, wt, val in _fields(buf, *span):
        if fno == 3 and wt == 0:
            reverse = bool(val)
        if fno != 2 or wt != 2:
            continue
        ip, prefix = b"", 0
        for f, w, v in _fields(buf, *val):
            if f == 1 and w == 2:
                ip = bytes(buf[v[0]:v[1]])
            elif f == 2 and w == 0:
                prefix = v
        if len(ip) in (4, 16):
            nets.append(ipaddress.ip_network((ip, prefix), strict=False))
    return nets, reverse


# ------------------------------------------------------------------ loading --

def load(src, cache_dir):
    if src.startswith(("http://", "https://")):
        os.makedirs(cache_dir, exist_ok=True)
        path = os.path.join(cache_dir, os.path.basename(src.split("?")[0]))
        print(f"↓ {src}", file=sys.stderr)
        req = urllib.request.Request(src, headers={"User-Agent": "geodat2shadowrocket"})
        with urllib.request.urlopen(req, timeout=300) as r, open(path, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        src = path
    with open(src, "rb") as f:
        return memoryview(f.read())


class Dat:
    def __init__(self, src, cache_dir):
        self.src, self.cache_dir = src, cache_dir
        self._buf = self._idx = None

    @property
    def buf(self):
        if self._buf is None:
            self._buf = load(self.src, self.cache_dir)
            self._idx = index_dat(self._buf)
        return self._buf

    @property
    def idx(self):
        self.buf
        return self._idx


# ---------------------------------------------------------------- building ---

class Bucket:
    def __init__(self):
        self.full, self.suffix, self.keyword, self.regex = set(), set(), set(), set()
        self.nets = []
        self.skipped_reverse = []

    def add_site(self, entries, attr_filter):
        for dtype, value, attrs in entries:
            if not attr_ok(attrs, attr_filter):
                continue
            value = value.strip().lower().rstrip(".")
            if not value:
                continue
            {T_FULL: self.full, T_DOMAIN: self.suffix,
             T_PLAIN: self.keyword, T_REGEX: self.regex}.get(dtype, self.keyword).add(value)

    def optimize(self):
        """Убирает домены, уже покрытые более общим DOMAIN-SUFFIX / KEYWORD."""
        def covered(d, include_self):
            parts = d.split(".")
            for i in range(0 if include_self else 1, len(parts)):
                if ".".join(parts[i:]) in self.suffix:
                    return True
            return False

        self.suffix = {d for d in self.suffix if not covered(d, False)}
        self.full = {d for d in self.full if not covered(d, True)}
        if self.keyword and len(self.keyword) < 200:
            kws = list(self.keyword)
            self.suffix = {d for d in self.suffix if not any(k in d for k in kws)}
            self.full = {d for d in self.full if not any(k in d for k in kws)}
        v4 = [n for n in self.nets if n.version == 4]
        v6 = [n for n in self.nets if n.version == 6]
        self.nets = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))


def attr_ok(attrs, flt):
    for want, neg in flt:
        if (want in attrs) == neg:
            return False
    return True


def parse_ref(ref):
    """'geosite:name@attr@!attr2' -> (kind, name, [(attr, negated)])"""
    if ":" not in ref:
        raise SystemExit(f"ожидается geosite:<имя> или geoip:<имя>, получено '{ref}'")
    kind, rest = ref.split(":", 1)
    kind = kind.strip().lower()
    if kind not in ("geosite", "geoip"):
        raise SystemExit(f"неизвестный тип '{kind}' в '{ref}'")
    name, *attrs = rest.split("@")
    flt = [(a[1:].lower(), True) if a.startswith("!") else (a.lower(), False) for a in attrs if a]
    return kind, name.strip().lower(), flt


def parse_spec(spec):
    if "=" in spec:
        out, refs = spec.split("=", 1)
    else:
        out, refs = None, spec
    refs = [parse_ref(r) for r in refs.split("+") if r.strip()]
    if out is None:
        k, n, f = refs[0]
        out = f"{k}-{n}" + "".join(("-no-" if neg else "-") + a for a, neg in f)
    return out.strip(), refs


# ----------------------------------------------------------------- writing ---

def write_outputs(name, b, outdir, fmt, no_resolve, header):
    files = []
    nr = ",no-resolve" if no_resolve else ""
    n_domains = len(b.full) + len(b.suffix)
    use_set = fmt == "domainset" or (fmt == "auto" and n_domains >= 20000)

    rules = []
    if not use_set:
        rules += [f"DOMAIN,{d}" for d in sorted(b.full)]
        rules += [f"DOMAIN-SUFFIX,{d}" for d in sorted(b.suffix)]
    rules += [f"DOMAIN-KEYWORD,{k}" for k in sorted(b.keyword)]
    rules += [f"IP-CIDR,{n}{nr}" if n.version == 4 else f"IP-CIDR6,{n}{nr}" for n in b.nets]

    stats = (f"DOMAIN={len(b.full)} DOMAIN-SUFFIX={len(b.suffix)} KEYWORD={len(b.keyword)} "
             f"IP-CIDR={len(b.nets)} regex(пропущено)={len(b.regex)}")

    if use_set and n_domains:
        p = os.path.join(outdir, f"{name}.domainset.txt")
        with open(p, "w") as f:
            f.write(f"# {header}\n# {name}: {stats}\n")
            for d in sorted(b.full):
                f.write(d + "\n")
            for d in sorted(b.suffix):
                f.write("." + d + "\n")
        files.append(("DOMAIN-SET", p))
    if rules:
        p = os.path.join(outdir, f"{name}.list")
        with open(p, "w") as f:
            f.write(f"# {header}\n# {name}: {stats}\n")
            f.write("\n".join(rules) + "\n")
        files.append(("RULE-SET", p))
    if b.regex:
        p = os.path.join(outdir, f"{name}.regex-skipped.txt")
        with open(p, "w") as f:
            f.write("# Регулярные выражения geosite (Shadowrocket не поддерживает DOMAIN-REGEX)\n")
            f.write("\n".join(sorted(b.regex)) + "\n")
    return files, stats


CONF_TEMPLATE = """# Shadowrocket config — сгенерировано geodat2shadowrocket
# Источник: {source}
[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
dns-server = system
fallback-dns-server = system
ipv6 = false
prefer-ipv6 = false
dns-direct-system = false
icmp-auto-reply = true
always-reject-url-rewrite = false
private-ip-answer = true
dns-direct-fallback-proxy = true
update-url = {update_url}

[Rule]
{rules}
GEOIP,LAN,DIRECT
FINAL,{final}

[Host]
localhost = 127.0.0.1
"""


# -------------------------------------------------------------------- main ---

def main():
    ap = argparse.ArgumentParser(
        description="geosite.dat/geoip.dat → Shadowrocket rule sets",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("specs", nargs="*",
                    help="geosite:NAME | geoip:NAME | OUT=geosite:A+geoip:B ... (атрибуты: @attr, @!attr)")
    ap.add_argument("--geosite", default=DEFAULT_GEOSITE, help="путь или URL geosite.dat")
    ap.add_argument("--geoip", default=DEFAULT_GEOIP, help="путь или URL geoip.dat")
    ap.add_argument("-o", "--out", default="shadowrocket", help="каталог вывода (по умолч. ./shadowrocket)")
    ap.add_argument("--cache", default=".geodat-cache", help="куда скачивать .dat")
    ap.add_argument("--list", choices=["geosite", "geoip"], help="вывести список категорий и выйти")
    ap.add_argument("--format", choices=["auto", "list", "domainset"], default="auto",
                    help="домены: .list (RULE-SET) или DOMAIN-SET; auto = DOMAIN-SET от 20k доменов")
    ap.add_argument("--allow-resolve", dest="no_resolve", action="store_false",
                    help="не добавлять no-resolve к IP-CIDR (по умолч. добавляется)")
    ap.add_argument("--no-optimize", action="store_true", help="не удалять дубли/покрытые домены и не схлопывать CIDR")
    ap.add_argument("--base-url", help="URL, по которому будут лежать файлы, — тогда генерируется shadowrocket.conf")
    ap.add_argument("--policy", action="append", default=[], metavar="OUT=POLICY",
                    help="политика для набора в .conf (по умолч. PROXY), напр. ads=REJECT")
    ap.add_argument("--final", default="DIRECT", help="политика FINAL в .conf (по умолч. DIRECT)")
    args = ap.parse_args()

    gs, gi = Dat(args.geosite, args.cache), Dat(args.geoip, args.cache)

    if args.list:
        d = gs if args.list == "geosite" else gi
        for n in sorted(d.idx):
            print(n)
        return
    if not args.specs:
        ap.error("укажите хотя бы одну категорию (или --list)")

    os.makedirs(args.out, exist_ok=True)
    policies = dict(p.split("=", 1) for p in args.policy)
    header = "generated by geodat2shadowrocket from runetfreedom/russia-v2ray-rules-dat"
    conf_rules, errors = [], 0

    for spec in args.specs:
        out, refs = parse_spec(spec)
        b = Bucket()
        for kind, name, flt in refs:
            dat = gs if kind == "geosite" else gi
            span = dat.idx.get(name)
            if span is None:
                print(f"✗ {kind}:{name} не найдена (см. --list {kind})", file=sys.stderr)
                errors += 1
                continue
            if kind == "geosite":
                b.add_site(parse_geosite(dat.buf, span), flt)
            else:
                nets, rev = parse_geoip(dat.buf, span)
                if rev:
                    print(f"! geoip:{name} имеет reverse_match — инверсия в Shadowrocket не переносится",
                          file=sys.stderr)
                b.nets.extend(nets)
        if not (b.full or b.suffix or b.keyword or b.nets):
            print(f"! {out}: пусто (проверьте имя категории и фильтр атрибутов) — пропущено",
                  file=sys.stderr)
            continue
        if not args.no_optimize:
            b.optimize()
        files, stats = write_outputs(out, b, args.out, args.format, args.no_resolve, header)
        print(f"✓ {out}: {stats}", file=sys.stderr)
        pol = policies.get(out, "PROXY")
        for rtype, path in files:
            if args.base_url:
                url = args.base_url.rstrip("/") + "/" + os.path.basename(path)
                conf_rules.append(f"{rtype},{url},{pol}")

    if args.base_url:
        conf = CONF_TEMPLATE.format(
            source=header, final=args.final, rules="\n".join(conf_rules),
            update_url=args.base_url.rstrip("/") + "/shadowrocket.conf")
        with open(os.path.join(args.out, "shadowrocket.conf"), "w") as f:
            f.write(conf)
        print(f"✓ shadowrocket.conf ({len(conf_rules)} правил)", file=sys.stderr)

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
