#!/usr/bin/env python3
"""
subsift — sift signal from subdomain-recon noise.

Pipe in a list of subdomains (or httpx JSON lines) and get back a de-noised,
tagged, priority-scored view: which hosts are non-prod, admin, auth, API, infra,
or subdomain-takeover-shaped — and which are just ephemeral CI/wildcard junk.

Pure stdlib, no dependencies. Read from a file or stdin.

    subfinder -d target.com -silent | subsift --interesting
    subsift subs.txt --stats
    cat subs.txt | subsift --json > tagged.jsonl

MIT licensed.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict

__version__ = "0.1.0"

# --- noise: patterns that are almost never worth a human's attention ---------
NOISE_RULES = [
    # ephemeral preview / per-PR / per-branch deploys
    ("ephemeral-preview", re.compile(r"(^|[.-])(pr-?\d+|preview|uncover|deploy-preview|review-app)([.-]|$)", re.I)),
    # random hex / uuid-ish leading label (build hashes, ephemeral envs)
    ("hash-label", re.compile(r"^[a-f0-9]{10,}\.")),
    ("uuid-label", re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-")),
    # wildcard-DNS pollution: an embedded second domain inside a label
    ("embedded-domain", re.compile(r"[a-z0-9-]+\.(com|net|org|io)[a-z0-9-]", re.I)),
]
# collapse (keep a few, count the rest) rather than hard-drop
COLLAPSE_RE = re.compile(r"^\d+\.(partner|m|shop|store|customer|client|user)\.", re.I)
DEEP_NEST = 6  # more labels than this is usually a wildcard/fuzz artifact

# --- environment detection ---------------------------------------------------
ENV_TOKENS = {
    "prod": ["prod", "production", "prd", "live", "www"],
    "dev": ["dev", "develop", "development"],
    "test": ["test", "tst", "testing"],
    "staging": ["staging", "stg", "stage", "stag"],
    "uat": ["uat"],
    "qa": ["qa"],
    "sandbox": ["sandbox", "sbx", "sand"],
    "preprod": ["preprod", "pre-prod", "ppt", "pet", "sit", "hml", "homolog", "nonprod"],
    "rc": ["rc", "canary", "beta", "alpha"],
    "internal": ["int", "internal", "intranet", "corp", "local"],
    "demo": ["demo"],
}
# for scoring: non-prod is more interesting to a researcher than prod
NONPROD = {"dev", "test", "staging", "uat", "qa", "sandbox", "preprod", "rc", "internal", "demo"}

# Common public suffixes (not a full PSL — enough to strip the apex so ccTLD
# labels like ".mx" aren't misread as tokens). Longest match wins.
SUFFIXES = {
    "com.br", "com.mx", "com.co", "com.au", "com.ar", "com.tr", "com.sg", "com.hk",
    "com.my", "com.ph", "com.cn", "com.pe", "com.ec", "com.uy", "com.ve", "co.uk",
    "co.il", "co.nz", "co.za", "co.jp", "co.kr", "co.in", "co.id", "co.th", "org.uk",
    "net.au", "gov.uk", "ac.uk", "gov.br", "edu.au",
    "com.tw", "com.vn", "com.ua", "com.ng", "com.eg", "com.sa", "com.pk",
    "ne.jp", "or.jp",
    "com", "net", "org", "io", "dev", "app", "co", "de", "nl", "pl", "es", "ch", "il",
    "mx", "br", "uk", "eu", "us", "ca", "fr", "it", "se", "no", "fi", "dk", "info", "ai",
    "cloud", "xyz", "tech", "sh", "gg", "me", "tv", "id",
}


def subdomain_labels(labels: list) -> list:
    """Return only the sub-domain labels, stripping the registrable domain
    (apex = public-suffix + one org label) so ccTLDs aren't tokenized."""
    n = len(labels)
    # try longest suffix (up to 3 labels) then shorter
    for k in (3, 2, 1):
        if n > k and ".".join(labels[-k:]) in SUFFIXES:
            return labels[:-(k + 1)]  # drop suffix + org label
    return labels[:-2] if n > 2 else []

# --- category detection (label token -> category) ----------------------------
CATEGORIES = {
    "admin": ["admin", "adm", "backoffice", "bo", "console", "manage", "manager", "cpanel"],
    "auth": ["auth", "sso", "login", "signin", "oauth", "oidc", "idp", "keycloak", "adfs",
             "okta", "saml", "iam", "account", "accounts"],
    "api": ["api", "apis", "graphql", "gql", "rest", "gateway", "gw", "apigee", "kong",
            "apigw", "ws", "websocket", "grpc", "rpc"],
    "cicd": ["jenkins", "gitlab", "git", "gitea", "ci", "cd", "argo", "argocd", "drone",
             "bamboo", "teamcity", "bitbucket", "nexus", "artifactory", "registry", "harbor"],
    "monitoring": ["grafana", "kibana", "prometheus", "jaeger", "sentry", "elastic", "elk",
                   "splunk", "zabbix", "nagios", "metrics", "status", "health", "monitor"],
    "infra": ["vpn", "bastion", "jump", "jumpbox", "ssh", "rdp", "vault", "consul", "k8s",
              "kube", "kubernetes", "rancher", "portainer", "docker", "nomad"],
    "data": ["db", "sql", "mysql", "postgres", "pg", "mongo", "redis", "kafka", "backup",
             "dump", "phpmyadmin", "adminer", "pma"],
    "payment": ["pay", "payment", "payments", "checkout", "billing", "invoice", "pci",
                "wallet", "card", "psp"],
    "storage": ["cdn", "static", "assets", "asset", "img", "image", "images", "media",
                "fonts", "cache", "files", "upload", "uploads", "s3"],
    "mail": ["mail", "smtp", "imap", "pop", "mx", "webmail", "exchange", "owa"],
}
# per-category interest weight (bug-bounty lens)
CAT_WEIGHT = {
    "admin": 4, "auth": 4, "payment": 4, "infra": 4, "cicd": 4, "data": 4,
    "api": 3, "monitoring": 3, "mail": 1, "storage": -2,
}


@dataclass
class Host:
    name: str
    labels: list = field(default_factory=list)
    env: str = "prod"
    categories: list = field(default_factory=list)
    score: int = 0
    noise: str = ""          # non-empty = reason it's noise
    takeover_hint: bool = False

    def to_row(self) -> str:
        tags = []
        if self.env != "prod":
            tags.append(self.env)
        tags += self.categories
        if self.takeover_hint:
            tags.append("takeover?")
        return f"{self.score:>3}  {self.name}\t[{', '.join(tags) if tags else '-'}]"


def classify(name: str) -> Host:
    name = name.strip().lower().rstrip(".")
    labels = name.split(".")
    h = Host(name=name, labels=labels)

    # noise checks
    for reason, rx in NOISE_RULES:
        if rx.search(name):
            h.noise = reason
            return h
    if len(labels) > DEEP_NEST:
        h.noise = "deep-nesting"
        return h
    if COLLAPSE_RE.match(name):
        h.noise = "numbered-whitelabel"
        # not returned as pure noise; caller may collapse. Still classify below.

    toks = set()
    for lab in subdomain_labels(labels):
        toks.update(re.split(r"[-_]", lab))

    # environment (first match wins by priority order)
    for env, keys in ENV_TOKENS.items():
        if env == "prod":
            continue
        if toks & set(keys):
            h.env = env
            break

    # categories
    for cat, keys in CATEGORIES.items():
        if toks & set(keys):
            h.categories.append(cat)

    # score
    s = 0
    for cat in h.categories:
        s += CAT_WEIGHT.get(cat, 0)
    if h.env in NONPROD:
        s += 2
    if h.env == "internal":
        s += 1
    # a lone storage/cdn with nothing else is boring
    if h.categories == ["storage"] and h.env == "prod":
        s -= 1
    h.score = s
    return h


def load_hosts(fp, as_httpx: bool):
    for line in fp:
        line = line.strip()
        if not line:
            continue
        if as_httpx:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("input") or obj.get("host") or ""
            name = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
            if name:
                yield name
        else:
            # tolerate "host [tags]" or URLs
            name = re.sub(r"^https?://", "", line).split("/")[0].split(":")[0]
            name = name.split()[0] if name else name
            if name:
                yield name


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="subsift",
        description="Sift signal from subdomain-recon noise: de-noise, tag, and score subdomains.")
    ap.add_argument("file", nargs="?", help="input file (default: stdin)")
    ap.add_argument("--httpx", action="store_true", help="input is httpx JSON lines")
    ap.add_argument("--json", action="store_true", help="emit JSON lines with tags/score")
    ap.add_argument("--interesting", action="store_true",
                    help="only hosts with score >= --min-score, sorted high→low")
    ap.add_argument("--min-score", type=int, default=2, help="threshold for --interesting (default 2)")
    ap.add_argument("--keep-noise", action="store_true", help="do not drop noise hosts")
    ap.add_argument("--collapse", type=int, default=2, metavar="N",
                    help="keep at most N numbered white-label hosts per parent (default 2)")
    ap.add_argument("--stats", action="store_true", help="print a summary breakdown to stderr")
    ap.add_argument("--version", action="version", version=f"subsift {__version__}")
    args = ap.parse_args(argv)

    fp = open(args.file) if args.file else sys.stdin
    seen_collapse = Counter()
    hosts, dropped = [], Counter()

    for name in load_hosts(fp, args.httpx):
        h = classify(name)
        if h.noise and h.noise != "numbered-whitelabel" and not args.keep_noise:
            dropped[h.noise] += 1
            continue
        if h.noise == "numbered-whitelabel":
            parent = h.name.split(".", 1)[1]
            seen_collapse[parent] += 1
            if seen_collapse[parent] > args.collapse and not args.keep_noise:
                dropped["numbered-whitelabel"] += 1
                continue
        hosts.append(h)
    if args.file:
        fp.close()

    if args.interesting:
        hosts = [h for h in hosts if h.score >= args.min_score]
        hosts.sort(key=lambda h: (-h.score, h.name))

    for h in hosts:
        if args.json:
            print(json.dumps(asdict(h), separators=(",", ":")))
        else:
            print(h.to_row())

    if args.stats:
        env_c, cat_c = Counter(), Counter()
        for h in hosts:
            env_c[h.env] += 1
            for c in h.categories:
                cat_c[c] += 1
        print(f"\n[subsift] kept {len(hosts)} hosts; dropped {sum(dropped.values())} noise "
              f"({dict(dropped)})", file=sys.stderr)
        print(f"[subsift] envs: {dict(env_c)}", file=sys.stderr)
        print(f"[subsift] categories: {dict(cat_c.most_common())}", file=sys.stderr)


if __name__ == "__main__":
    main()
