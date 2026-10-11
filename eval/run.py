#!/usr/bin/env python3
"""Precision/recall of piip on a synthetic, labeled corpus.

    python3 eval/run.py                      # builtin engine
    python3 eval/run.py -e hybrid            # needs a Presidio server
    python3 eval/run.py --dump /tmp/corpus   # also write the documents

The corpus is generated from templates with a fixed seed (no real personal
data; the fake API keys are why it is generated instead of committed).
Every value is labeled with its span, so a finding counts as:

  recall     a labeled value is hit by a finding of a compatible type
  precision  a finding overlaps some labeled value (any type)

Documents without personal data (order numbers, dates, prices, versions,
hashes, place names...) measure false positives.
"""

import argparse
import json
import os
import random
import string
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict

SEED = 20261011

# Gold type -> piip finding types that count as a correct detection.
COMPATIBLE = {
    "email": {"email", "contact"},
    "phone": {"phone", "contact"},
    "address": {"address", "contact", "location"},
    "postal": {"address", "contact"},
    "card": {"card", "contact"},
    "mynumber": {"ssn", "id_doc"},
    "ssn": {"ssn"},
    "ip": {"ip"},
    "secret": {"password", "token"},
    "bank": {"bank", "contact"},
    "dob": {"dob", "contact"},
    "name_labeled": {"contact", "name_text", "person"},
    "name_free": {"person", "name_text", "contact"},
    "name_csv": {"person", "name_text", "contact"},
    "id_doc": {"id_doc", "contact"},
}

JA_SURNAMES = "佐藤 鈴木 高橋 田中 伊藤 渡辺 山本 中村 小林 加藤 吉田 山田 佐々木 山口 松本 井上 木村 林 清水 森".split()
JA_GIVEN = "太郎 花子 翔太 美咲 健一 由美 大輔 彩 拓也 結衣 直樹 愛 誠 真由美 浩二 さくら 陽菜 蓮 悠真 葵".split()
KANA = {"佐藤": "サトウ", "鈴木": "スズキ", "高橋": "タカハシ", "田中": "タナカ", "伊藤": "イトウ",
        "渡辺": "ワタナベ", "山本": "ヤマモト", "中村": "ナカムラ", "小林": "コバヤシ", "加藤": "カトウ",
        "吉田": "ヨシダ", "山田": "ヤマダ", "佐々木": "ササキ", "山口": "ヤマグチ", "松本": "マツモト",
        "井上": "イノウエ", "木村": "キムラ", "林": "ハヤシ", "清水": "シミズ", "森": "モリ"}
EN_FIRST = "James Mary Robert Patricia John Jennifer Michael Linda David Elizabeth Emily Daniel Sarah Kevin Laura".split()
EN_LAST = "Smith Johnson Williams Brown Jones Garcia Miller Davis Wilson Anderson Taylor Thomas Moore Martin Clark".split()
PLACES = [
    ("東京都", ["新宿区西新宿", "渋谷区道玄坂", "港区六本木", "世田谷区三軒茶屋", "品川区大崎", "千代田区丸の内"]),
    ("大阪府", ["大阪市北区梅田", "大阪市中央区難波", "堺市堺区南瓦町", "豊中市新千里東町"]),
    ("神奈川県", ["横浜市中区山下町", "川崎市川崎区駅前本町", "藤沢市藤沢", "相模原市中央区相模原"]),
    ("愛知県", ["名古屋市中村区名駅", "豊田市小坂本町", "岡崎市康生通"]),
    ("福岡県", ["福岡市博多区博多駅前", "北九州市小倉北区浅野"]),
    ("北海道", ["札幌市中央区北一条西", "旭川市宮下通"]),
    ("京都府", ["京都市下京区烏丸通", "宇治市宇治"]),
    ("埼玉県", ["さいたま市大宮区桜木町", "川越市脇田町"]),
]
DOMAINS = ["example.com", "example.jp", "example.co.jp", "mail.example.net", "example.org"]


class Doc:
    """Text built piece by piece; labeled pieces remember their span."""

    def __init__(self, kind, lang):
        self.kind, self.lang = kind, lang
        self.parts, self.spans, self.len = [], [], 0

    def t(self, text):
        self.parts.append(text)
        self.len += len(text)
        return self

    def v(self, gold, text):
        self.spans.append({"start": self.len, "end": self.len + len(text), "type": gold, "value": text})
        return self.t(text)

    def text(self):
        return "".join(self.parts)


class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)

    def pick(self, xs):
        return self.r.choice(xs)

    def digits(self, n):
        return "".join(self.r.choice(string.digits) for _ in range(n))

    # Values -------------------------------------------------------------

    def ja_name(self, space=True):
        s, g = self.pick(JA_SURNAMES), self.pick(JA_GIVEN)
        return f"{s}{'　' if space and self.r.random() < 0.3 else (' ' if space else '')}{g}", s

    def en_name(self):
        return f"{self.pick(EN_FIRST)} {self.pick(EN_LAST)}"

    def email(self):
        local = self.pick(["", "", "info.", "k."]) + "".join(
            self.r.choice(string.ascii_lowercase) for _ in range(self.r.randint(4, 9))
        )
        if self.r.random() < 0.3:
            local += self.digits(self.r.randint(1, 4))
        return f"{local}@{self.pick(DOMAINS)}"

    def phone(self, lang="ja"):
        if lang == "en":
            return self.pick([f"(555) {self.digits(3)}-{self.digits(4)}", f"555-{self.digits(3)}-{self.digits(4)}",
                              f"+1 555 {self.digits(3)} {self.digits(4)}"])
        kind = self.r.random()
        if kind < 0.45:
            n = f"0{self.pick('789')}0", self.digits(4), self.digits(4)
        elif kind < 0.75:
            n = self.pick(["03", "06", "045", "052", "092", "011"]), None, self.digits(4)
            n = n[0], self.digits(4 if len(n[0]) == 2 else 3), n[2]
        elif kind < 0.85:
            n = self.pick(["0120", "0570", "0800"]), self.digits(3), self.digits(3)
        else:
            return f"+81-{self.pick('789')}0-{self.digits(4)}-{self.digits(4)}"
        sep = self.pick(["-", "-", "-", "", " "])
        return sep.join(n)

    def address(self):
        pref, cities = self.pick(PLACES)
        city = self.pick(cities)
        num = self.pick([f"{self.r.randint(1, 9)}-{self.r.randint(1, 30)}-{self.r.randint(1, 20)}",
                         f"{self.r.randint(1, 9)}丁目{self.r.randint(1, 30)}番{self.r.randint(1, 20)}号",
                         f"{self.r.randint(1, 999)}-{self.r.randint(1, 30)}"])
        bldg = self.pick(["", "", f" サンハイツ{self.r.randint(101, 905)}", f"　{self.pick(['グリーン', 'パーク', 'メゾン'])}{self.r.randint(1, 3)}0{self.r.randint(1, 9)}号室"])
        with_pref = self.r.random() < 0.8
        return (pref if with_pref else "") + city + num + bldg

    def postal(self):
        return f"{self.digits(3)}-{self.digits(4)}"

    def card(self):
        kind = self.pick(["visa", "master", "amex"])
        if kind == "amex":
            body = self.pick(["34", "37"]) + self.digits(12)
        else:
            body = ("4" if kind == "visa" else self.pick(["51", "52", "53", "54", "55"])) + self.digits(14 if kind == "visa" else 13)
        num = body + str(luhn_check_digit(body))
        sep = self.pick(["-", " ", ""])
        if kind == "amex":
            return sep.join([num[:4], num[4:10], num[10:]])
        return sep.join(num[i:i + 4] for i in range(0, 16, 4))

    def mynumber(self):
        body = self.digits(11)
        num = body + str(mynumber_check_digit(body))
        sep = self.pick([" ", "-", ""])
        return sep.join([num[:4], num[4:8], num[8:]])

    def ssn(self):
        return f"{self.r.randint(100, 665)}-{self.r.randint(10, 99)}-{self.digits(4)}"

    def ip(self):
        return self.pick([f"192.0.2.{self.r.randint(1, 254)}", f"198.51.100.{self.r.randint(1, 254)}",
                          f"203.0.113.{self.r.randint(1, 254)}", f"10.{self.r.randint(0, 255)}.{self.r.randint(0, 255)}.{self.r.randint(1, 254)}",
                          f"2001:db8:{self.r.randint(1, 0xffff):x}::{self.r.randint(1, 0xffff):x}"])

    def password(self):
        return "".join(self.r.choice(string.ascii_letters + string.digits + "!#%") for _ in range(self.r.randint(8, 16)))

    def alnum(self, n, chars=string.ascii_letters + string.digits):
        return "".join(self.r.choice(chars) for _ in range(n))

    def secret(self):
        kind = self.r.randint(0, 6)
        if kind == 0:
            return "ghp_" + self.alnum(36)
        if kind == 1:
            return "sk-ant-api03-" + self.alnum(93, string.ascii_letters + string.digits + "_-") + "AA"
        if kind == 2:
            return "AKIA" + self.alnum(16, string.ascii_uppercase + string.digits)
        if kind == 3:
            return "xoxb-" + self.digits(12) + "-" + self.digits(13) + "-" + self.alnum(24)
        if kind == 4:
            return "sk_live_" + self.alnum(24)
        if kind == 5:
            return "AIza" + self.alnum(35, string.ascii_letters + string.digits + "_-")
        return "sk-proj-" + self.alnum(48)

    def bank(self):
        return self.digits(7)

    def dob(self, lang="ja"):
        y, m, d = self.r.randint(1950, 2005), self.r.randint(1, 12), self.r.randint(1, 28)
        if lang == "en":
            return self.pick([f"{y}-{m:02d}-{d:02d}", f"{m:02d}/{d:02d}/{y}"])
        return self.pick([f"{y}年{m}月{d}日", f"{y}/{m:02d}/{d:02d}", f"{y}-{m:02d}-{d:02d}"])

    # Documents ----------------------------------------------------------

    def ja_inquiry(self):
        d = Doc("inquiry", "ja")
        name, sur = self.ja_name()
        sep = self.pick(["：", ": ", "　", "\t"])
        d.t(f"お名前{sep}").v("name_labeled", name).t("\n")
        if self.r.random() < 0.6:
            d.t(f"フリガナ{sep}").v("name_labeled", KANA[sur] + " " + "タロウ").t("\n")
        d.t(f"メールアドレス{sep}").v("email", self.email()).t("\n")
        d.t(f"{self.pick(['電話番号', 'お電話番号', 'TEL', '携帯電話'])}{sep}").v("phone", self.phone()).t("\n")
        if self.r.random() < 0.7:
            d.t(f"郵便番号{sep}").v("postal", "〒" + self.postal() if self.r.random() < 0.5 else self.postal()).t("\n")
            d.t(f"ご住所{sep}").v("address", self.address()).t("\n")
        if self.r.random() < 0.3:
            d.t(f"生年月日{sep}").v("dob", self.dob()).t("\n")
        d.t("お問い合わせ内容：\n")
        d.t(self.pick([
            "先日注文した商品（注文番号 ORD-2026-0%s）がまだ届いていません。確認をお願いします。\n" % self.digits(5),
            "会員登録したのですが、ログインできません。パスワードの再設定方法を教えてください。\n",
            "請求書の宛名を会社名に変更したいです。対応可能でしょうか。\n",
            "返品について質問です。サイズが合わなかったため交換を希望します。\n",
        ]))
        if self.r.random() < 0.3:
            d.t("折り返しは ").v("phone", self.phone()).t(" までお願いします。\n")
        return d

    def en_ticket(self):
        d = Doc("ticket", "en")
        d.t("Name: ").v("name_labeled", self.en_name()).t("\n")
        d.t("Email: ").v("email", self.email()).t("\n")
        d.t(self.pick(["Phone: ", "Tel: ", "Mobile: "])).v("phone", self.phone("en")).t("\n")
        if self.r.random() < 0.3:
            d.t("SSN: ").v("ssn", self.ssn()).t("\n")
        if self.r.random() < 0.3:
            d.t("Date of birth: ").v("dob", self.dob("en")).t("\n")
        d.t("Message: ")
        d.t(self.pick([
            "I was charged twice for order #%s. Please refund the duplicate payment.\n" % self.digits(6),
            "The app crashes on startup since version 4.2.1. Steps attached.\n",
            "Please update my shipping address before the package ships.\n",
        ]))
        if self.r.random() < 0.4:
            d.t("My colleague ").v("name_free", self.en_name()).t(" can confirm this.\n")
        return d

    def access_log(self):
        d = Doc("access_log", "en")
        for _ in range(self.r.randint(3, 8)):
            d.v("ip", self.ip()).t(f' - - [10/Oct/2026:{self.r.randint(0, 23):02d}:{self.r.randint(0, 59):02d}:{self.r.randint(0, 59):02d} +0900] "')
            if self.r.random() < 0.3:
                d.t("GET /account?email=").v("email", self.email()).t(" HTTP/1.1")
            else:
                d.t(self.pick(["GET /products/12345 HTTP/1.1", "POST /api/v1/cart HTTP/1.1", "GET /static/app.v3.2.1.js HTTP/1.1"]))
            d.t(f'" {self.pick(["200", "200", "302", "404"])} {self.r.randint(200, 90000)} "-" "Mozilla/5.0"\n')
        return d

    def app_log(self):
        d = Doc("app_log", "en")
        for _ in range(self.r.randint(3, 7)):
            ts = f"2026-10-{self.r.randint(1, 30):02d}T{self.r.randint(0, 23):02d}:{self.r.randint(0, 59):02d}:{self.r.randint(0, 59):02d}Z"
            k = self.r.random()
            if k < 0.25:
                d.t(f'{{"ts":"{ts}","level":"info","msg":"login","user":"').v("email", self.email()).t('","ip":"').v("ip", self.ip()).t('"}\n')
            elif k < 0.4:
                d.t(f'{{"ts":"{ts}","level":"error","msg":"payment failed","card":"').v("card", self.card()).t('"}\n')
            elif k < 0.5:
                d.t(f"{ts} DEBUG auth header Authorization: Bearer ").v("secret", self.alnum(40)).t("\n")
            else:
                d.t(f'{{"ts":"{ts}","level":"info","msg":"{self.pick(["cache hit", "job done", "request ok"])}","duration_ms":{self.r.randint(1, 900)},"request_id":"{self.alnum(8, "0123456789abcdef")}-{self.alnum(4, "0123456789abcdef")}"}}\n')
        return d

    def csv(self):
        d = Doc("csv", "ja")
        d.t("顧客ID,氏名,メール,電話,住所,登録日\n")
        for _ in range(self.r.randint(3, 8)):
            d.t(f"C{self.digits(6)},").v("name_csv", self.ja_name(space=False)[0]).t(",").v("email", self.email()).t(",")
            d.v("phone", self.phone()).t(",").v("address", self.address()).t(f",2026/{self.r.randint(1, 9):02d}/{self.r.randint(1, 28):02d}\n")
        return d

    def ja_mail(self):
        d = Doc("email", "ja")
        name, _ = self.ja_name(space=False)
        d.t(f"{self.pick(['株式会社サンプル', 'サンプル商事'])}\n").v("name_free", name).t(" 様\n\n")
        d.t("いつもお世話になっております。\n")
        d.t(self.pick(["先日の打ち合わせの件でご連絡いたしました。\n", "お見積りをお送りいたします。\n"]))
        if self.r.random() < 0.5:
            other, _ = self.ja_name(space=False)
            d.t("担当の").v("name_free", other).t("より改めてご連絡いたします。\n")
        d.t("\n--\n")
        signer, _ = self.ja_name()
        d.v("name_free", signer).t("\n")
        d.t("TEL ").v("phone", self.phone()).t("\n")
        d.t("Mail ").v("email", self.email()).t("\n")
        if self.r.random() < 0.5:
            d.t("〒").v("postal", self.postal()).t(" ").v("address", self.address()).t("\n")
        return d

    def chat(self):
        d = Doc("chat", "ja")
        a, _ = self.ja_name(space=False)
        b, _ = self.ja_name(space=False)
        d.t("[10:02] ").v("name_free", a).t("：明日の訪問、").v("name_free", b).t("さんも同行できますか？\n")
        d.t(self.pick(["[10:05] 了解です。現地集合で。\n", "[10:05] 大丈夫です。資料は共有フォルダに入れました。\n"]))
        if self.r.random() < 0.5:
            d.t("[10:07] 先方の連絡先は ").v("phone", self.phone()).t(" です。\n")
        if self.r.random() < 0.4:
            d.t("[10:09] 私は").v("name_free", self.ja_name(space=False)[0]).t("と申します。よろしくお願いします。\n")
        return d

    def env_file(self):
        d = Doc("env", "en")
        d.t("APP_ENV=production\nAPP_DEBUG=false\nDB_HOST=").v("ip", self.ip()).t("\nDB_USER=app\n")
        d.t("DB_PASSWORD=").v("secret", self.password()).t("\n")
        d.t(self.pick(["GITHUB_TOKEN=", "ANTHROPIC_API_KEY=", "AWS_ACCESS_KEY_ID=", "SLACK_BOT_TOKEN=", "STRIPE_SECRET_KEY=", "GOOGLE_API_KEY=", "OPENAI_API_KEY="]))
        d.v("secret", self.secret()).t("\nCACHE_TTL=3600\nLOG_LEVEL=info\n")
        return d

    def payment_form(self):
        d = Doc("payment", "ja")
        d.t("カード番号：").v("card", self.card()).t("\n")
        d.t("有効期限：").v("card", f"{self.r.randint(1, 12):02d}/{self.r.randint(27, 31)}").t("\n")
        d.t("振込先：○○銀行 本店 普通 ").v("bank", self.bank()).t("\n")
        if self.r.random() < 0.5:
            d.t("マイナンバー：").v("mynumber", self.mynumber()).t("\n")
        if self.r.random() < 0.4:
            d.t("運転免許証番号：").v("id_doc", self.digits(12)).t("\n")
        return d

    def secrets_in_text(self):
        d = Doc("secret_text", "en")
        d.t(self.pick(["Here is the key you asked for: ", "Use this token for the deploy: ", "鍵はこれです："]))
        d.v("secret", self.secret()).t("\n")
        d.t(self.pick(["Rotate it after the release.\n", "Don't share it.\n", "リリース後に失効させます。\n"]))
        return d

    def negative(self):
        d = Doc("negative", self.pick(["ja", "en"]))
        lines = [
            f"注文番号：ORD-2026-{self.digits(6)}　合計 ¥{self.r.randint(1, 99)},{self.digits(3)}（税込）",
            f"配送予定日：2026年{self.r.randint(1, 12)}月{self.r.randint(1, 28)}日 {self.r.randint(9, 20)}:00〜{self.r.randint(10, 21)}:00",
            f"お問い合わせ番号 {self.digits(4)}-{self.digits(4)}-{self.digits(4)}",
            f"JAN {self.pick(['45', '49'])}{self.digits(11)}　商品コード SKU-{self.digits(5)}",
            f"version {self.r.randint(1, 9)}.{self.r.randint(0, 20)}.{self.r.randint(0, 99)} build {self.digits(8)}",
            f"commit {self.alnum(40, '0123456789abcdef')}",
            f"uuid {self.alnum(8, '0123456789abcdef')}-{self.alnum(4, '0123456789abcdef')}-4{self.alnum(3, '0123456789abcdef')}-a{self.alnum(3, '0123456789abcdef')}-{self.alnum(12, '0123456789abcdef')}",
            f"東京都と大阪府の店舗で{self.r.randint(10, 90)}%オフのセールを開催します。",
            f"先週、{self.pick(['京都', '札幌', '福岡', '横浜'])}に出張しました。",
            f"ISBN978-4-{self.digits(2)}-{self.digits(6)}-{self.r.randint(0, 9)}",
            f"Invoice INV-{self.digits(8)} due {self.r.randint(1, 12)}/{self.r.randint(1, 28)}/2026, amount ${self.r.randint(10, 999)}.{self.digits(2)}",
            f"Elapsed: {self.r.randint(100, 99999)} ms, rows: {self.r.randint(1, 1000000)}, epoch {self.r.randint(1700000000, 1800000000)}",
            f"会議室A（定員{self.r.randint(4, 20)}名）を{self.r.randint(13, 17)}時から予約しました。",
            f"在庫数 {self.r.randint(0, 9999)} 個、入荷予定 {self.r.randint(1, 12)}/{self.r.randint(1, 28)}",
            f"Tracking number: {self.digits(12)}",
            f"sha256: {self.alnum(64, '0123456789abcdef')}",
            f"https://www.example.com/products/{self.digits(6)}?ref=top&page={self.r.randint(1, 9)}",
        ]
        self.r.shuffle(lines)
        for line in lines[: self.r.randint(4, 8)]:
            d.t(line + "\n")
        return d


def luhn_check_digit(body):
    total = 0
    for i, ch in enumerate(reversed(body)):
        n = int(ch)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (10 - total % 10) % 10


def mynumber_check_digit(body):
    # 11 digits P11..P1 (left to right), weights Qn = n+1 (n<=6) or n-5.
    total = 0
    for n in range(1, 12):
        p = int(body[11 - n])
        q = n + 1 if n <= 6 else n - 5
        total += p * q
    r = total % 11
    return 0 if r <= 1 else 11 - r


MIX = [
    ("ja_inquiry", 120), ("en_ticket", 60), ("access_log", 60), ("app_log", 60), ("csv", 40),
    ("ja_mail", 60), ("chat", 60), ("env_file", 40), ("payment_form", 50), ("secrets_in_text", 40),
    ("negative", 150),
]


def corpus(seed=SEED):
    g = Gen(seed)
    docs = []
    for kind, n in MIX:
        for _ in range(n):
            docs.append(getattr(g, kind)())
    return docs


def run_piip(binary, engine, docs, extra):
    with tempfile.TemporaryDirectory() as tmp:
        for i, d in enumerate(docs):
            with open(os.path.join(tmp, f"{i:05d}.txt"), "w") as f:
                f.write(d.text())
        cmd = [binary, "-e", engine, *extra, "scan", tmp, "-f", "json", "--no-ignore"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode not in (0, 1):
            sys.exit(f"piip failed: {res.stderr}")
        found = defaultdict(list)
        for f in json.loads(res.stdout)["findings"]:
            found[int(os.path.basename(f["path"]).split(".")[0])].append(f)
        return found


def evaluate(docs, found):
    gold_total, gold_hit = Counter(), Counter()
    misses = defaultdict(list)
    pred_total, pred_tp = Counter(), Counter()
    fps = defaultdict(list)
    neg_chars = 0
    neg_fp = 0
    for i, d in enumerate(docs):
        findings = found.get(i, [])
        for s in d.spans:
            gold_total[s["type"]] += 1
            ok = any(f["start"] < s["end"] and s["start"] < f["end"] and f["type"] in COMPATIBLE[s["type"]] for f in findings)
            if ok:
                gold_hit[s["type"]] += 1
            else:
                misses[s["type"]].append(s["value"])
        for f in findings:
            pred_total[f["type"]] += 1
            if any(f["start"] < s["end"] and s["start"] < f["end"] for s in d.spans):
                pred_tp[f["type"]] += 1
            else:
                fps[f["type"]].append(f["rule"])
        if d.kind == "negative":
            neg_chars += len(d.text())
            neg_fp += len(findings)
    return gold_total, gold_hit, misses, pred_total, pred_tp, fps, neg_chars, neg_fp


def pct(a, b):
    return "-" if b == 0 else f"{100 * a / b:.1f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-e", "--engine", default="builtin")
    ap.add_argument("--bin", default=os.environ.get("PIIP_BIN", "target/release/piip"))
    ap.add_argument("--dump", help="write the documents and labels to this directory")
    ap.add_argument("--misses", type=int, default=0, help="show up to N missed values per type")
    ap.add_argument("piip_args", nargs="*", help="extra global piip options, after --")
    args = ap.parse_args()

    docs = corpus()
    if args.dump:
        os.makedirs(args.dump, exist_ok=True)
        with open(os.path.join(args.dump, "labels.jsonl"), "w") as out:
            for i, d in enumerate(docs):
                with open(os.path.join(args.dump, f"{i:05d}.txt"), "w") as f:
                    f.write(d.text())
                out.write(json.dumps({"id": i, "kind": d.kind, "lang": d.lang, "spans": d.spans}, ensure_ascii=False) + "\n")

    found = run_piip(args.bin, args.engine, docs, args.piip_args)
    gold_total, gold_hit, misses, pred_total, pred_tp, fps, neg_chars, neg_fp = evaluate(docs, found)

    chars = sum(len(d.text()) for d in docs)
    print(f"engine: {args.engine}   documents: {len(docs)}   characters: {chars}   labeled values: {sum(gold_total.values())}\n")
    print("| 正解の種別 | 件数 | 検出 | 再現率 |")
    print("|---|---:|---:|---:|")
    for t in sorted(gold_total, key=lambda t: -gold_total[t]):
        print(f"| {t} | {gold_total[t]} | {gold_hit[t]} | {pct(gold_hit[t], gold_total[t])} |")
    print(f"| **合計** | {sum(gold_total.values())} | {sum(gold_hit.values())} | {pct(sum(gold_hit.values()), sum(gold_total.values()))} |")
    print("\n| 検出の種別 | 件数 | 正しい | 適合率 |")
    print("|---|---:|---:|---:|")
    for t in sorted(pred_total, key=lambda t: -pred_total[t]):
        print(f"| {t} | {pred_total[t]} | {pred_tp[t]} | {pct(pred_tp[t], pred_total[t])} |")
    print(f"| **合計** | {sum(pred_total.values())} | {sum(pred_tp.values())} | {pct(sum(pred_tp.values()), sum(pred_total.values()))} |")
    print(f"\n個人情報を含まない文書: {neg_chars} 文字で誤検出 {neg_fp} 件")
    if args.misses:
        print("\n取りこぼし（種別ごと）:")
        for t, vals in sorted(misses.items()):
            print(f"  {t}: {vals[: args.misses]}")
        print("誤検出（ルール別）:")
        for t, rules in sorted(fps.items()):
            print(f"  {t}: {Counter(rules).most_common(5)}")


if __name__ == "__main__":
    main()
