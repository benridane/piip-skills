# piip リファレンス

## PII 種別（builtin）

| 種別 | 内容 | 例 |
|---|---|---|
| `email` | メールアドレス | `taro@example.jp` → `t***@example.jp` |
| `phone` | 電話番号（携帯・固定・0120/0570・括弧書き・国際・米国） | `090-1234-5678` → `***-***-5678` |
| `address` | 都道府県＋市区町村＋番地、政令市・23 区から始まる住所、〒付き郵便番号 | `東京都新宿区西新宿2-8-1` → `東京都***` |
| `card` | クレジットカード番号（Luhn 検証） | → `****-****-****-9014` |
| `ssn` | 米国 SSN / マイナンバー（検査数字） | → `***-**-6789` / `****-****-9018` |
| `password` | ラベル付きパスワード、`DB_PASSWORD=…` | → `[REDACTED]` |
| `token` | 各種 API キー、GitHub/Slack/AWS/Stripe などの秘密情報、秘密鍵ブロック、Basic/Bearer 認証 | `ghp_…6789` → `ghp_****…6789` |
| `hosting` | ホスティングのアカウント/サーバー ID（Xserver、さくら、ConoHa、ロリポップ、mixhost、Azure GUID） | `xs123456` → `xs***456` |
| `ip` | IPv4 / IPv6 | `192.168.1.10` → `192.***.***.10` |
| `dob` | ラベル付き生年月日 | `生年月日: 1990-01-15` → `****-**-**` |
| `bank` | ラベル付き口座番号 | `口座番号: 1234567` → `***4567` |
| `contact` | 問い合わせ形式のラベル付き項目（氏名・フリガナ・住所・電話・会員ID・有効期限・CVV） | `お名前：山田 太郎` → `お名前：山* 太*` |
| `id_doc` | 旅券・運転免許証・保険証・基礎年金番号・在留カード（ラベル付き） | → `*********` |
| `name_text` | 自己紹介の名前（既定で無効） | `山田太郎と申します` → `山***と申します` |
| `custom` | 設定ファイルの独自パターン | |

## Presidio エンティティ → 種別

`EMAIL_ADDRESS`→email、`PHONE_NUMBER`→phone、`CREDIT_CARD`→card、`IP_ADDRESS`→ip、`US_SSN`→ssn、
`IBAN_CODE`/`US_BANK_NUMBER`→bank、`US_PASSPORT`/`US_DRIVER_LICENSE`/`UK_NHS`/`MEDICAL_LICENSE`→id_doc、
`CRYPTO`→token、`PERSON`→person、`LOCATION`→location、その他→小文字のエンティティ名。
`person` は既定で有効、`location` は既定で無効（`--enable location`）。`--disable person` のように種別で切り替えられる。
既定で除外: `DATE_TIME`, `NRP`, `URL`, `ORGANIZATION`, `IN_PAN`（誤検出が多いため）。

## 設定ファイル（.piip.toml）

```toml
# 種別ごとの有効/無効（省略時: name_text と location 以外はすべて有効）
[types]
name_text = true
hosting = false

# 同意フレーズ。省略すると既定の 4 つ、[] にすると無効
consent_phrases = ["マスクを外すことに同意"]

# 独自パターン（PCRE、Unicode モード。区切り文字は付けない）
[[custom_patterns]]
label = "社員番号"
pattern = 'EMP-\d{6}'
replacement = "EMP-******"   # < > " ' ` は取り除かれる

[presidio]
engine = "builtin"            # builtin | presidio | hybrid（-e で上書き）
url = "http://127.0.0.1:5002" # 環境変数 PIIP_PRESIDIO_URL でも可
language = "auto"             # auto | en | ja | "en,ja"
threshold = 0.5
entities = []                 # 空 = すべて（exclude_entities を除く）
exclude_entities = ["DATE_TIME", "NRP", "URL", "ORGANIZATION", "IN_PAN"]
timeout_secs = 60

[hook]                        # Claude Code フック（piip hook）
enabled = true
engine = "builtin"            # hybrid なら人名も（Presidio に接続できなければ builtin）
include = ["*.log", "*.csv", "*.json", ".env", "data/**"]   # 省略時は既定の一覧
exclude = ["package.json", "**/node_modules/**"]
all_files = false             # true: ソースコードも含め全ファイル
grep = true                   # Grep の一致行もマスク
bash = true                   # 対象ファイル名を含む Bash コマンドの出力もマスク
```

環境変数: `PIIP_ENGINE`、`PIIP_PRESIDIO_URL`。

## Presidio サーバー

`scripts/presidio-start.sh` は uv で Python 環境を作り、英語（en_core_web_md）と日本語（ja_core_news_md）の
spaCy モデルを載せた Presidio Analyzer を `127.0.0.1:5002` で起動する。

- `PIIP_PRESIDIO_PORT` でポート変更、`PIIP_PRESIDIO_LANGS=en` で英語のみ
- 停止: `bash scripts/presidio-start.sh stop`
- ログ: `~/.cache/piip/presidio.log`
- 公式コンテナ（英語のみ）でも動く: `docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer`

## 終了コード

0 = 成功、1 = `scan --fail` で検出あり、2 = エラー（Presidio に接続できない、設定ファイルの誤りなど）。

## 制限事項

- HTML はタグ構造を考えず平文として処理する
- 画像の位置情報（EXIF/GPS）は扱わない
