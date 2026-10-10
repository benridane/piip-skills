---
name: piip
description: ローカルで個人情報（PII）と秘密情報を検出・マスクする CLI piip（Rust 製、Presidio エンジン選択可）。ファイル・ログ・問い合わせ文・JSON・ディレクトリを外部に送らずに匿名化/スキャンするときに使う。Triggers: mask/redact/anonymize PII, 個人情報 マスク, 匿名化, 伏せ字, PII スキャン, 秘密情報 検出, API キー 漏洩チェック, ログのサニタイズ, GDPR, マイナンバー, 電話番号/住所/メールを隠す, Presidio.
---

# PIIP — ローカル PII マスキング

個人情報と秘密情報を検出・マスクする Rust 製の CLI `piip`。
処理はすべてこのマシン上で行われ、外部 API は呼ばない。

実行ファイル: `piip`（PATH 上）。見つからなければ、このスキルのベースディレクトリの `bin/piip`。

## 最重要ルール: 生データを先に読まない

PII を含む可能性があるファイルをユーザーが渡したら、**Read や cat で中身を開く前に** `piip` を通し、
マスク済みの出力だけを読むこと。生の値がコンテキストに入った時点でマスクの意味がなくなる。

- 中身を理解したい → `piip mask FILE` の出力を読む
- どんな PII があるか知りたい → `piip scan FILE`（既定で生の値は出さない）
- `--show-values` は生の値を表示する。ユーザーが明示的に求めたときだけ使う

## よく使うコマンド

```bash
piip mask input.txt                  # マスク結果を標準出力へ
piip mask input.txt -o masked.txt    # ファイルへ書き出し
piip mask -i a.log b.log             # 上書き（元に戻せない。実行前にユーザーへ確認）
cat x.txt | piip mask                # 標準入力
piip mask --json input.txt           # {masked, changed, detected_types, consent_bypassed}

piip scan .                          # ディレクトリを再帰スキャン（.gitignore を尊重、ドライラン）
piip scan src/ -f json               # 機械可読（-f jsonl / summary も可）
piip scan . --fail                   # 検出があれば終了コード 1（CI・フック向け）

piip mask-json data.json --pretty    # JSON: キー名（email, password, phone…）で判定し、他の文字列は自由文として処理
piip field password 'hunter2'        # フォームの 1 フィールドとしてマスク
piip types                           # 種別一覧と現在の有効/無効
```

種別の切り替え: `--enable name_text`、`--disable ip,hosting`、`--only email,phone`。

## エンジン

| `-e` | 内容 | 用途 |
|---|---|---|
| `builtin`（既定） | 組み込みルール（正規表現＋検証: Luhn、マイナンバー検査数字など） | 高速。依存なし。構造化された PII・秘密情報 |
| `hybrid` | builtin の後に Presidio の NER で残りを検出 | 「佐藤花子さん」「John Smith」など、ラベルのない人名・地名も消したいとき |
| `presidio` | Presidio のみ | Presidio 単体の結果を見たいとき |

`hybrid`/`presidio` は Presidio Analyzer サーバーが必要。起動（初回はモデル取得で数分かかる）:

```bash
bash <このスキルのベースディレクトリ>/scripts/presidio-start.sh   # http://127.0.0.1:5002 で起動（既に起動済みなら何もしない）
piip presidio                                                     # 接続確認（health・言語・サンプル検出）
piip -e hybrid mask notes.txt
```

言語は自動判定（かな・漢字→ja、英単語→en、混在→両方）。`--lang ja` で固定できる。
Presidio は 1 秒あたり 10KB 前後と遅い。大きなディレクトリは builtin でスキャンし、hybrid は個別のファイルに使う。
地名（LOCATION）は既定で無効（地名だけなら「東京都に行きました」のように個人情報ではないため）。必要なら `--enable location`。
Presidio を使う前にユーザーへ一言伝えること（Python 環境と spaCy モデル約 100MB を ~/.cache 配下に入れるため）。

## 出力の読み方

- マスク形式: `t***@example.jp`、`***-***-5678`、`****-****-****-9014`、`東京都***`、`[REDACTED]`
- 全角の入力は、マスクされなかった部分が全角のまま残る（`携帯 ***－***－５６７８`）
- 同意フレーズ（例「マスクを外すことに同意」）を含む文は**マスクされずにそのまま**返り、
  標準エラーに警告が出る。必要なら `--ignore-consent`
- `name_text`（「山田太郎と申します」）は既定で無効。名前も消すなら `--enable name_text` か `-e hybrid`
- scan の行は `path:line:col: 種別 (提供元) [ルールID] -> マスク後の値`

## 設定

`./.piip.toml` → `~/.config/piip/config.toml` の順に読む（`--config` で指定も可）。
種別の既定値、同意フレーズ、独自パターン（社員番号など）、Presidio の URL・しきい値・エンティティを設定できる。
書式と全種別の一覧は [reference.md](reference.md) を参照。

## 注意

- 検出はルールと NER による推定で、取りこぼしも誤検出もある。「完全に匿名化された」とは言わないこと
- `mask -i` はファイルを上書きし、元の値は残らない。git 管理外のファイルでは特に、実行前に確認する
- バイナリファイルとサイズ上限（既定 10MiB、`--max-size`）を超えるファイルは scan で飛ばす
