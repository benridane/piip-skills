# piip-skills

個人情報（PII）と秘密情報をローカルで検出・マスクする Rust 製の CLI `piip` と、それを使う Claude Code のスキル。
より踏み込んだ検出が必要なときは、Microsoft Presidio をエンジンとして選べる。

- **ローカル完結**: 外部 API を呼ばない。Presidio もローカルの `127.0.0.1` で動く
- **日本語に強いルール**: 住所・電話・マイナンバー・問い合わせ形式の項目・全角文字に対応。検証（Luhn、マイナンバー検査数字など）で誤検出を抑える。正規表現は PCRE2（JIT）
- **速い**: 1MB の問い合わせ文を約 0.25 秒でマスク、64MB・300 ファイルのディレクトリを約 1.2 秒でスキャン（並列）
- **自動で守るフック**: ログ・CSV・JSON・`.env` などを Claude が Read/Grep/Bash で読むと、出力をマスクしてからモデルに渡す（ファイル自体は変えない）
- **エンジン選択**: `builtin`（既定）/ `hybrid`（builtin ルール → Presidio NER）/ `presidio`

```console
$ piip mask inquiry.txt
お名前：山* 太* 様
ご住所：東京都*** 電話：***-***-5678
メール：ｔ***＠ｅｘａｍｐｌｅ．ｊｐ
カード ****-****-****-9014 有効期限：**/** CVV：***

$ piip -e hybrid mask notes.txt
先日、営業部の佐***さんと鈴***さんが大阪の取引先を訪問しました。
Meeting notes: J*** S**** from Seattle called M*** J****** about the invoice.

$ piip scan . --fail
config/app.env:3:18: token (Config secret) [env_secret] -> [REDACTED]
logs/2026-10-01.log:120:41: email [email] -> t***@example.jp
```

## インストール

### Claude Code プラグイン（おすすめ）

```
/plugin marketplace add benridane/piip-skills
/plugin install piip@piip
```

スキル・フック・`piip` コマンドがまとめて入る。実行ファイルは初回に GitHub Releases から取得する
（チェックサム検証あり。取得できない環境では cargo でビルドする）。

### ソースから

必要なもの: Rust（cargo）。Presidio を使う場合は [uv](https://docs.astral.sh/uv/) も。

```bash
./install.sh                       # ~/.claude/skills/piip と ~/.local/bin/piip
./install.sh --hook                # フックも ~/.claude/settings.json に登録
./install.sh --project ~/src/foo   # リポジトリ単位: ~/src/foo/.claude/
```

Claude Code では「このログの個人情報をマスクして」「リポジトリに秘密情報が残っていないかスキャンして」のように頼むとスキルが使われる。

## フック

PostToolUse フック（`piip hook`）が、Claude の Read・Grep・Bash の出力をモデルに渡る前にマスクする。
頼まなくても、データファイルの生の値はコンテキストに入らない。

| ツール | マスクする条件 |
|---|---|
| Read | 対象ファイル（既定: `*.log` `*.csv` `*.tsv` `*.txt` `*.json` `*.jsonl` `*.xml` `*.sql` `*.eml` `.env` など） |
| Grep | 対象ファイルからの一致行（content モード） |
| Bash | コマンドに対象ファイル名が含まれるとき（`cat app.log`、`tail -f logs/*.log` など） |

- ファイル自体は書き換えない。マスクしていない部分の Edit はそのまま動き、マスクした値を含む Edit は一致せずに失敗する（実データを壊さない）
- ソースコードは既定で対象外（マスクした値を Write で書き戻す事故を防ぐため）。`[hook] all_files = true` で全ファイルを対象にできる
- マスクに失敗したときは出力を渡さない（フェイルクローズ）
- 対象の確認: `piip hook --check logs/app.log src/main.rs`

### Presidio（任意）

```bash
bash ~/.claude/skills/piip/scripts/presidio-start.sh   # 初回は Python 環境と spaCy モデル（en/ja）を ~/.cache/piip に用意
piip presidio                                          # 接続確認
piip -e hybrid mask notes.txt
```

同梱の `presidio/server.py` は公式 presidio-analyzer と同じ REST API（`/health`, `/analyze`）に、
日本語モデル（ja_core_news_md）と日本語向けのパターン認識器を加えたもの。
英語だけでよければ公式コンテナも使える: `docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer`。

## 使い方

```
piip mask [FILES]... [-i | -o OUT] [--json] [--ignore-consent]
piip scan [PATHS]... [-f text|json|jsonl|summary] [--fail] [--show-values] [--hidden] [--no-ignore] [--max-size MiB]
piip mask-json [FILE] [--pretty]
piip field NAME VALUE
piip types
piip presidio

共通: --config FILE, -e builtin|hybrid|presidio, --presidio-url URL, --lang auto|en|ja,
      --threshold 0.5, --enable TYPES, --disable TYPES, --only TYPES
```

種別、設定ファイル（`.piip.toml`）、制限事項は [skill/piip/reference.md](skill/piip/reference.md) を参照。

## 開発

```bash
cargo test
cargo run --release --example profile FILE   # ルールごとの処理時間
```

| ファイル | 内容 |
|---|---|
| `src/patterns.rs` | ルール定義、全角正規化と復元 |
| `src/detector.rs` | 検証関数、プロバイダー判定、フィールド名による検出 |
| `src/masker.rs` | マスク関数とルール適用、位置付き検出 |
| `src/regex.rs` | 区切り文字付き（`/…/iu`）の PCRE2 ラッパー |
| `src/presidio.rs` / `src/engine.rs` | Presidio クライアント、エンジンの切り替え |
| `presidio/` | ローカル Presidio サーバー（uv プロジェクト） |
| `skill/piip/` | Claude Code スキル（SKILL.md、リファレンス、起動スクリプト） |

ライセンス: [MIT](LICENSE)。
