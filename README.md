# piip-skills

個人情報（PII）と秘密情報をローカルで検出・マスクする Rust 製の CLI `piip` と、それを使う Claude Code のスキル。
より踏み込んだ検出が必要なときは、Microsoft Presidio をエンジンとして選べる。

- **ローカル完結**: 外部 API を呼ばない。Presidio もローカルの `127.0.0.1` で動く
- **日本語に強いルール**: 住所・電話・マイナンバー・問い合わせ形式の項目・全角文字に対応。検証（Luhn、マイナンバー検査数字など）で誤検出を抑える。正規表現は PCRE2（JIT）
- **速い**: 1MB の問い合わせ文を約 0.25 秒でマスク（x86_64）、64MB・300 ファイルのディレクトリを約 1.2 秒でスキャン（並列）
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

スキル・フック・`piip` コマンドがまとめて入る。実行ファイルは初回に [GitHub Releases](https://github.com/benridane/piip-skills/releases)
から取得する（SHA-256 を検証。取得できない環境では cargo でビルドする）。

| 環境 | 配布物 | 備考 |
|---|---|---|
| Linux x86_64 / arm64 | 静的リンク（musl） | arm64 は PCRE2 の JIT なし（約 4 倍遅いが結果は同じ） |
| macOS arm64 / x86_64 | | arm64 は JIT なし |
| Windows x86_64 | `piip.exe` | フックの起動スクリプトは bash 前提（Git Bash）。未検証 |

実行ファイルだけ欲しい場合は Releases から直接取得できる。

### ソースから

必要なもの: Rust（cargo）。Presidio を使う場合は [uv](https://docs.astral.sh/uv/) も。

```bash
./install.sh                       # ~/.claude/skills/piip と ~/.local/bin/piip
./install.sh --hook                # フックも ~/.claude/settings.json に登録
./install.sh --project ~/src/foo   # リポジトリ単位: ~/src/foo/.claude/
```

Claude Code では「このログの個人情報をマスクして」「リポジトリに秘密情報が残っていないかスキャンして」のように頼むとスキルが使われる。

## フック

`piip hook` が Claude Code の3つの場面で働く。

| 場面 | フック | 動作 |
|---|---|---|
| 読む | PostToolUse | Read・Grep・Bash の出力をモデルに渡る前にマスクする |
| 書く・送る | PreToolUse | マスク済みの値の書き戻しを拒否。送信系コマンド・MCP・WebFetch に個人情報があれば確認を求める |
| 頼む | UserPromptSubmit | 個人情報を含むプロンプトを止め、マスクした版を示す（`#piip-ok` を付ければそのまま送る） |

### 読む

| ツール | マスクする条件 |
|---|---|
| Read | 対象ファイル（既定: `*.log` `*.csv` `*.tsv` `*.txt` `*.json` `*.jsonl` `*.xml` `*.sql` `*.eml` `.env` など） |
| Grep | 対象ファイルからの一致行（content モード） |
| Bash | コマンドに対象ファイル名が含まれるとき（`cat app.log`、`tail -f logs/*.log` など） |

- ファイル自体は書き換えない。マスクしていない部分の Edit はそのまま動き、マスクした値を含む Edit は一致せずに失敗する（実データを壊さない）
- ソースコードは既定で対象外（マスクした値を Write で書き戻す事故を防ぐため）。`[hook] all_files = true` で全ファイルを対象にできる
- マスクに失敗したときは出力を渡さない（フェイルクローズ）
- 対象の確認: `piip hook --check logs/app.log src/main.rs`

### 書く・送る

- **書き戻しの防止**: モデルに見せたマスク済みの値（`t***@example.jp`、`[REDACTED]` など）をセッションごとに記録し
  （`~/.cache/piip/sessions/`、マスク後の形だけ。7 日で削除）、Edit・Write・Bash がそれを新しく書き込もうとしたら拒否する。
  5 文字未満の値（`山*` など）は対象外
- **外部への送信**: `curl` `gh` `ssh` `aws` などの送信系コマンド、MCP ツール、WebFetch/WebSearch の入力に個人情報があれば、
  実行前に確認を求める（`[hook.outbound] action = "deny"` で拒否）。IP アドレスは既定で数えない

### 頼む

プロンプトに個人情報があると送信を止め、マスクした版を表示する。それをコピーして送り直すか、`#piip-ok` を付けてそのまま送る。
`[hook.prompt] action = "warn"` なら止めずに警告だけ、`"off"` で無効。

### Presidio（任意）

```bash
bash ~/.claude/skills/piip/scripts/presidio-start.sh   # 初回は Python 環境と spaCy モデル（en/ja）を ~/.cache/piip に用意
piip presidio                                          # 接続確認
piip -e hybrid mask notes.txt
```

同梱の `presidio/server.py` は公式 presidio-analyzer と同じ REST API（`/health`, `/analyze`）に、
日本語モデル（ja_core_news_md）と日本語向けのパターン認識器を加えたもの。
英語だけでよければ公式コンテナも使える: `docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer`。

## 精度

合成の評価セット（740 文書・18 万文字・正解 3,398 件。日英の問い合わせ、アクセスログ、アプリログ、CSV、メール、チャット、`.env`、
決済フォーム、個人情報を含まない紛らわしい文書）での結果。`python3 eval/run.py [-e hybrid]` で再現できる。

| 種別 | builtin 再現率 | hybrid 再現率 |
|---|---:|---:|
| メール・電話・IP・住所・郵便番号・カード・秘密情報・生年月日・口座・SSN・マイナンバー・身分証 | 100% | 100% |
| ラベル付きの名前（お名前：…） | 100% | 100% |
| CSV の列の名前 | 0% | 94.4% |
| 文中の名前（担当の佐藤より…） | 0% | 74.9% |
| **全体の再現率** | **83.8%** | **97.3%** |
| **全体の適合率** | **99.2%** | **98.3%** |
| 個人情報なしの文書 3.2 万文字での誤検出 | 20 件 | 41 件 |

builtin の誤検出は、Luhn 検査を偶然通る 13〜19 桁の番号（JAN コードなど）、検査数字を偶然満たす 12 桁の番号（追跡番号）が主。
hybrid では Presidio の人名の誤検出が加わる。

注意: 評価セットは作者がテンプレートから生成したもので、ルールの改善にも使ったため、数字は実データより良く出る。
実データでは表記の揺れがもっと大きい。目安として読み、重要な用途では結果を確認すること。

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
