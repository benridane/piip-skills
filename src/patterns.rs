//! PII text rules.
//!
//! Single source of truth for PII found in free text: the same rules mask
//! text and report detections, so what is reported is exactly what gets
//! masked. Rules run in order on text normalized by `normalize()`.

use std::sync::LazyLock;

use crate::regex::Re;

/// The 47 prefectures.
pub const PREFECTURES: &str = "北海道|東京都|京都府|大阪府|(?:青森|岩手|宮城|秋田|山形|福島|茨城|栃木|群馬|埼玉|千葉|神奈川|新潟|富山|石川|福井|山梨|長野|岐阜|静岡|愛知|三重|滋賀|兵庫|奈良|和歌山|鳥取|島根|岡山|広島|山口|徳島|香川|愛媛|高知|福岡|佐賀|長崎|熊本|大分|宮崎|鹿児島|沖縄)県";

/// The 20 designated cities, commonly written without the prefecture.
pub const DESIGNATED_CITIES: &str = "札幌市|仙台市|さいたま市|千葉市|横浜市|川崎市|相模原市|新潟市|静岡市|浜松市|名古屋市|京都市|大阪市|堺市|神戸市|岡山市|広島市|北九州市|福岡市|熊本市";

/// Tokyo's 23 special wards, commonly written without 東京都.
pub const TOKYO_WARDS: &str = "千代田区|中央区|港区|新宿区|文京区|台東区|墨田区|江東区|品川区|目黒区|大田区|世田谷区|渋谷区|中野区|杉並区|豊島区|北区|荒川区|板橋区|練馬区|足立区|葛飾区|江戸川区";

/// Required block/lot number at the end of a Japanese address.
pub const ADDRESS_TAIL: &str = r"(?:[0-9]{1,4}丁目(?:[\s]*[0-9]{1,4}(?:(?:-[0-9]{1,4}){1,3}|番地?(?:[0-9]{1,4}号)?|号))?|[0-9]{1,4}(?:番地?|号)(?:[0-9]{1,4}号)?|[0-9]{1,4}(?:-[0-9]{1,4}){1,3})";

/// Kanji ranges for character classes (explicit, not \p{Han}).
pub const KANJI: &str = r"\x{3400}-\x{4DBF}\x{4E00}-\x{9FFF}\x{F900}-\x{FAFF}々〆ヶ";

/// Katakana ranges (with the long vowel mark).
pub const KATAKANA: &str = r"\x{30A1}-\x{30FA}\x{30FC}\x{31F0}-\x{31FF}";

/// Hiragana range.
pub const HIRAGANA: &str = r"\x{3041}-\x{3096}";

/// Separator between a label and its value: colon, closing bracket, or tab.
const LABEL_SEPARATOR: &str = r"(?:[】\]][\t ]*[:=]?|[\t ]*[:=]|\t)[\t ]*";

// Patterns shared with the detector.

pub const PRIVATE_KEY_PATTERN: &str = r"/-----BEGIN [A-Z ]{0,48}PRIVATE KEY(?: BLOCK)?-----(?:[A-Za-z0-9+\/=:,.\s-]|<br\s*\/?>)+?-----END [A-Z ]{0,48}PRIVATE KEY(?: BLOCK)?-----/";

const BASIC_AUTH_CURL_USER: &str =
    r#"/(\bcurl\b[^\r\n]{0,200}?(?:-u|--user)[ =]+["']?)([^\s:"'@]{1,64}):([^\s"']{1,64})/"#;
const BASIC_AUTH_HEADER: &str =
    r"/(\bAuthorization[\s　]*[：:][\s　]*Basic\s+)([A-Za-z0-9+\/]{8,}={0,2})/iu";
const BASIC_AUTH_URL_USERINFO: &str =
    r"/(\b[a-z][a-z0-9+.\-]{1,20}:\/\/)([^\s\/:@]{1,64}):([^\s\/@]{1,64})@/i";

const BEARER_PATTERN: &str =
    r"/(\bBearer\b[\s　]*[：:]?[\s　]*)([A-Za-z0-9\-_~+\/]{8,}(?:\.[A-Za-z0-9\-_~+\/=]+){0,4}=*)/u";

pub const IPV6_CANDIDATE_PATTERN: &str =
    r"/(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:]|\.\d)/";

const JP_POSTAL_LABELED_PATTERN: &str = r"/((?:〒|郵便番号)[\s　]*[：:]?[\s　]*)([0-9０-９]{3}[-‐−ー―－]?[0-9０-９]{4})(?![0-9０-９])/u";

const LABELED_DOB_PATTERN: &str = r"/((?<![A-Za-z])(?:生年月日|誕生日|birth[\s　]?date|date\s+of\s+birth|dob)[\s　]*[：:は]?[\s　]*)((?:明治|大正|昭和|平成|令和)[0-9０-９]{1,2}年[0-9０-９]{1,2}月[0-9０-９]{1,2}日|[0-9０-９]{4}年[0-9０-９]{1,2}月[0-9０-９]{1,2}日|[0-9]{4}[-\/][0-9]{1,2}[-\/][0-9]{1,2}|[0-9]{1,2}[-\/][0-9]{1,2}[-\/][0-9]{2,4})/iu";

const BANK_LABELED_ACCOUNT: &str =
    r"/(口座番号[\s　]*[：:は]?[\s　]*)([0-9０-９]{6,8})(?![0-9０-９])/u";
const BANK_PASSBOOK_STYLE: &str =
    r"/((?:普通|当座)(?:預金|口座)?[\s　]*[：:]?[\s　]*)([0-9０-９]{7})(?![0-9０-９])/u";

const NAME_PATTERNS: &[(&str, &str)] = &[
    (
        "self_intro",
        r"/((?:私は|わたしは)?)([一-龠々ヶぁ-んァ-ヴーA-Za-z][一-龠々ヶぁ-んァ-ヴー・A-Za-z]{1,9})(と申します|といいます|と言います)/u",
    ),
    (
        "labeled",
        r"/((?:お?名前|氏名|フルネーム)[\s　]*[：:は][\s　]*)([一-龠々ヶぁ-んァ-ヴーA-Za-z・]{2,10}(?:[ 　][一-龠々ヶぁ-んァ-ヴーA-Za-z・]{1,10})?)/u",
    ),
];

pub const NAME_EXCLUSION_PATTERN: &str = r"/会社|\(株\)|\(有\)|（株）|（有）|法人|Inc|LLC|Corp/iu";

/// Developer secret patterns with their provider labels.
const DEV_SECRET_PATTERNS: &[(&str, &str, &str)] = &[
    (
        "github_token",
        r"/\bgh[pousr]_[A-Za-z0-9]{36,251}\b/",
        "GitHub",
    ),
    (
        "github_pat",
        r"/\bgithub_pat_[A-Za-z0-9_]{22,255}\b/",
        "GitHub",
    ),
    (
        "slack_token",
        r"/\bxox[baprs]-[A-Za-z0-9\-]{10,250}\b/",
        "Slack",
    ),
    ("aws_access_key", r"/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/", "AWS"),
    (
        "stripe_key",
        r"/\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,247}\b/",
        "Stripe",
    ),
    (
        "jwt",
        r"/\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/",
        "JWT",
    ),
    ("stripe_webhook", r"/\bwhsec_[A-Za-z0-9]{24,}\b/", "Stripe"),
    (
        "google_oauth",
        r"/\bya29\.[A-Za-z0-9_\-]{20,}/",
        "Google OAuth",
    ),
    (
        "sendgrid",
        r"/\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b/",
        "SendGrid",
    ),
    ("npm_token", r"/\bnpm_[A-Za-z0-9]{36}\b/", "npm"),
    ("gitlab_token", r"/\bglpat-[A-Za-z0-9_\-]{20,}\b/", "GitLab"),
    ("twilio_key", r"/\bSK[0-9a-fA-F]{32}\b/", "Twilio"),
    ("mailgun_key", r"/\bkey-[0-9a-f]{32}\b/", "Mailgun"),
    (
        "shopify_token",
        r"/\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/",
        "Shopify",
    ),
    (
        "telegram_bot",
        r"/\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b/",
        "Telegram",
    ),
    (
        "digitalocean",
        r"/\bdo[por]_v1_[a-f0-9]{64}\b/",
        "DigitalOcean",
    ),
    (
        "slack_webhook",
        r"/\bhttps:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9_\/\-]{20,}/",
        "Slack webhook",
    ),
    (
        "discord_webhook",
        r"/\bhttps:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]{20,}/",
        "Discord webhook",
    ),
];

/// Validators, see `crate::validate`.
#[derive(Clone, Copy, Debug)]
pub enum Validate {
    IsSecretValue,
    HasTokenChars,
    IsPersonName,
    HasDigit,
    IsPhoneValue,
    IsAccountValue,
    IsCardNumber,
    IsSsnNumber,
    IsMynumberNumber,
    IsMaskableIpv6,
    IsAiKey,
}

/// Masking functions, see `crate::masker`.
#[derive(Clone, Copy, Debug)]
pub enum MaskFn {
    KeepPrefix,
    Token,
    UrlSecret,
    Dob,
    Bank,
    IdDoc,
    PersonName,
    LabeledAddress,
    Phone,
    AccountId,
    Email,
    CreditCard,
    Ssn,
    Mynumber,
    Ip,
    HostingId,
    Name,
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Replace(&'static str),
    Mask(MaskFn),
}

#[derive(Clone, Copy, Debug)]
pub enum Provider {
    None,
    Static(&'static str),
    Hosting,
    Ai,
}

pub struct Rule {
    pub id: String,
    pub ptype: &'static str,
    pub re: Re,
    pub group: usize,
    pub validate: Option<Validate>,
    pub action: Action,
    pub provider: Provider,
}

/// Ordered text rules. Order matters: earlier rules consume text before
/// later, more generic ones see it.
pub static RULES: LazyLock<Vec<Rule>> = LazyLock::new(build_rules);

/// Fold full-width alphanumerics and symbols to ASCII, one char for one.
///
/// HTML-significant characters (＜ ＞ ＂ ＇ ＆ ｀) are left alone. Dash
/// look-alikes between alphanumerics (090ー1234) become "-".
pub fn normalize(text: &str) -> String {
    let folded: Vec<char> = text
        .chars()
        .map(|c| match c {
            '\u{3000}' => ' ',
            '\u{FF01}'..='\u{FF5E}' => {
                let ascii = char::from_u32(c as u32 - 0xFEE0).unwrap();
                if "<>\"'&`".contains(ascii) { c } else { ascii }
            }
            other => other,
        })
        .collect();

    let is_alnum = |c: Option<&char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    let mut out = String::with_capacity(text.len());
    for (i, &c) in folded.iter().enumerate() {
        let dash = matches!(c, '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' | 'ー' | 'ｰ');
        if dash && i > 0 && is_alnum(folded.get(i - 1)) && is_alnum(folded.get(i + 1)) {
            out.push('-');
        } else {
            out.push(c);
        }
    }
    out
}

/// Text being masked, remembering where each character came from.
///
/// Masking is carried back onto the original characters so full-width text
/// stays full-width outside the masked spans. Every character keeps the
/// index of the original character it came from, and a Myers diff only runs
/// inside each replaced value, so the whole pass stays O(n).
pub struct Tracked {
    pub text: String,
    /// Original char index per char of `text`; None = inserted by masking.
    /// Not tracked when the text needed no normalization.
    origin: Option<Vec<Option<usize>>>,
}

impl Tracked {
    pub fn new(normalized: &str, track: bool) -> Self {
        let origin = track.then(|| (0..normalized.chars().count()).map(Some).collect());
        Tracked {
            text: normalized.to_string(),
            origin,
        }
    }

    /// Apply sorted, non-overlapping byte-span replacements.
    pub fn apply(&mut self, edits: &[(usize, usize, String)]) {
        if edits.is_empty() {
            return;
        }

        let mut text = String::with_capacity(self.text.len());
        let mut last = 0;
        let mut new_origin = self.origin.as_ref().map(|o| Vec::with_capacity(o.len()));
        let mut ci = 0; // Char index in the old text.

        for (start, end, replacement) in edits {
            let kept = &self.text[last..*start];
            text.push_str(kept);
            text.push_str(replacement);

            if let (Some(old_origin), Some(out)) = (&self.origin, &mut new_origin) {
                let kept_chars = kept.chars().count();
                out.extend_from_slice(&old_origin[ci..ci + kept_chars]);
                ci += kept_chars;

                let old: Vec<char> = self.text[*start..*end].chars().collect();
                let new: Vec<char> = replacement.chars().collect();
                let mut map = vec![None; new.len()];
                // Characters the mask kept (dashes, last digits) keep their
                // original form; huge blocks (private keys) are not aligned.
                if old.len().saturating_mul(new.len()) <= 250_000 {
                    for (op, i, j) in diff(&old, &new) {
                        if op == Op::Equal {
                            map[j] = old_origin[ci + i];
                        }
                    }
                }
                out.extend(map);
                ci += old.len();
            }
            last = *end;
        }

        let rest = &self.text[last..];
        text.push_str(rest);
        if let (Some(old_origin), Some(out)) = (&self.origin, &mut new_origin) {
            out.extend_from_slice(&old_origin[ci..]);
        }

        self.text = text;
        self.origin = new_origin;
    }

    /// The masked text in the original's characters.
    pub fn restore(self, original: &str) -> String {
        let Some(origin) = self.origin else {
            return self.text;
        };
        let orig: Vec<char> = original.chars().collect();
        self.text
            .chars()
            .zip(origin)
            .map(|(c, o)| o.map_or(c, |i| orig[i]))
            .collect()
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Op {
    Equal,
    Delete,
    Insert,
}

/// Shortest edit script between two sequences (Myers' algorithm).
fn diff<T: PartialEq>(a: &[T], b: &[T]) -> Vec<(Op, usize, usize)> {
    let (n, m) = (a.len(), b.len());

    let mut start = 0;
    while start < n && start < m && a[start] == b[start] {
        start += 1;
    }
    let (mut end_a, mut end_b) = (n, m);
    while end_a > start && end_b > start && a[end_a - 1] == b[end_b - 1] {
        end_a -= 1;
        end_b -= 1;
    }

    let mut ops: Vec<(Op, usize, usize)> = (0..start).map(|i| (Op::Equal, i, i)).collect();
    for (op, i, j) in myers(&a[start..end_a], &b[start..end_b]) {
        ops.push((op, i + start, j + start));
    }
    for i in 0..(n - end_a) {
        ops.push((Op::Equal, end_a + i, end_b + i));
    }
    ops
}

fn myers<T: PartialEq>(a: &[T], b: &[T]) -> Vec<(Op, usize, usize)> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    if n == 0 {
        return (0..m as usize).map(|j| (Op::Insert, 0, j)).collect();
    }
    if m == 0 {
        return (0..n as usize).map(|i| (Op::Delete, i, 0)).collect();
    }

    let max = n + m;
    let offset = max + 1;
    let size = (2 * max + 3) as usize;
    let get = |v: &Vec<isize>, k: isize, default: isize| {
        let x = v[(k + offset) as usize];
        if x == isize::MIN { default } else { x }
    };

    let mut v = vec![isize::MIN; size];
    v[(1 + offset) as usize] = 0;
    let mut trace: Vec<Vec<isize>> = Vec::new();

    'outer: for d in 0..=max {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && get(&v, k - 1, -1) < get(&v, k + 1, -1)) {
                get(&v, k + 1, 0)
            } else {
                get(&v, k - 1, 0) + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[(k + offset) as usize] = x;
            if x >= n && y >= m {
                break 'outer;
            }
            k += 2;
        }
    }

    let mut ops = Vec::new();
    let (mut x, mut y) = (n, m);
    for d in (0..trace.len() as isize).rev() {
        let v = &trace[d as usize];
        let k = x - y;
        let prev_k = if k == -d || (k != d && get(v, k - 1, -1) < get(v, k + 1, -1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = get(v, prev_k, 0);
        let prev_y = prev_x - prev_k;

        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
            ops.push((Op::Equal, x as usize, y as usize));
        }
        if d > 0 {
            if x == prev_x {
                y -= 1;
                ops.push((Op::Insert, x as usize, y as usize));
            } else {
                x -= 1;
                ops.push((Op::Delete, x as usize, y as usize));
            }
        }
    }

    ops.reverse();
    ops
}

fn rule(
    id: &str,
    ptype: &'static str,
    regex: &str,
    group: usize,
    validate: Option<Validate>,
    action: Action,
    provider: Provider,
) -> Rule {
    Rule {
        id: id.to_string(),
        ptype,
        re: Re::delimited(regex).unwrap_or_else(|e| panic!("rule {id}: {e}")),
        group,
        validate,
        action,
        provider,
    }
}

fn build_rules() -> Vec<Rule> {
    use Action::{Mask, Replace};
    use MaskFn as M;
    use Provider::{Ai, Hosting, Static};
    use Validate as V;

    let lb: &str = &["(?<![A-Za-z0-9_", KANJI, KATAKANA, "])"].concat();
    let sep = LABEL_SEPARATOR;

    // Labels used as value terminators (a value ends where the next field starts).
    let name_labels = r"お名前|ご氏名|登録氏名|登録名|氏名|フルネーム|姓名|ご担当者様?名|担当者名|受取人(?:氏名|名|様)?|お届け先(?:氏名|名|様)|宛名|口座名義人?|カード名義人?|名義人|契約者(?:氏名|名|様)?|申込者(?:氏名|名)?|Full\s?name|Your\s+name|Customer\s+name|Contact\s+name|Cardholder(?:\s+name)?|Account\s+holder(?:\s+name)?";
    let kana_labels =
        r"フリガナ|ふりがな|カナ氏名|セイメイ|(?:お名前|氏名)[(](?:カナ|フリガナ|ふりがな)[)]";
    let address_labels = r"ご住所|現住所|住所|所在地|お届け先(?:ご)?住所|お届け先|配送先(?:住所)?|送付先(?:住所)?|発送先(?:住所)?|請求先住所|Shipping\s+address|Billing\s+address|Mailing\s+address|Home\s+address|Address";
    let phone_labels = r"お電話番号|ご連絡先電話番号|連絡先電話番号|電話番号|携帯電話番号|携帯番号|携帯電話|携帯|連絡先|電話|TEL|FAX|ファックス|Phone(?:\s+number)?|Telephone|Mobile(?:\s+number)?|Cell(?:\s+phone)?";
    let account_labels = r"会員番号|会員ID|会員コード|お客様番号|お客様ID|顧客番号|顧客ID|ユーザーID|ユーザー名|ユーザネーム|ログインID|ログイン名|アカウントID|アカウント名|契約番号|加入者番号|利用者ID|利用者番号|Customer\s+(?:ID|number|no\.?)|Member(?:ship)?\s+(?:ID|number|no\.?)|Account\s+(?:ID|number|no\.?)|User\s?name|User\s+ID|Login\s+(?:ID|name)";
    let expiry_labels = r"カード有効期限|有効期限|Expiry(?:\s+date)?|Expiration(?:\s+date)?|Exp\.?\s*date|Valid\s+thru|EXP";
    let cvv_labels = r"セキュリティーコード|セキュリティコード|CVV2?|CVC2?|CID|Security\s+code";
    let other_labels = r"メールアドレス|メール|E-?mail|パスワード|Password|生年月日|郵便番号|〒|口座番号|注文番号|Order\s*(?:number|no\.?|#)";
    let all_labels = [
        name_labels,
        kana_labels,
        address_labels,
        phone_labels,
        account_labels,
        expiry_labels,
        cvv_labels,
        other_labels,
    ]
    .join("|");

    // Space-separated name parts stop at the next label (お名前：山田 太郎 電話：…).
    let kk = [KANJI, KATAKANA].concat();
    let name_value = [
        "[",
        &kk,
        "A-Za-z][",
        &kk,
        "・A-Za-z.'-]{0,15}(?:[ ](?!(?:",
        &all_labels,
        "))[",
        &kk,
        "・A-Za-z.'-]{1,15}){0,2}",
    ]
    .concat();
    let kana_value = [
        "[",
        KATAKANA,
        HIRAGANA,
        "]{1,15}(?:[ ][",
        KATAKANA,
        HIRAGANA,
        "]{1,15})?",
    ]
    .concat();

    let pass_kw = "PASSWORD|PASSWD|PASS|PWD";
    let secret_kw = "SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH_?KEY|SALT|CREDENTIALS?";
    let env_name = |kw: &str| {
        let lower = kw.to_lowercase();
        [
            "(?<![A-Za-z0-9_])(?:(?-i:[A-Z0-9_]*(?:",
            kw,
            ")[A-Z0-9_]*)|(?-i:(?=[a-z0-9]*_)[a-z0-9_]*(?:",
            &lower,
            ")[a-z0-9_]*))",
        ]
        .concat()
    };
    let env_value = r#"([^\s"'<>,;]{4,200})"#;

    let label = |labels: &str| [lb, "[【\\[]?(?:", labels, ")", sep].concat();

    let mut rules = vec![
        // Private key blocks: whole block, before token patterns shred it.
        rule("private_key", "token", PRIVATE_KEY_PATTERN, 0, None, Replace("[REDACTED]"), Static("Private key")),
        // Passwords and config secrets.
        rule(
            "labeled_password",
            "password",
            r"/((?<![A-Za-z0-9_])(?:password|passwd|passcode|pwd|P\/W|PW|PIN|パスワード|パスコード|ログインパス|暗証番号)[\s]*[:=は][\s]*)([\x21-\x7E]{4,64})/iu",
            2,
            None,
            Replace("[REDACTED]"),
            Provider::None,
        ),
        rule(
            "define_secret",
            "token",
            &[
                r#"/(define\(\s*["'](?-i:[A-Z0-9_]*(?:"#, pass_kw, "|", secret_kw,
                r#")[A-Z0-9_]*)["']\s*,\s*["'])([^"'\r\n<>]{1,200})/u"#,
            ]
            .concat(),
            2,
            Some(V::IsSecretValue),
            Replace("[REDACTED]"),
            Static("Config secret"),
        ),
        rule(
            "env_password",
            "password",
            &["/(", &env_name(pass_kw), r#"[\t ]*(?:=>|=|:)[\t ]*["']?)"#, env_value, "/u"].concat(),
            2,
            Some(V::IsSecretValue),
            Replace("[REDACTED]"),
            Provider::None,
        ),
        rule(
            "env_secret",
            "token",
            &["/(", &env_name(secret_kw), r#"[\t ]*(?:=>|=|:)[\t ]*["']?)"#, env_value, "/u"].concat(),
            2,
            Some(V::IsSecretValue),
            Replace("[REDACTED]"),
            Static("Config secret"),
        ),
        // HTTP credentials.
        rule("curl_user", "token", BASIC_AUTH_CURL_USER, 3, None, Replace("[REDACTED]"), Static("Basic auth")),
        rule("auth_basic", "token", BASIC_AUTH_HEADER, 2, None, Mask(M::KeepPrefix), Static("Basic auth")),
        rule("url_userinfo", "token", BASIC_AUTH_URL_USERINFO, 3, None, Replace("***"), Static("Basic auth")),
        rule("bearer", "token", BEARER_PATTERN, 2, Some(V::HasTokenChars), Mask(M::Token), Static("Bearer token")),
        // Labeled personal data.
        rule("dob", "dob", LABELED_DOB_PATTERN, 2, None, Mask(M::Dob), Provider::None),
        rule("bank_labeled", "bank", BANK_LABELED_ACCOUNT, 2, None, Mask(M::Bank), Provider::None),
        rule("bank_passbook", "bank", BANK_PASSBOOK_STYLE, 2, None, Mask(M::Bank), Provider::None),
        // Identity document numbers (labeled).
        rule(
            "passport",
            "id_doc",
            &["/(", lb, r"(?:旅券番号|パスポート番号|パスポートNo\.?|Passport\s*(?:No\.?|number|#))[\t ]*[:]?[\t ]*)([A-Z]{2}[0-9]{7})(?![A-Za-z0-9])/iu"].concat(),
            2,
            None,
            Mask(M::IdDoc),
            Static("Passport"),
        ),
        rule(
            "drivers_license_jp",
            "id_doc",
            &["/(", lb, r"(?:運転免許証番号|運転免許番号|免許証番号|免許番号)[\t ]*[:]?[\t ]*(?:第[\t ]*)?)([0-9]{12})(?![0-9])/u"].concat(),
            2,
            None,
            Mask(M::IdDoc),
            Static("Driver's license"),
        ),
        rule(
            "drivers_license",
            "id_doc",
            r"/((?<![A-Za-z])Driver'?s?\s+licen[cs]e\s*(?:No\.?|number|#)?[\t ]*[:]?[\t ]*)([A-Z0-9][A-Z0-9-]{4,19})(?![A-Za-z0-9-])/iu",
            2,
            Some(V::HasDigit),
            Mask(M::IdDoc),
            Static("Driver's license"),
        ),
        rule(
            "health_insurance",
            "id_doc",
            &["/(", lb, r"(?:被保険者証?番号|保険者番号|保険証番号|保険証の番号)[\t ]*[:]?[\t ]*)([0-9A-Za-z-]{4,20})(?![0-9A-Za-z-])/u"].concat(),
            2,
            Some(V::HasDigit),
            Mask(M::IdDoc),
            Static("Health insurance"),
        ),
        rule(
            "pension",
            "id_doc",
            &["/(", lb, r"(?:基礎年金番号|年金番号)[\t ]*[:]?[\t ]*)([0-9]{4}[-\h]?[0-9]{6})(?![0-9])/u"].concat(),
            2,
            None,
            Mask(M::IdDoc),
            Static("Pension"),
        ),
        rule(
            "residence_card",
            "id_doc",
            &["/(", lb, r"(?:在留カード番号|在留カードの番号)[\t ]*[:]?[\t ]*)([A-Z]{2}[0-9]{8}[A-Z]{2})(?![A-Za-z0-9])/iu"].concat(),
            2,
            None,
            Mask(M::IdDoc),
            Static("Residence card"),
        ),
        // Inquiry-style labeled contact details ("お名前：山田太郎").
        rule(
            "contact_kana",
            "contact",
            &["/(", &label(kana_labels), ")(", &kana_value, ")/iu"].concat(),
            2,
            None,
            Mask(M::PersonName),
            Provider::None,
        ),
        rule(
            "contact_name",
            "contact",
            &["/(", &label(name_labels), ")(", &name_value, ")/iu"].concat(),
            2,
            Some(V::IsPersonName),
            Mask(M::PersonName),
            Provider::None,
        ),
        // Bare 名前/Name/名義 only at the start of a line: mid-sentence they
        // are too common in technical text (変数の名前: foo).
        rule(
            "contact_name_line",
            "contact",
            &[
                r"/((?:^|(?<=[\n>]))[\t ]*(?:[■□●○◆◇・*※-]|[0-9]{1,2}[.)])?[\t ]*[【\[]?(?:名前|Name|名義)",
                sep, ")(", &name_value, ")/imu",
            ]
            .concat(),
            2,
            Some(V::IsPersonName),
            Mask(M::PersonName),
            Provider::None,
        ),
        rule(
            "contact_address",
            "contact",
            &[
                "/(", &label(address_labels), r")([^\r\n<]{4,120}?)(?=[\t ]*(?:$|[\r\n<]|(?:[,、，;|][\t ]*)?",
                &label(&all_labels), "))/imu",
            ]
            .concat(),
            2,
            Some(V::HasDigit),
            Mask(M::LabeledAddress),
            Provider::None,
        ),
        rule(
            "contact_phone",
            "contact",
            &[
                "/(", lb, "[【\\[]?(?:", phone_labels, r")(?:\.)?", sep,
                r")(\+?\(?[0-9][0-9 ().-]{6,22}[0-9](?:[\t ]*[(]?(?:内線|ext\.?|x)[\t ]*[0-9]{1,6}[)]?)?)/iu",
            ]
            .concat(),
            2,
            Some(V::IsPhoneValue),
            Mask(M::Phone),
            Provider::None,
        ),
        rule(
            "contact_account",
            "contact",
            &["/(", &label(account_labels), r#")([^\s,、，;|<>"'。]{2,64})/iu"#].concat(),
            2,
            Some(V::IsAccountValue),
            Mask(M::AccountId),
            Provider::None,
        ),
        rule(
            "contact_card_expiry",
            "contact",
            &[
                "/(", &label(expiry_labels),
                r")((?:0?[1-9]|1[0-2])[\t ]*[\/-][\t ]*(?:20)?[0-9]{2}(?![0-9])|(?:20)?[0-9]{2}年[\t ]*(?:0?[1-9]|1[0-2])月(?![\t ]*[0-9]{1,2}日))/iu",
            ]
            .concat(),
            2,
            None,
            Replace("**/**"),
            Provider::None,
        ),
        rule(
            "contact_card_cvv",
            "contact",
            &["/(", &label(cvv_labels), r")([0-9]{3,4})(?![0-9])/iu"].concat(),
            2,
            None,
            Replace("***"),
            Provider::None,
        ),
        // Japanese addresses and labeled postal codes.
        rule(
            "jp_address",
            "address",
            &[
                "/(", PREFECTURES, ")((?:[一-龠々ぁ-んァ-ヶー]{1,10}?[市区町村郡]){1,3}[一-龠々ぁ-んァ-ヶー0-9]{0,20}?",
                ADDRESS_TAIL, ")/u",
            ]
            .concat(),
            2,
            None,
            Replace("***"),
            Provider::None,
        ),
        rule(
            "jp_city_address",
            "address",
            &[
                "/(?<![一-龠々])((?:", DESIGNATED_CITIES, ")(?:[一-龠々ぁ-んァ-ヶー]{1,5}区)?|(?:", TOKYO_WARDS,
                "))((?:[一-龠々ァ-ヶ][一-龠々ぁ-んァ-ヶー0-9]{0,19}?)", ADDRESS_TAIL, ")/u",
            ]
            .concat(),
            2,
            None,
            Replace("***"),
            Provider::None,
        ),
        rule("jp_postal", "address", JP_POSTAL_LABELED_PATTERN, 2, None, Replace("***-****"), Provider::None),
        // Email.
        rule("email", "email", r"/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/", 0, None, Mask(M::Email), Provider::None),
        // Payment cards (Luhn-validated).
        rule("card", "card", r"/\b\d{4}[-\h]?\d{4}[-\h]?\d{4}[-\h]?\d{1,7}\b/", 0, Some(V::IsCardNumber), Mask(M::CreditCard), Provider::None),
        rule("card_amex_diners", "card", r"/\b\d{4}[-\h]?\d{6}[-\h]?\d{4,5}\b/", 0, Some(V::IsCardNumber), Mask(M::CreditCard), Provider::None),
        // National IDs.
        rule("ssn", "ssn", r"/\b\d{3}[-\h]\d{2}[-\h]\d{4}\b/", 0, Some(V::IsSsnNumber), Mask(M::Ssn), Provider::None),
        rule("mynumber", "ssn", r"/\b\d{4}[-\h]?\d{4}[-\h]?\d{4}\b/", 0, Some(V::IsMynumberNumber), Mask(M::Mynumber), Provider::None),
        // Phone numbers.
        rule("phone_jp_mobile", "phone", r"/\b0[5789]0[-\h]?\d{4}[-\h]?\d{4}\b/", 0, None, Mask(M::Phone), Provider::None),
        rule("phone_jp_paren", "phone", r"/\b0\d{1,4}\(\d{1,4}\)\d{4}\b|\(0\d{1,4}\)\s?\d{1,4}[-\h]?\d{4}\b/", 0, None, Mask(M::Phone), Provider::None),
        rule("phone_jp_special", "phone", r"/\b0(?:120|800|570|990)[-\h]?\d{3}[-\h]?\d{3,4}\b/", 0, None, Mask(M::Phone), Provider::None),
        rule("phone_jp_landline", "phone", r"/\b0\d{1,4}[-\h]?\d{1,4}[-\h]?\d{4}\b/", 0, None, Mask(M::Phone), Provider::None),
        rule("phone_international", "phone", r"/\+\d{1,3}[-\h]?\d{1,4}[-\h]?\d{1,4}[-\h]?\d{2,4}\b/", 0, None, Mask(M::Phone), Provider::None),
        rule("phone_us_paren", "phone", r"/\(\d{3}\)\s?\d{3}[-\h]?\d{4}/", 0, None, Mask(M::Phone), Provider::None),
        rule("phone_us_dashed", "phone", r"/(?<![\d.-])(?:1[-.])?\d{3}([-.])\d{3}\1\d{4}(?![\d.-])/", 0, None, Mask(M::Phone), Provider::None),
        // IP addresses.
        rule(
            "ipv4",
            "ip",
            r"/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/",
            0,
            None,
            Mask(M::Ip),
            Provider::None,
        ),
        rule("ipv6", "ip", IPV6_CANDIDATE_PATTERN, 0, Some(V::IsMaskableIpv6), Mask(M::Ip), Provider::None),
    ];

    // Hosting account/server IDs.
    let hosting: &[(&str, &str)] = &[
        ("xserver_account", r"/\bxs\d{5,8}\b/i"),
        ("xserver_server", r"/\bsv\d{3,5}\b/i"),
        ("sakura_account", r"/\b[a-z]{3}\d{5}\b/i"),
        ("sakura_domain", r"/\b[\w-]+\.sakura\.ne\.jp\b/i"),
        ("conoha_account", r"/\bgnc[a-z0-9]{8,12}\b/i"),
        ("lolipop_domain", r"/\b[\w-]+\.lolipop\.jp\b/i"),
        ("mixhost_domain", r"/\b[\w-]+\.mixh\.jp\b/i"),
        (
            "azure_guid",
            r"/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i",
        ),
    ];
    for (id, regex) in hosting {
        rules.push(rule(
            &format!("hosting_{id}"),
            "hosting",
            regex,
            0,
            None,
            Mask(M::HostingId),
            Hosting,
        ));
    }

    // Developer secrets with fixed prefixes. Run before the generic AI key
    // patterns so those cannot pre-chew their substrings.
    for (id, regex, provider) in DEV_SECRET_PATTERNS {
        let is_url = matches!(*id, "slack_webhook" | "discord_webhook");
        let mask = if is_url { M::UrlSecret } else { M::Token };
        rules.push(rule(
            &format!("secret_{id}"),
            "token",
            regex,
            0,
            None,
            Mask(mask),
            Static(provider),
        ));
    }

    // AI API keys.
    let ai_keys: &[(&str, &str)] = &[
        ("openai_project", r"/\bsk-proj-[A-Za-z0-9_-]{40,}\b/"),
        (
            "openai_legacy",
            r"/\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/",
        ),
        ("openai_48", r"/\bsk-[A-Za-z0-9]{48}\b/"),
        // No upper bound: sk-ant-api03- plus 95 characters is 101 after "sk-ant-".
        ("anthropic", r"/\bsk-ant-[A-Za-z0-9_-]{95,}\b/"),
        ("google_ai", r"/\bAIza[A-Za-z0-9_-]{30,}\b/"),
        ("huggingface", r"/\bhf_[A-Za-z0-9]{30,}\b/"),
        ("replicate", r"/\br8_[A-Za-z0-9]{30,}\b/"),
        ("cohere", r"/\b[A-Za-z0-9]{30,}-co\b/"),
        ("azure_openai", r"/\b[a-fA-F0-9]{32}\b/"),
        ("generic", r"/\b(?:sk|ai|api)-[A-Za-z0-9_-]{20,}\b/"),
    ];
    for (id, regex) in ai_keys {
        rules.push(rule(
            &format!("ai_{id}"),
            "token",
            regex,
            0,
            Some(V::IsAiKey),
            Mask(M::Token),
            Ai,
        ));
    }

    // Name self-introductions (opt-in type name_text).
    for (id, regex) in NAME_PATTERNS {
        rules.push(rule(
            &format!("name_{id}"),
            "name_text",
            regex,
            2,
            Some(V::IsPersonName),
            Mask(M::Name),
            Provider::None,
        ));
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_rules_compile() {
        assert!(RULES.len() > 60);
    }

    #[test]
    fn normalize_is_char_for_char() {
        let s = "電話：０９０ー１２３４ー５６７８　ｔａｒｏ＠ｅｘａｍｐｌｅ．ｊｐ ＜b＞";
        let n = normalize(s);
        assert_eq!(n, "電話:090-1234-5678 taro@example.jp ＜b＞");
        assert_eq!(n.chars().count(), s.chars().count());
    }

    #[test]
    fn restore_keeps_full_width_outside_masks() {
        let original = "ＡＢＣ 電話０９０ー１２３４ー５６７８\n次の行ＸＹＺ\n";
        let normalized = normalize(original);
        let start = normalized.find("090").unwrap();
        let mut tracked = Tracked::new(&normalized, true);
        tracked.apply(&[(
            start,
            start + "090-1234-5678".len(),
            "***-***-5678".to_string(),
        )]);
        let restored = tracked.restore(original);
        // Unmasked chars (the dashes and last four digits) keep their original width.
        assert_eq!(restored, "ＡＢＣ 電話***ー***ー５６７８\n次の行ＸＹＺ\n");
    }
}
