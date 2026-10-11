//! Masking behavior.

use piip::config::{FileConfig, Settings};
use piip::masker::Masker;

fn mask(text: &str) -> String {
    let settings = Settings::default();
    Masker::new(&settings).mask_text(text)
}

fn mask_with(types: &[(&str, bool)], text: &str) -> String {
    let mut settings = Settings::default();
    for (t, on) in types {
        settings.types.insert(t.to_string(), *on);
    }
    Masker::new(&settings).mask_text(text)
}

#[test]
fn readme_examples() {
    let cases = [
        ("example@domain.com", "e***@domain.com"),
        ("東京都新宿区西新宿2-8-1", "東京都***"),
        ("〒123-4567", "〒***-****"),
        ("4532-1234-5678-9014", "****-****-****-9014"),
        ("password: xxxx", "password: [REDACTED]"),
        ("パスワードは hunter22", "パスワードは [REDACTED]"),
        ("PW: abcd1234", "PW: [REDACTED]"),
        ("生年月日: 1990-01-15", "生年月日: ****-**-**"),
        ("口座番号: 1234567", "口座番号: ***4567"),
        ("お名前：山田 太郎", "お名前：山* 太*"),
        ("横浜市中区山下町1-2-3", "横浜市中区***"),
        ("192.168.1.1", "192.***.***.1"),
        ("2001:db8::8a2e:370:7334", "2001:db8:***"),
    ];
    for (input, expected) in cases {
        assert_eq!(mask(input), expected, "input: {input}");
    }
}

#[test]
fn self_introduction_is_opt_in() {
    assert_eq!(mask("山田太郎と申します"), "山田太郎と申します");
    assert_eq!(
        mask_with(&[("name_text", true)], "山田太郎と申します"),
        "山***と申します"
    );
    // Company introductions are not names.
    assert_eq!(
        mask_with(&[("name_text", true)], "株式会社テストと申します"),
        "株式会社テストと申します"
    );
}

#[test]
fn full_width_input_keeps_width_outside_masks() {
    assert_eq!(
        mask("ｔａｒｏ＠ｅｘａｍｐｌｅ．ｊｐ"),
        "ｔ***＠ｅｘａｍｐｌｅ．ｊｐ"
    );
    assert_eq!(
        mask("電話 ０９０－１２３４－５６７８"),
        "電話 ***－***－５６７８"
    );
}

#[test]
fn place_mentions_and_technical_text_are_left_alone() {
    for text in [
        "東京都に行きました",
        "千葉県産の野菜",
        "変数の名前: foo",
        "会議は 10:30:00 に開始",
        "パスワードは忘れました",
        "Bearer authentication",
        "C++ の std::vector::push_back",
    ] {
        assert_eq!(mask(text), text);
    }
}

#[test]
fn validation_rejects_invalid_numbers() {
    // Fails Luhn.
    assert!(!mask("4532-1234-5678-9015").starts_with("****-****-****"));
    // My Number check digit.
    assert_eq!(mask("1234 5678 9018"), "****-****-9018");
    assert_ne!(mask("1234 5678 9019"), "****-****-9019");
    // SSN area 000 is invalid.
    assert_eq!(mask("SSN 123-45-6789"), "SSN ***-**-6789");
    assert!(!mask("SSN 000-45-6789").contains("***-**-6789"));
}

#[test]
fn secrets() {
    assert_eq!(
        mask("define( 'DB_PASSWORD', 'S3cr3t' );"),
        "define( 'DB_PASSWORD', '[REDACTED]' );"
    );
    assert_eq!(mask("DB_PASSWORD=getenv('X')"), "DB_PASSWORD=getenv('X')");
    assert_eq!(
        mask("curl -u admin:pa55 https://x"),
        "curl -u admin:[REDACTED] https://x"
    );
    assert_eq!(
        mask("https://user:pw@example.com"),
        "https://user:***@example.com"
    );
    assert_eq!(
        mask("Authorization: Basic dXNlcjpwYXNz"),
        "Authorization: Basic dXNl***"
    );
    assert_eq!(
        mask("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),
        "ghp_********************************6789"
    );
    assert_eq!(
        mask("https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX"),
        "https://hooks.slack.com/***"
    );
    let key = format!("sk-ant-api03-{}", "aB3_cD4-eF".repeat(9) + "gH5AA");
    assert!(
        mask(&key).starts_with("sk-a****"),
        "anthropic key: {}",
        mask(&key)
    );
    let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----";
    assert_eq!(mask(pem), "[REDACTED]");
}

#[test]
fn inquiry_form() {
    let text = "お名前：山田 太郎 様\n電話番号：03-1234-5678\n会員番号：AB123456\n有効期限：12/27\nセキュリティコード：123";
    assert_eq!(
        mask(text),
        "お名前：山* 太* 様\n電話番号：***-***-5678\n会員番号：A***\n有効期限：**/**\nセキュリティコード：***"
    );
}

#[test]
fn disabled_types_are_kept() {
    assert_eq!(mask_with(&[("ip", false)], "192.168.1.1"), "192.168.1.1");
    assert_eq!(
        mask_with(&[("email", false)], "a@example.com 090-1234-5678"),
        "a@example.com ***-***-5678"
    );
}

#[test]
fn custom_patterns_and_consent() {
    let cfg: FileConfig = toml::from_str(
        r#"
        consent_phrases = ["公開OK"]
        [[custom_patterns]]
        label = "社員番号"
        pattern = 'EMP-\d{6}'
        replacement = "EMP-<******>"
        "#,
    )
    .unwrap();
    let settings = Settings::from_file_config(cfg).unwrap();
    let masker = Masker::new(&settings);
    // Unsafe HTML characters are stripped from replacements.
    assert_eq!(masker.mask_text("担当 EMP-123456"), "担当 EMP-******");
    assert!(settings.has_consent_phrase("これは公開OKです"));
    assert!(!settings.has_consent_phrase("I consent to unmasking"));
}

#[test]
fn field_based_masking() {
    let settings = Settings::default();
    let m = Masker::new(&settings);
    assert_eq!(m.mask_value("password", "hunter2"), "[REDACTED]");
    assert_eq!(m.mask_value("email", "taro@example.jp"), "t***@example.jp");
    assert_eq!(m.mask_value("full_name", "Taro Yamada"), "T*** Y*****");
    assert_eq!(m.mask_value("remote_addr", "203.0.113.5"), "203.***.***.5");
    assert_eq!(m.mask_value("server_id", "xs123456"), "xs***456");
    assert_eq!(
        m.mask_value("api_key", "abcdefghijklmnopqrstuvwxyz123456"),
        "abcd************************3456"
    );
    assert_eq!(m.mask_value("note", "hello"), "hello");
}

#[test]
fn scan_reports_positions_without_duplicates() {
    let settings = Settings::default();
    let m = Masker::new(&settings);
    let text = "電話：090-1234-5678\nmail: a@example.com";
    let found = m.find_all(text);
    let rules: Vec<&str> = found.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rules, ["contact_phone", "email"]);
    assert_eq!(found[0].start, 3);
    assert_eq!(found[1].masked, "a***@example.com");
}

#[test]
fn numbers_do_not_span_lines() {
    // 1234 5678 2026 10 happens to pass the Luhn check.
    assert_eq!(
        mask("tel 090-1234-5678\n2026-10-01 order ok"),
        "tel ***-***-5678\n2026-10-01 order ok"
    );
    assert_eq!(
        mask("カード 4532 1234 5678 9014"),
        "カード ****-****-****-9014"
    );
}

#[test]
fn eval_regressions() {
    let cases = [
        // Full-width space after a Japanese label.
        ("お名前　山田 太郎", "お名前　山* 太*"),
        ("お名前 を入力してください", "お名前 を入力してください"),
        // Landlines have 10 digits; 12 digits is some other number.
        (
            "お問い合わせ番号 0123-4567-8901",
            "お問い合わせ番号 0123-4567-8901",
        ),
        ("Invoice INV-01234567", "Invoice INV-01234567"),
        // Cities without the prefecture, but not 市内.
        ("川越市脇田町662-9", "川越市***"),
        ("大阪市内2-3日で届きます", "大阪市内2-3日で届きます"),
        // GUIDs only in Azure context.
        (
            "request_id 1b4e28ba-2fa1-41d2-883f-0016d3cca427",
            "request_id 1b4e28ba-2fa1-41d2-883f-0016d3cca427",
        ),
        (
            "AZURE_TENANT_ID=1b4e28ba-2fa1-41d2-883f-0016d3cca427",
            "AZURE_TENANT_ID=****-****-****-****-0016d3cca427",
        ),
        // Real passwords may start with %; %VAR% is a placeholder.
        ("DB_PASSWORD=%tH0keH%%uY8Gn", "DB_PASSWORD=[REDACTED]"),
        ("DB_PASSWORD=%DB_PASS%", "DB_PASSWORD=%DB_PASS%"),
    ];
    for (input, expected) in cases {
        assert_eq!(mask(input), expected, "input: {input}");
    }
    // A Slack token keeps its digits away from the My Number rule.
    // Built at run time so the fake token does not trip secret scanners.
    let token = ["xox", "b-674537383454-2349903409556-", &"6dZKqEuATtLr".repeat(2)].concat();
    let slack = mask(&format!("key: {token}"));
    assert!(
        slack.starts_with("key: xoxb") && !slack.contains("674537"),
        "{slack}"
    );
}
