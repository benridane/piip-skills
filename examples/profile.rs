use std::time::Instant;
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let text = piip::patterns::normalize(&std::fs::read_to_string(path).unwrap());
    let mut rows = Vec::new();
    for rule in piip::patterns::RULES.iter() {
        let t = Instant::now();
        let n = rule.re.captures_all(&text).map(|m| m.len()).unwrap_or(0);
        rows.push((t.elapsed().as_secs_f64() * 1000.0, rule.id.clone(), n));
    }
    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    let total: f64 = rows.iter().map(|r| r.0).sum();
    println!("total {total:.0} ms");
    for (ms, id, n) in rows.iter().take(12) {
        println!("{ms:8.1} ms  {id} ({n})");
    }
    let s = piip::config::Settings::default();
    let t = Instant::now();
    let m = piip::masker::Masker::new(&s)
        .mask_text(&std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap());
    println!(
        "mask_text {:.0} ms ({} bytes)",
        t.elapsed().as_secs_f64() * 1000.0,
        m.len()
    );
}
