//! Delimited regular expressions (`/foo/iu`) on top of PCRE2.
//!
//! Rules are written as delimited patterns with trailing flags. PCRE2 gives
//! lookbehinds, backreferences, `(?-i:...)` and, without /u, ASCII-only
//! `\b`/`\d`, which several rules rely on.

use std::ffi::c_int;
use std::ptr;

use pcre2_sys::*;

/// Capture group spans (byte offsets) of one match; index 0 is the whole match.
pub type Groups = Vec<Option<(usize, usize)>>;

const PCRE2_UNSET: usize = usize::MAX;

/// A compiled PCRE2 pattern.
///
/// A thin wrapper over pcre2-sys instead of the `pcre2` crate: subjects are
/// `&str` (always valid UTF-8) and matching always starts on a character
/// boundary, so PCRE2_NO_UTF_CHECK is safe. Without it PCRE2 validates the
/// whole subject on every call, which makes each match O(n).
pub struct Re {
    code: *mut pcre2_code_8,
}

// SAFETY: a compiled pattern (including its JIT code) is read-only after
// compilation and may be shared between threads; match data is per call.
unsafe impl Send for Re {}
unsafe impl Sync for Re {}

impl Drop for Re {
    fn drop(&mut self) {
        // SAFETY: `code` came from pcre2_compile_8 and is freed once.
        unsafe { pcre2_code_free_8(self.code) }
    }
}

/// Per-thread match context with a JIT stack big enough for the lazy,
/// alternation-heavy label patterns. Shared by all patterns on the thread
/// (a JIT stack may be reused, just not concurrently).
struct JitContext {
    context: *mut pcre2_match_context_8,
    stack: *mut pcre2_jit_stack_8,
}

impl JitContext {
    fn new() -> Self {
        // SAFETY: plain allocations from PCRE2; checked below.
        unsafe {
            let context = pcre2_match_context_create_8(ptr::null_mut());
            let stack = pcre2_jit_stack_create_8(32 * 1024, 8 * 1024 * 1024, ptr::null_mut());
            assert!(
                !context.is_null() && !stack.is_null(),
                "PCRE2 allocation failed"
            );
            pcre2_jit_stack_assign_8(context, None, stack.cast());
            JitContext { context, stack }
        }
    }
}

impl Drop for JitContext {
    fn drop(&mut self) {
        // SAFETY: both pointers were created in new() and are freed once.
        unsafe {
            pcre2_match_context_free_8(self.context);
            pcre2_jit_stack_free_8(self.stack);
        }
    }
}

thread_local! {
    static JIT_CONTEXT: JitContext = JitContext::new();
}

/// Per-call match data (ovector sized for the pattern).
struct MatchState {
    data: *mut pcre2_match_data_8,
}

impl Drop for MatchState {
    fn drop(&mut self) {
        // SAFETY: created by pcre2_match_data_create_from_pattern_8.
        unsafe { pcre2_match_data_free_8(self.data) }
    }
}

fn error_message(code: c_int) -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer and its length are valid.
    let len = unsafe { pcre2_get_error_message_8(code, buf.as_mut_ptr(), buf.len()) };
    if len < 0 {
        return format!("PCRE2 error {code}");
    }
    String::from_utf8_lossy(&buf[..len as usize]).into_owned()
}

impl Re {
    /// Compile a delimited pattern such as `/foo/iu` or `#bar#i`.
    ///
    /// Flags: i (caseless), m (multi-line), s (dotall), x (extended),
    /// u (Unicode properties, PCRE2_UCP).
    /// Subjects are always valid UTF-8 (`&str`), so UTF mode is always on;
    /// without /u, `\b`, `\d`, `\s` and `\w` stay ASCII-only.
    pub fn delimited(src: &str) -> Result<Re, String> {
        let delim = src.chars().next().ok_or("empty pattern")?;
        let body = &src[delim.len_utf8()..];
        let end = body
            .rfind(delim)
            .ok_or_else(|| format!("missing closing delimiter in {src}"))?;
        let pattern = &body[..end];
        let flags = &body[end + delim.len_utf8()..];

        let mut options = PCRE2_UTF;
        for flag in flags.chars() {
            options |= match flag {
                'i' => PCRE2_CASELESS,
                'm' => PCRE2_MULTILINE,
                's' => PCRE2_DOTALL,
                'x' => PCRE2_EXTENDED,
                'u' => PCRE2_UCP,
                other => return Err(format!("unsupported regex flag '{other}' in {src}")),
            };
        }
        Re::compile(pattern, options).map_err(|e| format!("{src}: {e}"))
    }

    /// Compile a bare pattern (no delimiters) with /u semantics.
    pub fn unicode(pattern: &str) -> Result<Re, String> {
        Re::compile(pattern, PCRE2_UTF | PCRE2_UCP).map_err(|e| format!("{pattern}: {e}"))
    }

    fn compile(pattern: &str, options: u32) -> Result<Re, String> {
        let mut error_code: c_int = 0;
        let mut error_offset: usize = 0;
        // SAFETY: pattern pointer/length are valid for the call.
        let code = unsafe {
            pcre2_compile_8(
                pattern.as_ptr(),
                pattern.len(),
                options,
                &mut error_code,
                &mut error_offset,
                ptr::null_mut(),
            )
        };
        if code.is_null() {
            return Err(format!(
                "{} at offset {error_offset}",
                error_message(error_code)
            ));
        }
        // JIT is an optimization: the interpreter is used if it fails.
        // SAFETY: `code` is a valid compiled pattern.
        unsafe { pcre2_jit_compile_8(code, PCRE2_JIT_COMPLETE) };
        Ok(Re { code })
    }

    fn match_state(&self) -> MatchState {
        // SAFETY: allocation sized from this pattern; checked below.
        let data = unsafe { pcre2_match_data_create_from_pattern_8(self.code, ptr::null_mut()) };
        assert!(!data.is_null(), "PCRE2 allocation failed");
        MatchState { data }
    }

    /// Match at `start` (a char boundary). Ok(None) = no match.
    fn match_at(
        &self,
        state: &MatchState,
        subject: &str,
        start: usize,
    ) -> Result<Option<Groups>, c_int> {
        // SAFETY: subject is valid UTF-8 and `start` is a char boundary, which
        // is what PCRE2_NO_UTF_CHECK requires; match data fits the pattern.
        let rc = JIT_CONTEXT.with(|jit| unsafe {
            pcre2_match_8(
                self.code,
                subject.as_ptr(),
                subject.len(),
                start,
                PCRE2_NO_UTF_CHECK,
                state.data,
                jit.context,
            )
        });
        if rc == PCRE2_ERROR_NOMATCH {
            return Ok(None);
        }
        if rc < 0 {
            return Err(rc);
        }
        // SAFETY: the ovector holds `count` pairs for this match data.
        let ovector = unsafe {
            let count = pcre2_get_ovector_count_8(state.data) as usize;
            std::slice::from_raw_parts(pcre2_get_ovector_pointer_8(state.data), count * 2)
        };
        Ok(Some(
            ovector
                .chunks(2)
                .map(|p| (p[0] != PCRE2_UNSET).then_some((p[0], p[1])))
                .collect(),
        ))
    }

    pub fn is_match(&self, subject: &str) -> bool {
        self.find(subject).is_some()
    }

    /// First match span.
    pub fn find(&self, subject: &str) -> Option<(usize, usize)> {
        let state = self.match_state();
        self.match_at(&state, subject, 0)
            .ok()
            .flatten()
            .and_then(|g| g[0])
    }

    /// All non-overlapping matches with their groups.
    ///
    /// Returns None when PCRE2 reports an error (match limit etc.); callers
    /// then leave the text untouched.
    pub fn captures_all(&self, subject: &str) -> Option<Vec<Groups>> {
        let state = self.match_state();
        let mut out = Vec::new();
        let mut pos = 0;
        let mut last_end: Option<usize> = None;

        while pos <= subject.len() {
            let groups = match self.match_at(&state, subject, pos) {
                Ok(Some(g)) => g,
                Ok(None) => break,
                Err(_) => return None,
            };
            let m = groups[0].expect("group 0 always matches");

            if m.0 == m.1 && Some(m.1) == last_end {
                pos = next_char_boundary(subject, m.1);
                continue;
            }

            out.push(groups);
            last_end = Some(m.1);
            pos = if m.0 == m.1 {
                next_char_boundary(subject, m.1)
            } else {
                m.1
            };
        }

        Some(out)
    }

    /// preg_replace_callback: replace every match with `f(subject, groups)`.
    pub fn replace_all<F>(&self, subject: &str, mut f: F) -> Option<String>
    where
        F: FnMut(&str, &Groups) -> String,
    {
        let matches = self.captures_all(subject)?;
        if matches.is_empty() {
            return Some(subject.to_string());
        }

        let mut out = String::with_capacity(subject.len());
        let mut last = 0;
        for groups in &matches {
            let (start, end) = groups[0].expect("group 0 always matches");
            out.push_str(&subject[last..start]);
            out.push_str(&f(subject, groups));
            last = end;
        }
        out.push_str(&subject[last..]);

        Some(out)
    }
}

fn next_char_boundary(s: &str, pos: usize) -> usize {
    if pos >= s.len() {
        return pos + 1;
    }
    let mut next = pos + 1;
    while next < s.len() && !s.is_char_boundary(next) {
        next += 1;
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_word_boundary_without_u() {
        // Without /u, Japanese characters are not word characters.
        let re = Re::delimited(r"/\b0[5789]0[-\s]?\d{4}[-\s]?\d{4}\b/").unwrap();
        assert!(re.is_match("電話09012345678です"));
    }

    #[test]
    fn unicode_word_boundary_with_u() {
        let re = Re::delimited(r"/\btest\b/u").unwrap();
        assert!(!re.is_match("漢test"));
        let re = Re::delimited(r"/\btest\b/").unwrap();
        assert!(re.is_match("漢test"));
    }

    #[test]
    fn empty_matches_advance_by_char() {
        let re = Re::delimited("/x*/u").unwrap();
        let out = re.replace_all("あxい", |_, _| "-".to_string()).unwrap();
        assert_eq!(out, "-あ-い-");
    }
}
