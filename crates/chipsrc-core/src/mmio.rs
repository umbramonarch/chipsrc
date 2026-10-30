//! Layer 1 — Hardware MMIO address normalization, bitmask classification,
//! and fast register/linker construct extraction.

use crate::model::{
    ArchLayer, ExtractedMacro, FileScope, LanguageKind, MacroKind, RawXrefSite, RepoBlueprint,
};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

/// Normalizes C/C++/Rust/datasheet hexadecimal literals into canonical `"0x..."` form.
///
/// Examples:
/// - `"0x41C0_0004UL"` -> `Some("0x41C00004")`
/// - `"0x40000000"` -> `Some("0x40000000")`
/// - `"0X0004"` -> `Some("0x4")`
/// - `"400h"` -> `Some("0x400")`
pub fn normalize_hex_literal(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Strip balanced outer parentheses if present
    let mut token = trimmed;
    while token.starts_with('(') && token.ends_with(')') && token.len() >= 2 {
        let inner = token[1..token.len() - 1].trim();
        if inner.is_empty() {
            break;
        }
        token = inner;
    }

    // Never extract hex literals from inside string or character literals
    if token.starts_with('"')
        || token.starts_with('\'')
        || token.starts_with("r\"")
        || token.starts_with("r#")
        || token.starts_with("b\"")
        || token.starts_with("b'")
    {
        return None;
    }

    // Case 1: Direct 0x / 0X prefix
    if let Some(rest) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        if let Some(norm) = parse_hex_body_and_suffix(rest) {
            return Some(norm);
        }
    }

    // Case 2: Trailing 'h' or 'H' datasheet notation (e.g., "400h", "0400H", "41C0_0004h")
    if (token.ends_with('h') || token.ends_with('H')) && token.len() >= 2 {
        let body = &token[..token.len() - 1];
        // Require at least one decimal digit so plain words like "ah" or "eh" are not misclassified
        if body.bytes().any(|b| b.is_ascii_digit())
            && body.bytes().all(|b| b.is_ascii_hexdigit() || b == b'_')
        {
            if let Some(norm) = format_cleaned_hex_digits(body) {
                return Some(norm);
            }
        }
    }

    // Case 3: Search for an embedded 0x... literal inside a cast or expression
    // e.g. "((ADC_TypeDef *) 0x40012000UL)"
    static EMBEDDED_HEX_RE: OnceLock<Regex> = OnceLock::new();
    let re = EMBEDDED_HEX_RE.get_or_init(|| {
        Regex::new(r"(?i)\b0x([0-9a-f][0-9a-f_]*)(?:[ul]+|(?:u|i)(?:8|16|32|64|128|size))?\b")
            .expect("valid embedded hex regex")
    });

    if let Some(caps) = re.captures(token) {
        if let Some(m) = caps.get(1) {
            return format_cleaned_hex_digits(m.as_str());
        }
    }

    None
}

/// Normalizes explicit user CLI hex queries, accepting datasheet `<HEX>h` notation
/// even when the leading hex digit is `A`..`F` (e.g. `"FFh"` -> `"0xFF"`, `"deadbeefh"` -> `"0xDEADBEEF"`).
pub fn normalize_query_hex_literal(raw: &str) -> Option<String> {
    if let Some(norm) = normalize_hex_literal(raw) {
        return Some(norm);
    }

    let mut token = raw.trim();
    while token.starts_with('(') && token.ends_with(')') && token.len() >= 2 {
        let inner = token[1..token.len() - 1].trim();
        if inner.is_empty() {
            break;
        }
        token = inner;
    }

    if (token.ends_with('h') || token.ends_with('H')) && (3..=17).contains(&token.len()) {
        let body = &token[..token.len() - 1];
        let hex_count = body.bytes().filter(|b| b.is_ascii_hexdigit()).count();
        let lower_body = body.to_ascii_lowercase();
        let is_english_word = matches!(lower_body.as_str(), "eac" | "beac");
        if hex_count >= 2
            && !is_english_word
            && body.bytes().all(|b| b.is_ascii_hexdigit() || b == b'_')
        {
            return format_cleaned_hex_digits(body);
        }
    }

    None
}

fn parse_hex_body_and_suffix(rest: &str) -> Option<String> {
    if rest.is_empty() {
        return None;
    }
    let hex_end = rest
        .bytes()
        .take_while(|b| b.is_ascii_hexdigit() || *b == b'_')
        .count();
    if hex_end == 0 {
        return None;
    }
    let hex_part = &rest[..hex_end];
    let suffix = &rest[hex_end..];
    if !is_valid_int_suffix(suffix) {
        return None;
    }
    format_cleaned_hex_digits(hex_part)
}

fn is_valid_int_suffix(suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    if suffix
        .bytes()
        .all(|b| matches!(b, b'u' | b'U' | b'l' | b'L'))
    {
        return true;
    }
    matches!(
        suffix.to_ascii_lowercase().as_str(),
        "u8" | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
    )
}

fn format_cleaned_hex_digits(raw_digits: &str) -> Option<String> {
    let mut digits = String::with_capacity(raw_digits.len());
    for ch in raw_digits.chars() {
        if ch == '_' {
            continue;
        }
        if !ch.is_ascii_hexdigit() {
            return None;
        }
        digits.push(ch.to_ascii_uppercase());
    }
    if digits.is_empty() {
        return None;
    }

    // Keep 8-digit hardware addresses (e.g., 0x40000000, 0x08000000) intact when >= 0x0100_0000,
    // otherwise strip leading zeros so "0X0004" -> "0x4" and "0x0000" -> "0x0".
    if digits.len() == 8 {
        if let Ok(val) = u64::from_str_radix(&digits, 16) {
            if val >= 0x0100_0000 {
                return Some(format!("0x{digits}"));
            }
        }
    }

    let stripped = digits.trim_start_matches('0');
    if stripped.is_empty() {
        Some("0x0".to_string())
    } else {
        Some(format!("0x{stripped}"))
    }
}

fn parse_hex_u64(raw: &str) -> Option<u64> {
    let norm = normalize_hex_literal(raw)?;
    let digits = norm.strip_prefix("0x")?;
    u64::from_str_radix(digits, 16).ok()
}

fn is_non_hardware_magic_or_id_name(upper_name: &str) -> bool {
    let has_hw_anchor = upper_name.contains("BASE")
        || upper_name.contains("ADDR")
        || upper_name.contains("REG")
        || upper_name.contains("PERIPH")
        || upper_name.contains("MMIO");
    if has_hw_anchor {
        return false;
    }

    upper_name.split('_').any(|seg| {
        matches!(
            seg,
            "MAGIC"
                | "SIGNATURE"
                | "COOKIE"
                | "VERSION"
                | "VER"
                | "CRC"
                | "CRC16"
                | "CRC32"
                | "HASH"
                | "SEED"
                | "KEY"
                | "UUID"
                | "GUID"
                | "ID"
                | "TAG"
                | "TOKEN"
                | "COLOR"
                | "RGB"
                | "RGBA"
                | "ARGB"
                | "TIMEOUT"
                | "BAUD"
                | "FREQ"
                | "HZ"
        )
    })
}

/// Returns `true` when `val` is a 32-bit FourCC / ASCII magic constant (e.g. `0x50574D00` = `"PWM\0"`),
/// which happens to fall numerically in `0x4000_0000..=0x7FFF_FFFF` because `'@'..'~'` are `0x40..0x7E`.
fn is_ascii_fourcc_magic(val: u64) -> bool {
    if !(0x4000_0000..=0x7FFF_FFFF).contains(&val) {
        return false;
    }
    let bytes = (val as u32).to_be_bytes();
    // Leading byte must be an uppercase ASCII letter ('A'..'Z')
    if !bytes[0].is_ascii_uppercase() {
        return false;
    }
    // Second and third bytes must be ASCII alphanumeric or '_'/' ', and fourth byte either ASCII or NUL (`\0`)
    let valid_mid = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b' ';
    let valid_end = |b: u8| valid_mid(b) || b == 0;
    // Exclude values that end with `0x0000` (64 KiB aligned peripheral bases like `0x40010000` or `0x50000000`)
    if bytes[2] == 0 && bytes[3] == 0 {
        return false;
    }
    valid_mid(bytes[1]) && valid_mid(bytes[2]) && valid_end(bytes[3])
}

/// Classifies `#define` macros and `const` declarations into domain categories,
/// checking custom `mmio_ranges` from `.chipsrc.json` (`RepoBlueprint`) when provided.
pub fn classify_macro_value_with_blueprint(
    name: &str,
    raw_value: &str,
    is_fn_like: bool,
    blueprint: Option<&RepoBlueprint>,
) -> (MacroKind, Option<String>, String) {
    let trimmed_val = raw_value.trim();
    let upper_name = name.to_ascii_uppercase();
    let hex_addr = normalize_hex_literal(trimmed_val);
    let hex_val = hex_addr
        .as_deref()
        .and_then(|h| h.strip_prefix("0x"))
        .and_then(|d| u64::from_str_radix(d, 16).ok());

    let is_mask_name = upper_name.ends_with("_MSK")
        || upper_name.ends_with("_MASK")
        || upper_name.ends_with("_POS")
        || upper_name.ends_with("_BIT")
        || upper_name.ends_with("_SHIFT")
        || upper_name.ends_with("_EN")
        || upper_name.ends_with("_START")
        || upper_name.ends_with("_EOC")
        || upper_name.contains("_MASK_")
        || upper_name.contains("_MSK_");

    let is_addr_name = upper_name.ends_with("_BASE")
        || upper_name.ends_with("_ADDR")
        || upper_name.ends_with("_ADDRESS")
        || upper_name.ends_with("_OFFSET")
        || upper_name.ends_with("_BASE_ADDR")
        || upper_name.ends_with("_REG_ADDR");

    let has_periph_cast = trimmed_val.contains("_TypeDef")
        || trimmed_val.contains("volatile uint")
        || trimmed_val.contains("volatile u32")
        || (trimmed_val.contains("*(") && trimmed_val.contains("volatile"));

    let is_non_hw_magic = !is_addr_name
        && !has_periph_cast
        && (is_non_hardware_magic_or_id_name(&upper_name)
            || hex_val.is_some_and(is_ascii_fourcc_magic));

    // 0. Check custom MMIO ranges from `.chipsrc.json`
    if let (Some(bp), Some(v)) = (blueprint, hex_val) {
        if !is_mask_name && !is_non_hw_magic {
            if let Some(custom_range) = bp.mmio_ranges.iter().find(|r| {
                match (parse_hex_u64(&r.start), parse_hex_u64(&r.end)) {
                    (Some(s), Some(e)) => (s..=e).contains(&v),
                    _ => false,
                }
            }) {
                let desc = if custom_range.name.is_empty() {
                    "MMIO register/base address".to_string()
                } else {
                    format!("MMIO register/base address ({})", custom_range.name)
                };
                return (MacroKind::MmioAddress, hex_addr, desc);
            }
        }
    }

    // 1. Check MMIO address
    let is_mmio_range = !is_non_hw_magic
        && hex_val.is_some_and(|v| {
            (0x4000_0000..=0xFFFF_FFFF).contains(&v) && !(v == 0xFFFF_FFFF && is_mask_name)
        });

    if is_mmio_range
        || has_periph_cast
        || (is_addr_name && (hex_addr.is_some() || trimmed_val.contains("_BASE")))
    {
        return (
            MacroKind::MmioAddress,
            hex_addr,
            "MMIO register/base address".to_string(),
        );
    }

    // 2. Check Bitmask / shift constant
    let has_bit_shift = trimmed_val.contains("<<")
        || trimmed_val.contains("BIT(")
        || trimmed_val.contains("_BV(")
        || trimmed_val.contains("GENMASK(");

    let is_hex_bitmask = hex_val.is_some_and(|v| {
        if !is_fn_like && v > 0 && v < 0x4000_0000 {
            let direct_hex = trimmed_val.starts_with("0x")
                || trimmed_val.starts_with("0X")
                || trimmed_val.starts_with("(0x")
                || trimmed_val.starts_with("(0X");
            direct_hex && (v.is_power_of_two() || (v & (v + 1)) == 0)
        } else {
            false
        }
    });

    if has_bit_shift || is_mask_name || is_hex_bitmask {
        return (
            MacroKind::Bitmask,
            hex_addr,
            "Hardware bitmask / shift constant".to_string(),
        );
    }

    // 3. Function-like macro
    if is_fn_like {
        return (
            MacroKind::FunctionMacro,
            hex_addr,
            "Function-like macro".to_string(),
        );
    }

    // 4. Object macro / constant
    (
        MacroKind::ObjectMacro,
        hex_addr,
        "Object macro / compile-time constant".to_string(),
    )
}

/// Inspects tokens immediately before `match_start_byte` and immediately after `match_end_byte`
/// to classify whether a hardware register access (`PERIPH->REG` or `*(volatile ...)`) is a
/// write/mutation (`=`, `|=`, `&=`, `^=`, `+=`, `-=`, `<<=`, `>>=`, `++`, `--`) vs. a read.
pub fn is_register_write_in_line(
    line: &str,
    match_start_byte: usize,
    match_end_byte: usize,
) -> bool {
    let before = line
        .get(..match_start_byte)
        .unwrap_or("")
        .trim_end_matches(|c: char| c.is_whitespace() || c == '(');
    if before.ends_with("++") || before.ends_with("--") {
        return true;
    }

    let mut after = line
        .get(match_end_byte..)
        .unwrap_or("")
        .trim_start_matches(|c: char| c.is_whitespace() || c == ')');

    // Skip any additional `[...]` array subscripts or `.FIELD` chain segments after the match
    loop {
        let prev = after;
        if let Some(rest) = after.strip_prefix('[') {
            if let Some(close_pos) = rest.find(']') {
                after = rest[close_pos + 1..]
                    .trim_start_matches(|c: char| c.is_whitespace() || c == ')');
                continue;
            }
        }
        if let Some(rest) = after.strip_prefix('.') {
            let ident_len = rest
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count();
            if ident_len > 0 {
                after =
                    rest[ident_len..].trim_start_matches(|c: char| c.is_whitespace() || c == ')');
                continue;
            }
        }
        if after.len() == prev.len() {
            break;
        }
    }

    if after.starts_with("++")
        || after.starts_with("--")
        || after.starts_with("|=")
        || after.starts_with("&=")
        || after.starts_with("^=")
        || after.starts_with("+=")
        || after.starts_with("-=")
        || after.starts_with("*=")
        || after.starts_with("/=")
        || after.starts_with("%=")
        || after.starts_with("<<=")
        || after.starts_with(">>=")
    {
        return true;
    }

    if after.starts_with('=') && !after.starts_with("==") {
        return true;
    }

    false
}

/// Scans source text line-by-line for hardware peripheral struct register dereferences
/// (`PERIPH->REG` and nested `PERIPH->GROUP.REG[i]`), volatile MMIO pointer dereferences,
/// and linker section placement attributes.
pub fn extract_mmio_and_linker_constructs(
    rel_path: &str,
    source: &str,
    scope: FileScope,
    arch_layer: ArchLayer,
    section_id: &str,
) -> (Vec<ExtractedMacro>, Vec<RawXrefSite>) {
    static PERIPH_REG_RE: OnceLock<Regex> = OnceLock::new();
    static VOLATILE_MMIO_RE: OnceLock<Regex> = OnceLock::new();
    static ATTR_SECTION_RE: OnceLock<Regex> = OnceLock::new();
    static RUST_LINK_SECTION_RE: OnceLock<Regex> = OnceLock::new();
    static RUST_INTERRUPT_RE: OnceLock<Regex> = OnceLock::new();

    let lang = Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .and_then(LanguageKind::from_extension)
        .unwrap_or(LanguageKind::C);

    let is_c_cpp = matches!(lang, LanguageKind::C | LanguageKind::Cpp);
    let is_rust = lang == LanguageKind::Rust;
    if !is_c_cpp && !is_rust {
        return (Vec::new(), Vec::new());
    }

    let periph_re = PERIPH_REG_RE.get_or_init(|| {
        Regex::new(
            r"\b([A-Z][A-Z0-9_]{1,15})\s*->\s*([A-Z][A-Z0-9_]{1,24}(?:\s*\.\s*[A-Z][A-Z0-9_]{1,24})*)(?:\s*\[[^\]]*\])*",
        )
        .expect("valid periph->reg regex")
    });
    let volatile_re = VOLATILE_MMIO_RE.get_or_init(|| {
        Regex::new(
            r"\*\s*\(\s*volatile\s+[A-Za-z0-9_]+\s*\*\s*\)\s*(0[xX][0-9a-fA-F_]+[uUlL]*|[A-Z][A-Z0-9_]{2,})",
        )
        .expect("valid volatile mmio regex")
    });
    let attr_section_re = ATTR_SECTION_RE.get_or_init(|| {
        Regex::new(r#"__attribute__\s*\(\(\s*section\s*\(\s*"([^"]+)"\s*\)\s*\)\)"#)
            .expect("valid attribute section regex")
    });
    let rust_link_re = RUST_LINK_SECTION_RE.get_or_init(|| {
        Regex::new(r#"#\[\s*(?:unsafe\s*\(\s*)?link_section\s*=\s*"([^"]+)"\s*\)?\s*\]"#)
            .expect("valid rust link_section regex")
    });
    let rust_intr_re = RUST_INTERRUPT_RE.get_or_init(|| {
        Regex::new(r"^\s*#\[\s*(interrupt|exception)\b[^\]]*\]")
            .expect("valid rust interrupt regex")
    });

    let mut macros = Vec::new();
    let mut xrefs = Vec::new();
    let mut in_block_comment = false;
    let mut raw_string_hashes: Option<usize> = None;

    for (idx, raw_line) in source.lines().enumerate() {
        let line_num = idx + 1;
        let comment_stripped = strip_line_comments(raw_line, &mut in_block_comment);
        let trimmed_with_strings = comment_stripped.trim();
        if trimmed_with_strings.is_empty() {
            continue;
        }

        // Mask out string literals (including multi-line Rust raw strings `r#"..."#`)
        // so string constants and test fixtures never trigger fake register or attribute hits.
        let code_only = mask_string_literals(&comment_stripped, &mut raw_string_hashes);
        let code_trimmed = code_only.trim();
        if code_trimmed.is_empty() {
            continue;
        }

        // In Rust files, stop scanning once we enter an inline `#[cfg(test)]` module at the end of a file.
        if is_rust && code_trimmed.starts_with("#[cfg(test)]") {
            break;
        }

        // Skip preprocessor #define lines for PERIPH->REG so macro definitions themselves
        // are not duplicated as runtime register access sites.
        let is_define_line =
            code_trimmed.starts_with('#') && code_trimmed[1..].trim_start().starts_with("define");

        if is_c_cpp
            && !is_define_line
            && memchr::memmem::find(code_trimmed.as_bytes(), b"->").is_some()
        {
            for caps in periph_re.captures_iter(code_trimmed) {
                let Some(m0) = caps.get(0) else {
                    continue;
                };
                let periph = &caps[1];
                let raw_reg = &caps[2];
                let reg: String = raw_reg.chars().filter(|c| !c.is_whitespace()).collect();
                let full_access = format!("{periph}->{reg}");
                let hex_addr = normalize_hex_literal(code_trimmed);
                let is_write = is_register_write_in_line(code_trimmed, m0.start(), m0.end());
                let (category, description) = if is_write {
                    (
                        "mmio_write",
                        format!("Hardware register write {full_access}"),
                    )
                } else {
                    ("mmio_read", format!("Hardware register read {full_access}"))
                };

                macros.push(ExtractedMacro {
                    name: full_access.clone(),
                    kind: MacroKind::RegisterAccess,
                    value_or_args: trimmed_with_strings.to_string(),
                    hex_addr,
                    file: rel_path.to_string(),
                    line: line_num,
                    scope,
                    arch_layer,
                    section_id: section_id.to_string(),
                    description,
                });

                xrefs.push(RawXrefSite {
                    file: rel_path.to_string(),
                    line: line_num,
                    enclosing_symbol: None,
                    target_name: full_access,
                    category: category.to_string(),
                    context: trimmed_with_strings.to_string(),
                });
            }
        }

        // Check volatile MMIO pointer dereferences (C/C++)
        if is_c_cpp
            && !is_define_line
            && memchr::memmem::find(code_trimmed.as_bytes(), b"volatile").is_some()
        {
            for caps in volatile_re.captures_iter(code_trimmed) {
                let Some(m0) = caps.get(0) else {
                    continue;
                };
                let raw_target = &caps[1];
                let hex_addr = normalize_hex_literal(raw_target);
                let target_name = hex_addr.clone().unwrap_or_else(|| raw_target.to_string());
                let is_write = is_register_write_in_line(code_trimmed, m0.start(), m0.end());
                let (category, description) = if is_write {
                    ("mmio_write", "Volatile MMIO pointer write".to_string())
                } else {
                    ("mmio_read", "Volatile MMIO pointer read".to_string())
                };

                macros.push(ExtractedMacro {
                    name: target_name.clone(),
                    kind: MacroKind::RegisterAccess,
                    value_or_args: trimmed_with_strings.to_string(),
                    hex_addr,
                    file: rel_path.to_string(),
                    line: line_num,
                    scope,
                    arch_layer,
                    section_id: section_id.to_string(),
                    description,
                });

                xrefs.push(RawXrefSite {
                    file: rel_path.to_string(),
                    line: line_num,
                    enclosing_symbol: None,
                    target_name,
                    category: category.to_string(),
                    context: trimmed_with_strings.to_string(),
                });
            }
        }

        // Check GCC/Clang __attribute__((section("..."))) in C/C++
        if is_c_cpp && memchr::memmem::find(code_trimmed.as_bytes(), b"__attribute__").is_some() {
            for caps in attr_section_re.captures_iter(trimmed_with_strings) {
                let sec_name = caps[1].to_string();
                macros.push(ExtractedMacro {
                    name: sec_name.clone(),
                    kind: MacroKind::LinkerSection,
                    value_or_args: trimmed_with_strings.to_string(),
                    hex_addr: None,
                    file: rel_path.to_string(),
                    line: line_num,
                    scope,
                    arch_layer,
                    section_id: section_id.to_string(),
                    description: "Linker section placement attribute".to_string(),
                });
                xrefs.push(RawXrefSite {
                    file: rel_path.to_string(),
                    line: line_num,
                    enclosing_symbol: None,
                    target_name: sec_name,
                    category: "linker_section".to_string(),
                    context: trimmed_with_strings.to_string(),
                });
            }
        }

        // Check Rust #[link_section = "..."] and #[interrupt] / #[exception]
        if is_rust && code_trimmed.starts_with("#[") {
            if memchr::memmem::find(code_trimmed.as_bytes(), b"link_section").is_some() {
                for caps in rust_link_re.captures_iter(trimmed_with_strings) {
                    let sec_name = caps[1].to_string();
                    macros.push(ExtractedMacro {
                        name: sec_name.clone(),
                        kind: MacroKind::LinkerSection,
                        value_or_args: trimmed_with_strings.to_string(),
                        hex_addr: None,
                        file: rel_path.to_string(),
                        line: line_num,
                        scope,
                        arch_layer,
                        section_id: section_id.to_string(),
                        description: "Rust linker section attribute".to_string(),
                    });
                    xrefs.push(RawXrefSite {
                        file: rel_path.to_string(),
                        line: line_num,
                        enclosing_symbol: None,
                        target_name: sec_name,
                        category: "linker_section".to_string(),
                        context: trimmed_with_strings.to_string(),
                    });
                }
            }

            for caps in rust_intr_re.captures_iter(code_trimmed) {
                let attr_kind = &caps[1];
                let attr_name = format!("#[{attr_kind}]");
                macros.push(ExtractedMacro {
                    name: attr_name.clone(),
                    kind: MacroKind::LinkerSection,
                    value_or_args: trimmed_with_strings.to_string(),
                    hex_addr: None,
                    file: rel_path.to_string(),
                    line: line_num,
                    scope,
                    arch_layer,
                    section_id: section_id.to_string(),
                    description: "Interrupt/exception vector attribute".to_string(),
                });
                xrefs.push(RawXrefSite {
                    file: rel_path.to_string(),
                    line: line_num,
                    enclosing_symbol: None,
                    target_name: attr_name,
                    category: "linker_section".to_string(),
                    context: trimmed_with_strings.to_string(),
                });
            }
        }
    }

    (macros, xrefs)
}

/// Strips `//` and `/* ... */` comments from a single line while tracking multi-line block comment state.
fn strip_line_comments(line: &str, in_block_comment: &mut bool) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;

    while i < bytes.len() {
        if *in_block_comment {
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                *in_block_comment = false;
                i += 2;
            } else {
                let step = line[i..].chars().next().map_or(1, char::len_utf8);
                i += step;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            break;
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            *in_block_comment = true;
            i += 2;
        } else {
            let ch = line[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }

    out
}

/// Masks out string and character literals (including multi-line Rust raw strings `r#"..."#`)
/// with spaces of identical byte length so regexes do not match inside string literals.
fn mask_string_literals(line: &str, raw_string_hashes: &mut Option<usize>) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;

    while i < bytes.len() {
        if let Some(hashes) = *raw_string_hashes {
            if bytes[i] == b'"' {
                let mut matched = true;
                for h in 0..hashes {
                    if bytes.get(i + 1 + h) != Some(&b'#') {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    for _ in 0..=hashes {
                        out.push(' ');
                    }
                    i += 1 + hashes;
                    *raw_string_hashes = None;
                    continue;
                }
            }
            let step = line[i..].chars().next().map_or(1, char::len_utf8);
            out.push(' ');
            i += step;
            continue;
        }

        // Check for Rust raw string start `r"..."` or `r#"..."#`
        if bytes[i] == b'r'
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'))
        {
            let mut h = 0usize;
            while bytes.get(i + 1 + h) == Some(&b'#') {
                h += 1;
            }
            if bytes.get(i + 1 + h) == Some(&b'"') {
                for _ in 0..(2 + h) {
                    out.push(' ');
                }
                i += 2 + h;
                *raw_string_hashes = Some(h);
                continue;
            }
        }

        // Standard double-quoted string literal
        if bytes[i] == b'"' {
            out.push(' ');
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    out.push(' ');
                    i += 1;
                    if i < bytes.len() {
                        let step = line[i..].chars().next().map_or(1, char::len_utf8);
                        out.push(' ');
                        i += step;
                    }
                    continue;
                }
                if bytes[i] == b'"' {
                    out.push(' ');
                    i += 1;
                    break;
                }
                let step = line[i..].chars().next().map_or(1, char::len_utf8);
                out.push(' ');
                i += step;
            }
            continue;
        }

        let ch = line[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_hex_literal() {
        assert_eq!(
            normalize_hex_literal("0x41C0_0004UL"),
            Some("0x41C00004".to_string())
        );
        assert_eq!(
            normalize_hex_literal("0x40000000"),
            Some("0x40000000".to_string())
        );
        assert_eq!(normalize_hex_literal("0X0004"), Some("0x4".to_string()));
        assert_eq!(normalize_hex_literal("400h"), Some("0x400".to_string()));
        assert_eq!(
            normalize_hex_literal("((ADC_TypeDef *) 0x40012000UL)"),
            Some("0x40012000".to_string())
        );
        assert_eq!(normalize_hex_literal("not_a_hex"), None);
        assert_eq!(normalize_hex_literal("\"0x41C00004\""), None);

        // Query-time hex suffix normalization supports leading A-F
        assert_eq!(normalize_query_hex_literal("FFh"), Some("0xFF".to_string()));
        assert_eq!(
            normalize_query_hex_literal("deadbeefh"),
            Some("0xDEADBEEF".to_string())
        );
        assert_eq!(normalize_query_hex_literal("each"), None);
    }

    #[test]
    fn test_classify_macro_value() {
        let (kind, hex, _) =
            classify_macro_value_with_blueprint("VENDOR_ADC1_BASE", "0x40012000UL", false, None);
        assert_eq!(kind, MacroKind::MmioAddress);
        assert_eq!(hex.as_deref(), Some("0x40012000"));

        let (kind2, hex2, _) =
            classify_macro_value_with_blueprint("ADC_CR_ADEN", "(1UL << 0)", false, None);
        assert_eq!(kind2, MacroKind::Bitmask);
        assert!(hex2.is_none());

        let (kind3, hex3, _) =
            classify_macro_value_with_blueprint("TIM_SR_UIF_MSK", "0x0001U", false, None);
        assert_eq!(kind3, MacroKind::Bitmask);
        assert_eq!(hex3.as_deref(), Some("0x1"));

        let (kind4, _, _) = classify_macro_value_with_blueprint("CLAMP", "(x, lo, hi)", true, None);
        assert_eq!(kind4, MacroKind::FunctionMacro);

        // ASCII FourCC magic number 0x50574D00 ("PWM\0") must NOT be misclassified as MmioAddress
        let (kind_magic, hex_magic, _) =
            classify_macro_value_with_blueprint("MAGIC_MODULE_ID", "0x50574D00UL", false, None);
        assert_eq!(kind_magic, MacroKind::ObjectMacro);
        assert_eq!(hex_magic.as_deref(), Some("0x50574D00"));
    }

    #[test]
    fn test_extract_mmio_and_linker_constructs() {
        let src = r#"
// Comment mentioning FAKE_TIM1->CCR1 — UTF-8 check */ should be ignored
__attribute__((section(".ramfunc")))
void motor_set_pwm(uint32_t duty) {
    const char *msg = "FAKE_STR->REG = 1";
    VENDOR_TIM1->CCR1 = duty;
    IOMUX->SECCFG.PINCM[idx] |= 0x80U;
    TIMG2->CPU_INT.ICLR = 0xFFFFFFFFUL;
    if (VENDOR_TIM1->SR & 1U) {
        GPIOA->BSRR = (1U << 5);
    }
    *(volatile uint32_t *)0x40021000 = 0x1;
}
"#;
        let (macros, xrefs) = extract_mmio_and_linker_constructs(
            "fw/drvs/motor.c",
            src,
            FileScope::FirstParty,
            ArchLayer::Drivers,
            "fw-drvs",
        );

        assert!(macros
            .iter()
            .any(|m| m.kind == MacroKind::LinkerSection && m.name == ".ramfunc"));
        assert!(!macros.iter().any(|m| m.name.contains("FAKE_STR")));
        assert!(macros
            .iter()
            .any(|m| m.kind == MacroKind::RegisterAccess && m.name == "VENDOR_TIM1->CCR1"));
        assert!(macros
            .iter()
            .any(|m| m.kind == MacroKind::RegisterAccess && m.name == "IOMUX->SECCFG.PINCM"));
        assert!(macros
            .iter()
            .any(|m| m.kind == MacroKind::RegisterAccess && m.name == "TIMG2->CPU_INT.ICLR"));
        assert!(macros
            .iter()
            .any(|m| m.kind == MacroKind::RegisterAccess && m.name == "GPIOA->BSRR"));
        assert!(macros
            .iter()
            .any(|m| m.kind == MacroKind::RegisterAccess && m.name == "0x40021000"));
        assert!(xrefs
            .iter()
            .any(|x| x.category == "mmio_write" && x.target_name == "VENDOR_TIM1->CCR1"));
        assert!(xrefs
            .iter()
            .any(|x| x.category == "mmio_write" && x.target_name == "IOMUX->SECCFG.PINCM"));
        assert!(xrefs
            .iter()
            .any(|x| x.category == "mmio_write" && x.target_name == "TIMG2->CPU_INT.ICLR"));
        assert!(xrefs
            .iter()
            .any(|x| x.category == "mmio_read" && x.target_name == "VENDOR_TIM1->SR"));
    }
}
