//! Layer 1 — Hardware MMIO address normalization, bitmask classification,
//! and fast register/linker construct extraction.

use crate::model::{ArchLayer, ExtractedMacro, FileScope, MacroKind, RawXrefSite};
use regex::Regex;
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

/// Classifies `#define` macros and `const` declarations into domain categories.
pub fn classify_macro_value(
    name: &str,
    raw_value: &str,
    is_fn_like: bool,
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

    // 1. Check MMIO address
    let is_mmio_range = hex_val.is_some_and(|v| {
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

/// Scans source text line-by-line for hardware peripheral struct register dereferences
/// (`PERIPH->REG`), volatile MMIO pointer dereferences, and linker section placement attributes.
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

    let periph_re = PERIPH_REG_RE.get_or_init(|| {
        Regex::new(r"\b([A-Z][A-Z0-9_]{2,})->([A-Z][A-Z0-9_]{1,})\b")
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
        Regex::new(r"#\[\s*(interrupt|exception)\b[^\]]*\]").expect("valid rust interrupt regex")
    });

    let mut macros = Vec::new();
    let mut xrefs = Vec::new();
    let mut in_block_comment = false;

    for (idx, raw_line) in source.lines().enumerate() {
        let line_num = idx + 1;
        let active_line = strip_line_comments(raw_line, &mut in_block_comment);
        let trimmed = active_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Skip preprocessor #define lines for PERIPH->REG so macro definitions themselves
        // are not duplicated as runtime register access sites.
        let is_define_line =
            trimmed.starts_with('#') && trimmed[1..].trim_start().starts_with("define");

        if !is_define_line && memchr::memmem::find(trimmed.as_bytes(), b"->").is_some() {
            for caps in periph_re.captures_iter(trimmed) {
                let periph = &caps[1];
                let reg = &caps[2];
                let full_access = format!("{periph}->{reg}");
                let hex_addr = normalize_hex_literal(trimmed);

                macros.push(ExtractedMacro {
                    name: full_access.clone(),
                    kind: MacroKind::RegisterAccess,
                    value_or_args: trimmed.to_string(),
                    hex_addr,
                    file: rel_path.to_string(),
                    line: line_num,
                    scope,
                    arch_layer,
                    section_id: section_id.to_string(),
                    description: format!("Hardware register access {periph}->{reg}"),
                });

                xrefs.push(RawXrefSite {
                    file: rel_path.to_string(),
                    line: line_num,
                    enclosing_symbol: None,
                    target_name: full_access,
                    category: "mmio_access".to_string(),
                    context: trimmed.to_string(),
                });
            }
        }

        // Check volatile MMIO pointer dereferences
        if !is_define_line && memchr::memmem::find(trimmed.as_bytes(), b"volatile").is_some() {
            for caps in volatile_re.captures_iter(trimmed) {
                let raw_target = &caps[1];
                let hex_addr = normalize_hex_literal(raw_target);
                let target_name = hex_addr.clone().unwrap_or_else(|| raw_target.to_string());

                macros.push(ExtractedMacro {
                    name: target_name.clone(),
                    kind: MacroKind::RegisterAccess,
                    value_or_args: trimmed.to_string(),
                    hex_addr,
                    file: rel_path.to_string(),
                    line: line_num,
                    scope,
                    arch_layer,
                    section_id: section_id.to_string(),
                    description: "Volatile MMIO pointer dereference".to_string(),
                });

                xrefs.push(RawXrefSite {
                    file: rel_path.to_string(),
                    line: line_num,
                    enclosing_symbol: None,
                    target_name,
                    category: "mmio_access".to_string(),
                    context: trimmed.to_string(),
                });
            }
        }

        // Check GCC/Clang __attribute__((section("...")))
        if memchr::memmem::find(trimmed.as_bytes(), b"section").is_some() {
            for caps in attr_section_re.captures_iter(trimmed) {
                let sec_name = caps[1].to_string();
                macros.push(ExtractedMacro {
                    name: sec_name.clone(),
                    kind: MacroKind::LinkerSection,
                    value_or_args: trimmed.to_string(),
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
                    context: trimmed.to_string(),
                });
            }

            for caps in rust_link_re.captures_iter(trimmed) {
                let sec_name = caps[1].to_string();
                macros.push(ExtractedMacro {
                    name: sec_name.clone(),
                    kind: MacroKind::LinkerSection,
                    value_or_args: trimmed.to_string(),
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
                    context: trimmed.to_string(),
                });
            }
        }

        // Check Rust #[interrupt] / #[exception]
        if memchr::memmem::find(trimmed.as_bytes(), b"#[").is_some() {
            for caps in rust_intr_re.captures_iter(trimmed) {
                let attr_kind = &caps[1];
                let attr_name = format!("#[{attr_kind}]");
                macros.push(ExtractedMacro {
                    name: attr_name.clone(),
                    kind: MacroKind::LinkerSection,
                    value_or_args: trimmed.to_string(),
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
                    context: trimmed.to_string(),
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
                i += 1;
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
    }

    #[test]
    fn test_classify_macro_value() {
        let (kind, hex, _) = classify_macro_value("VENDOR_ADC1_BASE", "0x40012000UL", false);
        assert_eq!(kind, MacroKind::MmioAddress);
        assert_eq!(hex.as_deref(), Some("0x40012000"));

        let (kind2, hex2, _) = classify_macro_value("ADC_CR_ADEN", "(1UL << 0)", false);
        assert_eq!(kind2, MacroKind::Bitmask);
        assert!(hex2.is_none());

        let (kind3, hex3, _) = classify_macro_value("TIM_SR_UIF_MSK", "0x0001U", false);
        assert_eq!(kind3, MacroKind::Bitmask);
        assert_eq!(hex3.as_deref(), Some("0x1"));

        let (kind4, _, _) = classify_macro_value("CLAMP", "(x, lo, hi)", true);
        assert_eq!(kind4, MacroKind::FunctionMacro);
    }

    #[test]
    fn test_extract_mmio_and_linker_constructs() {
        let src = r#"
// Comment mentioning FAKE_TIM1->CCR1 should be ignored
__attribute__((section(".ramfunc")))
void motor_set_pwm(uint32_t duty) {
    VENDOR_TIM1->CCR1 = duty;
    GPIOA->BSRR = (1U << 5);
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
        assert!(macros
            .iter()
            .any(|m| m.kind == MacroKind::RegisterAccess && m.name == "VENDOR_TIM1->CCR1"));
        assert!(macros
            .iter()
            .any(|m| m.kind == MacroKind::RegisterAccess && m.name == "GPIOA->BSRR"));
        assert!(macros
            .iter()
            .any(|m| m.kind == MacroKind::RegisterAccess && m.name == "0x40021000"));
        assert!(xrefs
            .iter()
            .any(|x| x.category == "mmio_access" && x.target_name == "VENDOR_TIM1->CCR1"));
    }
}
