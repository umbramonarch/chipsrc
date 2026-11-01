//! Layer 1 — Multi-language Tree-sitter CST parser and incremental AST extractor.
//!
//! Supports C, C++, Rust, Python, TypeScript, TSX, JavaScript, and JSX.
//! Extracts symbols, types, macros/constants, MMIO register accesses, imports,
//! call sites, and cross-reference sites in a single pass per file.

use crate::error::{ChipsrcError, Result};
use crate::mmio::{classify_macro_value_with_blueprint, extract_mmio_and_linker_constructs};
use crate::model::{
    ArchLayer, ExtractedImport, ExtractedMacro, ExtractedSymbol, ExtractedType, FileScope,
    IncrementalAstCache, LanguageKind, MacroKind, ParsedFileUnit, RawCallSite, RawXrefSite,
    RepoBlueprint, ScannedFile, SymbolKind, TypeKind, Visibility,
};
use crate::scanner::assign_section_id_with_blueprint;
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs;
use tree_sitter::{Language, Node, Parser};

thread_local! {
    static THREAD_PARSERS: RefCell<FxHashMap<LanguageKind, Parser>> =
        RefCell::new(FxHashMap::default());
}

/// Maximum number of struct fields or enum variants included in `fields_summary` before
/// appending `, ... (+N more)`.
const MAX_TYPE_SUMMARY_ITEMS: usize = 16;

/// Parses all `scanned_files` with an optional `.chipsrc.json` [`RepoBlueprint`] and takes
/// `existing_cache` by value so unchanged entries are moved out via `.remove()` without deep cloning.
pub fn parse_files_incremental_with_blueprint(
    scanned_files: &[ScannedFile],
    existing_cache: Option<IncrementalAstCache>,
    blueprint: Option<&RepoBlueprint>,
) -> Result<(Vec<ParsedFileUnit>, usize, usize)> {
    let mut cache_map: std::collections::BTreeMap<String, ParsedFileUnit> =
        existing_cache.map(|c| c.files).unwrap_or_default();
    let mut reused_units = Vec::new();
    let mut to_parse = Vec::new();

    for scanned in scanned_files {
        let cached_hit = cache_map.remove(&scanned.rel_path).filter(|unit| {
            unit.scanned.size_bytes == scanned.size_bytes
                && unit.scanned.blake3_hash == scanned.blake3_hash
                && unit.scanned.scope == scanned.scope
                && unit.scanned.arch_layer == scanned.arch_layer
        });

        if let Some(mut unit) = cached_hit {
            unit.scanned = scanned.clone();
            reused_units.push(unit);
        } else {
            to_parse.push(scanned);
        }
    }

    let reused_count = reused_units.len();
    let reparsed_count = to_parse.len();

    let parsed_results: Vec<Result<ParsedFileUnit>> = to_parse
        .into_par_iter()
        .map(|s| parse_single_file_with_blueprint(s, blueprint))
        .collect();

    let mut all_units = Vec::with_capacity(reused_count + reparsed_count);
    all_units.extend(reused_units);
    for res in parsed_results {
        all_units.push(res?);
    }

    all_units.sort_by(|a, b| a.scanned.rel_path.cmp(&b.scanned.rel_path));
    Ok((all_units, reused_count, reparsed_count))
}

/// Parses a single `ScannedFile` from disk with an optional `.chipsrc.json` [`RepoBlueprint`].
pub fn parse_single_file_with_blueprint(
    scanned: &ScannedFile,
    blueprint: Option<&RepoBlueprint>,
) -> Result<ParsedFileUnit> {
    let raw_bytes =
        fs::read(&scanned.abs_path).map_err(|e| ChipsrcError::io(&scanned.abs_path, e))?;
    let source = String::from_utf8_lossy(&raw_bytes);
    parse_source_str_with_blueprint(scanned, &source, blueprint)
}

/// Parses an in-memory `source` string for a given `ScannedFile` descriptor.
#[cfg(test)]
pub fn parse_source_str(scanned: &ScannedFile, source: &str) -> Result<ParsedFileUnit> {
    parse_source_str_with_blueprint(scanned, source, None)
}

/// Parses an in-memory `source` string for a given `ScannedFile` descriptor with an optional
/// `.chipsrc.json` [`RepoBlueprint`].
pub fn parse_source_str_with_blueprint(
    scanned: &ScannedFile,
    source: &str,
    blueprint: Option<&RepoBlueprint>,
) -> Result<ParsedFileUnit> {
    let is_sfc = is_sfc_file(&scanned.rel_path);

    // Prepare a byte-length- and line-preserving parse buffer when needed:
    // - For C/C++: rewrite top-level uppercase qualifier/attribute macros to valid C keywords/spaces.
    // - For Single-File Components (`.astro`, `.vue`, `.svelte`): project frontmatter and
    //   `<script>` blocks into TSX while blanking template markup with spaces (`\n` preserved).
    let normalized_source = if is_sfc {
        Some(preprocess_sfc_to_tsx(source, &scanned.rel_path))
    } else {
        match scanned.language {
            LanguageKind::C | LanguageKind::Cpp => normalize_c_qualifier_macros(source, blueprint),
            _ => None,
        }
    };
    let parse_bytes: &[u8] = match normalized_source.as_deref() {
        Some(bytes) => bytes,
        None => source.as_bytes(),
    };

    let tree = THREAD_PARSERS.with(|cell| -> Result<tree_sitter::Tree> {
        let mut map = cell.borrow_mut();
        let parser = match map.entry(scanned.language) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                let mut p = Parser::new();
                let ts_lang = tree_sitter_language(scanned.language);
                p.set_language(&ts_lang)
                    .map_err(|e| ChipsrcError::ParserConfig(e.to_string()))?;
                v.insert(p)
            }
        };
        parser.parse(parse_bytes, None).ok_or_else(|| {
            ChipsrcError::ParserConfig(format!(
                "Tree-sitter returned None for {}",
                scanned.rel_path
            ))
        })
    })?;

    let (section_id, _, _) = assign_section_id_with_blueprint(
        &scanned.rel_path,
        scanned.scope,
        scanned.arch_layer,
        blueprint,
    );
    let lines: Vec<&str> = source.lines().collect();

    let mut ctx = ExtractContext {
        scanned,
        bytes: source.as_bytes(),
        lines: &lines,
        section_id: &section_id,
        blueprint,
        is_header: is_c_or_cpp_header(&scanned.rel_path),
        in_test_scope: scanned.scope == FileScope::Test,
        symbols: Vec::new(),
        header_prototypes: Vec::new(),
        types: Vec::new(),
        macros: Vec::new(),
        imports: Vec::new(),
        raw_calls: Vec::new(),
        raw_xrefs: Vec::new(),
        handled_type_ranges: HashSet::new(),
        local_var_types: FxHashMap::default(),
        local_collection_elem_types: FxHashMap::default(),
        local_vars: FxHashSet::default(),
        seen_fn_ptr_candidates: FxHashSet::default(),
        seen_field_xrefs: FxHashSet::default(),
        parse_errors: 0,
    };

    let root = tree.root_node();
    walk_ast(&mut ctx, root, None, None);

    if is_sfc {
        extract_sfc_component_and_template(&mut ctx, source);
    }

    // For C/C++ header files (.h / .hpp), include prototype declarations that do not already
    // have an inline function_definition in the same header.
    if ctx.is_header && !ctx.header_prototypes.is_empty() {
        let defined_names: HashSet<String> = ctx
            .symbols
            .iter()
            .map(|s| s.qualified_name.clone())
            .collect();
        for proto in ctx.header_prototypes.drain(..) {
            if !defined_names.contains(&proto.qualified_name) {
                ctx.symbols.push(proto);
            }
        }
    }

    // Run fast line-by-line MMIO & linker attribute scanner and merge results
    let (mmio_macros, mut mmio_xrefs) = extract_mmio_and_linker_constructs(
        &scanned.rel_path,
        source,
        scanned.scope,
        scanned.arch_layer,
        &section_id,
    );

    // Attribute MMIO / linker xrefs to their enclosing function if inside a function body
    for xref in &mut mmio_xrefs {
        if xref.enclosing_symbol.is_none() {
            if let Some(sym) = ctx
                .symbols
                .iter()
                .find(|s| xref.line >= s.start_line && xref.line <= s.end_line)
            {
                xref.enclosing_symbol = Some(sym.name.clone());
            }
        }
    }

    ctx.macros.extend(mmio_macros);
    ctx.raw_xrefs.extend(mmio_xrefs);

    // Sort symbols, types, macros deterministically by line number
    ctx.symbols.sort_by(|a, b| {
        a.start_line
            .cmp(&b.start_line)
            .then_with(|| a.name.cmp(&b.name))
    });
    ctx.types.sort_by(|a, b| {
        a.start_line
            .cmp(&b.start_line)
            .then_with(|| a.name.cmp(&b.name))
    });
    ctx.macros
        .sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.name.cmp(&b.name)));

    Ok(ParsedFileUnit {
        scanned: scanned.clone(),
        symbols: ctx.symbols,
        types: ctx.types,
        macros: ctx.macros,
        imports: ctx.imports,
        raw_calls: ctx.raw_calls,
        raw_xrefs: ctx.raw_xrefs,
        parse_errors: ctx.parse_errors,
    })
}

fn tree_sitter_language(lang: LanguageKind) -> Language {
    match lang {
        LanguageKind::C => tree_sitter_c::LANGUAGE.into(),
        LanguageKind::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        LanguageKind::Rust => tree_sitter_rust::LANGUAGE.into(),
        LanguageKind::Python => tree_sitter_python::LANGUAGE.into(),
        LanguageKind::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        LanguageKind::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        LanguageKind::JavaScript | LanguageKind::Jsx => tree_sitter_javascript::LANGUAGE.into(),
    }
}

fn is_c_or_cpp_header(rel_path: &str) -> bool {
    let lower = rel_path.to_ascii_lowercase();
    lower.ends_with(".h")
        || lower.ends_with(".hpp")
        || lower.ends_with(".hh")
        || lower.ends_with(".hxx")
        || lower.ends_with(".inl")
}

fn is_sfc_file(rel_path: &str) -> bool {
    let lower = rel_path.to_ascii_lowercase();
    lower.ends_with(".astro") || lower.ends_with(".vue") || lower.ends_with(".svelte")
}

fn is_c_ident_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

fn is_c_ident_continue(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

/// Returns true when the bytes between `line_start` and `pos` make the current physical line a
/// preprocessor directive (first non-whitespace byte is `#`). Directive lines are never rewritten
/// so `#define STATIC static` and `#ifdef __WEAK` keep their exact original semantics.
fn line_is_preproc_directive(bytes: &[u8], line_start: usize, pos: usize) -> bool {
    for &b in bytes.get(line_start..pos).unwrap_or_default() {
        if b == b' ' || b == b'\t' || b == b'\r' {
            continue;
        }
        return b == b'#';
    }
    false
}

/// Classifies a top-level C/C++ uppercase qualifier/attribute macro token into the valid C
/// keyword prefix (`"static inline"`, `"static"`, `"inline"`, `"const"`, or `""` for pure
/// attribute/weak/section/ISR macros) that should replace it while preserving exact byte length.
fn classify_c_qualifier_macro_replacement(
    token: &[u8],
    blueprint: Option<&RepoBlueprint>,
) -> Option<&'static [u8]> {
    let s = std::str::from_utf8(token).ok()?;
    if s.len() < 2 {
        return None;
    }

    if let Some(bp) = blueprint {
        if bp.c_qualifiers.iter().any(|q| q == s) {
            return Some(b"");
        }
    }

    if s.len() < 3
        || !s
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        || !s.bytes().any(|b| b.is_ascii_uppercase())
    {
        return None;
    }

    if s == "STATIC" {
        return Some(b"static");
    }
    if s == "CONST" {
        return Some(b"const");
    }
    if s.len() >= 13
        && (s == "__STATIC_INLINE"
            || s == "__STATIC_FORCEINLINE"
            || s == "STATIC_INLINE"
            || s == "STATIC_FORCEINLINE"
            || s.ends_with("_STATIC_INLINE")
            || s.ends_with("_STATIC_FORCEINLINE"))
    {
        return Some(b"static inline");
    }
    if s.len() >= 6
        && (s == "INLINE"
            || s == "__INLINE"
            || s == "__INLINE__"
            || s == "FORCEINLINE"
            || s == "__FORCEINLINE"
            || s.ends_with("_INLINE")
            || s.ends_with("_FORCEINLINE"))
    {
        return Some(b"inline");
    }
    if matches!(
        s,
        "__I"
            | "__O"
            | "__IO"
            | "__IM"
            | "__OM"
            | "__IOM"
            | "__IAR_FT"
            | "__ALIGNED"
            | "WEAK"
            | "__WEAK"
            | "__IRQ"
            | "__INTERRUPT"
            | "__RAMFUNC"
            | "RAMFUNC"
            | "__PACKED"
            | "PACKED"
    ) || s.ends_with("_WEAK")
        || s.ends_with("_IRQ")
        || s.ends_with("_INTERRUPT")
        || s.ends_with("_RAMFUNC")
        || s.ends_with("_PACKED")
        || s.ends_with("_ALIGNED")
        || s.ends_with("_ATTR")
        || s.ends_with("_ATTRIBUTE")
    {
        return Some(b"");
    }

    None
}

/// Returns true when the token ending at `after_token` is followed on the same declaration by
/// another identifier or pointer `*` (e.g. `STATIC void f(void)` or `CONST char *p`), rather than
/// `=`, `,`, `;`, `)`, or `}` (such as `enum { STATIC = 0, CONST = 1 };`).
fn is_followed_by_c_decl_token(bytes: &[u8], mut pos: usize) -> bool {
    while pos < bytes.len() {
        match bytes[pos] {
            b' ' | b'\t' | b'\r' | b'\n' => pos += 1,
            b'*' => return true,
            b if is_c_ident_start(b) => return true,
            _ => return false,
        }
    }
    false
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BraceFrame {
    /// `extern "C" { ... }` or `extern "C++" { ... }` linkage block (transparent to top-level depth).
    Transparent,
    /// `struct`, `union`, or `class` body where member qualifier macros (`__IO`, `__I`, etc.) appear.
    Aggregate,
    /// Function body or statement block where local expressions must not be rewritten.
    Block,
}

fn blank_range_preserving_newlines(buf: &mut [u8], start: usize, end: usize) {
    for b in &mut buf[start..end] {
        if *b != b'\n' && *b != b'\r' {
            *b = b' ';
        }
    }
}

/// Byte-length-preserving normalization of C/C++ storage-class and attribute macros.
///
/// Rewrites qualifier tokens at top-level (including inside `extern "C" { ... }` transparent frames)
/// and inside `struct`/`union`/`class` aggregate bodies (`__IO`, `__I`, `__O`, etc.) when followed
/// by a declaration type/identifier token, leaving function bodies, `enum { STATIC = 0 }`,
/// preprocessor directives, comments, and literals completely untouched.
fn normalize_c_qualifier_macros(
    source: &str,
    blueprint: Option<&RepoBlueprint>,
) -> Option<Vec<u8>> {
    let bytes = source.as_bytes();
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0usize;
    let mut line_start = 0usize;
    let mut in_continued_directive = false;
    let mut line_directive_known = false;
    let mut line_directive = false;
    let mut brace_stack: Vec<BraceFrame> = Vec::new();
    let mut paren_depth = 0u32;
    let mut pending_aggregate = false;

    while i < bytes.len() {
        let b = bytes[i];

        if b == b'\n' {
            let mut last_sig = 0u8;
            for &c in bytes[line_start..i].iter().rev() {
                if c != b' ' && c != b'\t' && c != b'\r' {
                    last_sig = c;
                    break;
                }
            }
            let continues = last_sig == b'\\'
                && (in_continued_directive || line_is_preproc_directive(bytes, line_start, i));
            in_continued_directive = continues;
            line_start = i + 1;
            line_directive_known = continues;
            line_directive = continues;
            i += 1;
            continue;
        }

        // Line comment: never rewritten.
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Block comment: never rewritten, but keep line bookkeeping accurate.
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < bytes.len() {
                if bytes[i] == b'\n' {
                    line_start = i + 1;
                    in_continued_directive = false;
                    line_directive_known = false;
                    line_directive = false;
                    i += 1;
                    continue;
                }
                if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }

        // String / character literal: never rewritten.
        if b == b'"' || b == b'\'' {
            let quote = b;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\n' {
                    line_start = i + 1;
                    in_continued_directive = false;
                    line_directive_known = false;
                    line_directive = false;
                    i += 1;
                    break;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        match b {
            b'{' => {
                if !line_directive_known {
                    line_directive = line_is_preproc_directive(bytes, line_start, i);
                    line_directive_known = true;
                }
                if !line_directive {
                    let frame = if pending_aggregate && paren_depth == 0 {
                        BraceFrame::Aggregate
                    } else {
                        BraceFrame::Block
                    };
                    brace_stack.push(frame);
                    pending_aggregate = false;
                }
                i += 1;
                continue;
            }
            b'}' => {
                if !line_directive_known {
                    line_directive = line_is_preproc_directive(bytes, line_start, i);
                    line_directive_known = true;
                }
                if !line_directive {
                    pending_aggregate = false;
                    if let Some(frame) = brace_stack.pop() {
                        if frame == BraceFrame::Transparent {
                            let buf = out.get_or_insert_with(|| bytes.to_vec());
                            buf[i] = b' ';
                        }
                    }
                }
                i += 1;
                continue;
            }
            b'(' => {
                paren_depth = paren_depth.saturating_add(1);
                i += 1;
                continue;
            }
            b')' => {
                paren_depth = paren_depth.saturating_sub(1);
                if paren_depth == 0 {
                    pending_aggregate = false;
                }
                i += 1;
                continue;
            }
            b';' => {
                if paren_depth == 0 {
                    pending_aggregate = false;
                }
                i += 1;
                continue;
            }
            _ => {}
        }

        if is_c_ident_start(b) {
            let start = i;
            while i < bytes.len() && is_c_ident_continue(bytes[i]) {
                i += 1;
            }
            if !line_directive_known {
                line_directive = line_is_preproc_directive(bytes, line_start, start);
                line_directive_known = true;
            }
            if line_directive {
                continue;
            }

            let token = &bytes[start..i];
            if paren_depth == 0 && matches!(token, b"struct" | b"union" | b"class") {
                pending_aggregate = true;
                continue;
            }

            let allow_qual_replace = paren_depth == 0
                && brace_stack
                    .iter()
                    .all(|&f| matches!(f, BraceFrame::Transparent | BraceFrame::Aggregate));

            // Detect `extern "C"` / `extern "C++"` linkage blocks and single-line declarations.
            if allow_qual_replace && token == b"extern" {
                let mut p = i;
                while p < bytes.len() && matches!(bytes[p], b' ' | b'\t' | b'\r') {
                    p += 1;
                }
                let c_lit_end = if bytes.get(p..p + 3) == Some(b"\"C\"") {
                    Some(p + 3)
                } else if bytes.get(p..p + 5) == Some(b"\"C++\"") {
                    Some(p + 5)
                } else {
                    None
                };
                if let Some(lit_end) = c_lit_end {
                    let mut q = lit_end;
                    while q < bytes.len() && matches!(bytes[q], b' ' | b'\t' | b'\r' | b'\n') {
                        q += 1;
                    }
                    let buf = out.get_or_insert_with(|| bytes.to_vec());
                    if bytes.get(q) == Some(&b'{') {
                        blank_range_preserving_newlines(buf, start, q + 1);
                        brace_stack.push(BraceFrame::Transparent);
                        // Recompute line_start if we crossed newlines between `"C"` and `{`
                        if let Some(rel_nl) = bytes[start..=q].iter().rposition(|&c| c == b'\n') {
                            line_start = start + rel_nl + 1;
                            line_directive_known = false;
                            line_directive = false;
                        }
                        i = q + 1;
                        continue;
                    } else {
                        blank_range_preserving_newlines(buf, p, lit_end);
                        i = lit_end;
                        continue;
                    }
                }
            }

            if allow_qual_replace {
                if let Some(kw) = classify_c_qualifier_macro_replacement(token, blueprint) {
                    if kw.is_empty() {
                        // Check for function-like qualifier macro such as `__ALIGNED(4)`
                        let mut p = i;
                        while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
                            p += 1;
                        }
                        if bytes.get(p) == Some(&b'(') {
                            let mut depth = 1u32;
                            let mut q = p + 1;
                            while q < bytes.len() && depth > 0 {
                                match bytes[q] {
                                    b'(' => depth += 1,
                                    b')' => depth -= 1,
                                    _ => {}
                                }
                                q += 1;
                            }
                            if depth == 0 && is_followed_by_c_decl_token(bytes, q) {
                                let buf = out.get_or_insert_with(|| bytes.to_vec());
                                blank_range_preserving_newlines(buf, start, q);
                                if let Some(rel_nl) =
                                    bytes[start..q].iter().rposition(|&c| c == b'\n')
                                {
                                    line_start = start + rel_nl + 1;
                                    line_directive_known = false;
                                    line_directive = false;
                                }
                                i = q;
                                continue;
                            }
                        }
                    }
                    if kw.len() <= token.len() && is_followed_by_c_decl_token(bytes, i) {
                        let buf = out.get_or_insert_with(|| bytes.to_vec());
                        let dst = &mut buf[start..i];
                        dst.fill(b' ');
                        dst[..kw.len()].copy_from_slice(kw);
                    }
                }
            }
            continue;
        }

        i += 1;
    }

    out
}

struct ExtractContext<'a> {
    scanned: &'a ScannedFile,
    bytes: &'a [u8],
    lines: &'a [&'a str],
    section_id: &'a str,
    blueprint: Option<&'a RepoBlueprint>,
    is_header: bool,
    in_test_scope: bool,
    symbols: Vec<ExtractedSymbol>,
    header_prototypes: Vec<ExtractedSymbol>,
    types: Vec<ExtractedType>,
    macros: Vec<ExtractedMacro>,
    imports: Vec<ExtractedImport>,
    raw_calls: Vec<RawCallSite>,
    raw_xrefs: Vec<RawXrefSite>,
    handled_type_ranges: HashSet<(usize, usize)>,
    local_var_types: FxHashMap<String, String>,
    local_collection_elem_types: FxHashMap<String, String>,
    local_vars: FxHashSet<String>,
    seen_fn_ptr_candidates: FxHashSet<(usize, String)>,
    seen_field_xrefs: FxHashSet<(usize, String, bool)>,
    parse_errors: usize,
}

impl ExtractContext<'_> {
    fn current_scope(&self) -> FileScope {
        if self.in_test_scope {
            FileScope::Test
        } else {
            self.scanned.scope
        }
    }

    fn current_layer(&self) -> ArchLayer {
        if self.in_test_scope {
            ArchLayer::Tests
        } else {
            self.scanned.arch_layer
        }
    }
}

fn format_type_summary_items(items: Vec<String>) -> String {
    let total = items.len();
    if total <= MAX_TYPE_SUMMARY_ITEMS {
        items.join(", ")
    } else {
        let mut head: String = items[..MAX_TYPE_SUMMARY_ITEMS].join(", ");
        head.push_str(&format!(", ... (+{} more)", total - MAX_TYPE_SUMMARY_ITEMS));
        head
    }
}

fn has_preceding_rust_test_attr(node: Node<'_>, bytes: &[u8]) -> bool {
    let mut prev = node.prev_sibling();
    while let Some(sib) = prev {
        if sib.kind() == "attribute_item" {
            let txt = node_text(sib, bytes);
            if txt.contains("cfg(test)")
                || txt.contains("#[test]")
                || txt.contains("::test")
                || txt.contains("test_case")
            {
                return true;
            }
        } else if !sib.is_extra() {
            break;
        }
        prev = sib.prev_sibling();
    }
    false
}

fn walk_ast(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
    enclosing_fn: Option<(&str, usize)>,
) {
    if node.is_error() || node.is_missing() {
        ctx.parse_errors += 1;
    }

    let kind = node.kind();
    let prev_test_scope = ctx.in_test_scope;
    if ctx.scanned.language == LanguageKind::Rust
        && matches!(kind, "mod_item" | "function_item")
        && has_preceding_rust_test_attr(node, ctx.bytes)
    {
        ctx.in_test_scope = true;
    }

    let mut next_enclosing_type: Option<String> = enclosing_type.map(ToOwned::to_owned);
    let mut next_enclosing_fn: Option<(String, usize)> =
        enclosing_fn.map(|(n, l)| (n.to_string(), l));

    match ctx.scanned.language {
        LanguageKind::C | LanguageKind::Cpp => {
            handle_c_cpp_node(
                ctx,
                node,
                kind,
                enclosing_type,
                enclosing_fn,
                &mut next_enclosing_type,
                &mut next_enclosing_fn,
            );
        }
        LanguageKind::Rust => {
            handle_rust_node(
                ctx,
                node,
                kind,
                enclosing_type,
                enclosing_fn,
                &mut next_enclosing_type,
                &mut next_enclosing_fn,
            );
        }
        LanguageKind::Python => {
            handle_python_node(
                ctx,
                node,
                kind,
                enclosing_type,
                enclosing_fn,
                &mut next_enclosing_type,
                &mut next_enclosing_fn,
            );
        }
        LanguageKind::TypeScript
        | LanguageKind::Tsx
        | LanguageKind::JavaScript
        | LanguageKind::Jsx => {
            handle_ts_js_node(
                ctx,
                node,
                kind,
                enclosing_type,
                enclosing_fn,
                &mut next_enclosing_type,
                &mut next_enclosing_fn,
            );
        }
    }

    let entered_new_fn = next_enclosing_fn.is_some()
        && next_enclosing_fn.as_ref().map(|(n, l)| (n.as_str(), *l)) != enclosing_fn;

    let saved_scope = if entered_new_fn {
        let prev_types = std::mem::take(&mut ctx.local_var_types);
        let prev_elems = std::mem::take(&mut ctx.local_collection_elem_types);
        let prev_vars = std::mem::take(&mut ctx.local_vars);
        extract_function_parameters(ctx, node);
        Some((prev_types, prev_elems, prev_vars))
    } else {
        None
    };

    let active_fn = next_enclosing_fn.as_ref().map(|(n, l)| (n.as_str(), *l));
    let active_type = next_enclosing_type.as_deref();

    extract_local_var_binding(ctx, node, kind, active_fn);
    extract_fn_ptr_candidates_from_node(ctx, node, kind, active_fn);
    extract_field_access_mutability(ctx, node, kind, active_type, active_fn);

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_ast(ctx, child, active_type, active_fn);
    }

    if let Some((prev_types, prev_elems, prev_vars)) = saved_scope {
        ctx.local_var_types = prev_types;
        ctx.local_collection_elem_types = prev_elems;
        ctx.local_vars = prev_vars;
    }
    ctx.in_test_scope = prev_test_scope;
}

// ============================================================================
// C / C++ AST Extraction
// ============================================================================

/// Returns `true` when a C/C++ `field_declaration` is a member function prototype
/// (`bool start(uint16_t rpm);`) rather than a data field or function-pointer field
/// (`void (*on_frame)(uint8_t);`).
fn is_cpp_method_field_declaration(node: Node<'_>) -> bool {
    let Some(fn_decl) = find_first_descendant_of_kind(node, "function_declarator") else {
        return false;
    };
    if let Some(inner_decl) = fn_decl.child_by_field_name("declarator") {
        if inner_decl.kind() == "parenthesized_declarator"
            && has_descendant_kind(inner_decl, "pointer_declarator")
        {
            return false;
        }
    }
    true
}

fn handle_c_cpp_node(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind: &str,
    enclosing_type: Option<&str>,
    enclosing_fn: Option<(&str, usize)>,
    next_enclosing_type: &mut Option<String>,
    next_enclosing_fn: &mut Option<(String, usize)>,
) {
    match kind {
        "function_definition" => {
            if let Some(sym) = extract_c_cpp_function(ctx, node, enclosing_type, false) {
                *next_enclosing_fn = Some((sym.name.clone(), sym.start_line));
                ctx.symbols.push(sym);
            }
        }
        "declaration" => {
            // Check if this declaration is a function prototype in a header file
            if ctx.is_header && is_cpp_method_field_declaration(node) {
                let text = node_text(node, ctx.bytes);
                if !text.trim_start().starts_with("typedef") {
                    if let Some(sym) = extract_c_cpp_function(ctx, node, enclosing_type, true) {
                        ctx.header_prototypes.push(sym);
                    }
                }
            } else if enclosing_fn.is_none() {
                // Top-level const / constexpr declaration
                extract_c_cpp_const_declaration(ctx, node);
            }
        }
        "field_declaration" => {
            // C++ method declaration inside class/struct in a header file
            if ctx.is_header && is_cpp_method_field_declaration(node) {
                if let Some(sym) = extract_c_cpp_function(ctx, node, enclosing_type, true) {
                    ctx.header_prototypes.push(sym);
                }
            }
        }
        "type_definition" => {
            extract_c_typedef(ctx, node);
        }
        "struct_specifier" | "union_specifier" | "enum_specifier" | "class_specifier" => {
            let type_kind = match kind {
                "struct_specifier" => TypeKind::Struct,
                "union_specifier" => TypeKind::Union,
                "enum_specifier" => TypeKind::Enum,
                _ => TypeKind::Class,
            };
            if let Some(ty_name) = extract_c_specifier_type(ctx, node, type_kind) {
                *next_enclosing_type = Some(ty_name);
            }
        }
        "preproc_def" => {
            extract_c_preproc_def(ctx, node, false);
        }
        "preproc_function_def" => {
            extract_c_preproc_def(ctx, node, true);
        }
        "preproc_include" => {
            extract_c_include(ctx, node, enclosing_fn);
        }
        "call_expression" => {
            extract_call_site(ctx, node, enclosing_fn);
        }
        _ => {}
    }
}

fn extract_decl_header<'a>(node: Node<'_>, bytes: &'a [u8]) -> &'a str {
    let full_text = node_text(node, bytes);
    let header_end = node
        .child_by_field_name("body")
        .map(|b| b.start_byte())
        .unwrap_or_else(|| node.end_byte());
    let slice = if header_end > node.start_byte() && header_end <= bytes.len() {
        std::str::from_utf8(&bytes[node.start_byte()..header_end]).unwrap_or(full_text)
    } else {
        full_text
    };
    split_at_top_level_brace(slice)
}

fn extract_c_cpp_function(
    ctx: &ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
    is_prototype: bool,
) -> Option<ExtractedSymbol> {
    let fn_decl = find_first_descendant_of_kind(node, "function_declarator")?;
    let decl_target = fn_decl.child_by_field_name("declarator").unwrap_or(fn_decl);
    let raw_decl_name = extract_declarator_name(decl_target, ctx.bytes)?;
    if raw_decl_name.is_empty()
        || matches!(
            raw_decl_name.as_str(),
            "if" | "else"
                | "for"
                | "while"
                | "switch"
                | "return"
                | "sizeof"
                | "typeof"
                | "alignof"
                | "_Static_assert"
                | "static_assert"
        )
    {
        return None;
    }

    // Handle AVR/embedded ISR(VECTOR_NAME) macro-style function definitions
    let (mut name, mut forced_isr) =
        if (raw_decl_name == "ISR" || raw_decl_name == "SIGNAL") && !is_prototype {
            if let Some(params) = fn_decl.child_by_field_name("parameters") {
                let param_txt = node_text(params, ctx.bytes).trim();
                (format!("{raw_decl_name}{param_txt}"), true)
            } else {
                (raw_decl_name, true)
            }
        } else {
            (raw_decl_name, false)
        };

    // Handle C++ out-of-line qualified method definitions: `ClassName::method_name`
    let mut effective_enclosing: Option<String> = enclosing_type.map(ToOwned::to_owned);
    if let Some((scope_part, leaf_part)) = name.rsplit_once("::") {
        let clean_scope = scope_part.trim().to_string();
        let clean_leaf = leaf_part.trim().to_string();
        if !clean_scope.is_empty() && !clean_leaf.is_empty() {
            effective_enclosing = Some(clean_scope);
            name = clean_leaf;
        }
    }

    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let doc_summary = extract_preceding_doc(ctx.lines, start_line);
    let has_isr_attr = has_preceding_interrupt_attr(ctx.lines, start_line);
    if has_isr_attr {
        forced_isr = true;
    }

    // Only the declaration header (everything before the body brace) decides linkage and ISR kind,
    // so literals or `static` locals inside the body cannot misclassify the function.
    let decl_header = extract_decl_header(node, ctx.bytes);
    let visibility = if c_decl_header_is_static(decl_header) {
        Visibility::Static
    } else {
        Visibility::Public
    };

    let kind = classify_symbol_kind(
        &name,
        effective_enclosing.as_deref(),
        forced_isr,
        visibility,
        ctx.current_layer(),
        decl_header,
        ctx.blueprint,
    );

    let qualified_name = match effective_enclosing.as_deref() {
        Some(enc) => format!("{enc}::{name}"),
        None => name.clone(),
    };
    let symbol_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
    let signature = extract_clean_signature(node, ctx.bytes);

    Some(ExtractedSymbol {
        symbol_id,
        name,
        qualified_name,
        kind,
        visibility,
        file: ctx.scanned.rel_path.clone(),
        start_line,
        end_line,
        signature,
        doc_summary,
        enclosing_type: effective_enclosing,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
    })
}

/// Returns true when a C/C++ declaration header (the text preceding the body brace) carries a
/// `static` storage-class specifier — either written directly or expressed through a common
/// uppercase qualifier macro that [`normalize_c_qualifier_macros`] rewrites to `static` before
/// Tree-sitter parsing.
fn c_decl_header_is_static(decl_header: &str) -> bool {
    decl_header
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|tok| {
            tok == "static"
                || tok == "STATIC"
                || tok.contains("STATIC_INLINE")
                || tok.contains("STATIC_FORCEINLINE")
        })
}

fn extract_c_typedef(ctx: &mut ExtractContext<'_>, node: Node<'_>) {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(typedef_name) = extract_declarator_name(declarator, ctx.bytes) else {
        return;
    };
    if typedef_name.is_empty() {
        return;
    }

    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let doc_summary = extract_preceding_doc(ctx.lines, start_line);

    let mut fields_summary = String::new();
    let mut resolved_kind = TypeKind::Typedef;

    if let Some(type_node) = node.child_by_field_name("type") {
        let tk = type_node.kind();
        if tk == "struct_specifier" || tk == "union_specifier" || tk == "enum_specifier" {
            ctx.handled_type_ranges
                .insert((type_node.start_byte(), type_node.end_byte()));
            fields_summary = summarize_c_type_fields(type_node, ctx.bytes);
            if !fields_summary.is_empty() {
                resolved_kind = match tk {
                    "struct_specifier" => TypeKind::Struct,
                    "union_specifier" => TypeKind::Union,
                    "enum_specifier" => TypeKind::Enum,
                    _ => TypeKind::Typedef,
                };
            }
        } else {
            fields_summary = normalize_whitespace(node_text(type_node, ctx.bytes));
        }
    }

    let type_id = format!("{}::{}", ctx.scanned.rel_path, typedef_name);
    ctx.types.push(ExtractedType {
        type_id,
        name: typedef_name,
        kind: resolved_kind,
        visibility: Visibility::Public,
        file: ctx.scanned.rel_path.clone(),
        start_line,
        end_line,
        fields_summary,
        doc_summary,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
    });
}

fn extract_c_specifier_type(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind: TypeKind,
) -> Option<String> {
    let range = (node.start_byte(), node.end_byte());
    if ctx.handled_type_ranges.contains(&range) {
        return node
            .child_by_field_name("name")
            .map(|n| node_text(n, ctx.bytes).trim().to_string());
    }

    // Only emit standalone struct/enum/union/class if it has a body block
    let body = node.child_by_field_name("body")?;
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return None;
    }

    ctx.handled_type_ranges.insert(range);
    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let doc_summary = extract_preceding_doc(ctx.lines, start_line);
    let fields_summary = summarize_c_type_fields(node, ctx.bytes);
    let _ = body;

    let type_id = format!("{}::{}", ctx.scanned.rel_path, name);
    ctx.types.push(ExtractedType {
        type_id,
        name: name.clone(),
        kind,
        visibility: Visibility::Public,
        file: ctx.scanned.rel_path.clone(),
        start_line,
        end_line,
        fields_summary,
        doc_summary,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
    });

    Some(name)
}

fn recover_c_field_from_raw_text(
    raw_decl: &str,
    blueprint: Option<&RepoBlueprint>,
) -> Option<(String, String)> {
    let before_semi = raw_decl.split(';').next().unwrap_or(raw_decl).trim();
    let tokens: Vec<&str> = before_semi
        .split_whitespace()
        .filter(|tok| {
            !matches!(*tok, "volatile" | "const" | "mutable")
                && classify_c_qualifier_macro_replacement(tok.as_bytes(), blueprint).is_none()
        })
        .collect();
    if tokens.len() < 2 {
        return None;
    }
    let last_tok = tokens[tokens.len() - 1];
    let field_ident = last_tok
        .split('[')
        .next()
        .unwrap_or(last_tok)
        .trim_start_matches('*')
        .trim();
    if !is_valid_identifier(field_ident) {
        return None;
    }
    let real_type = tokens[..tokens.len() - 1].join(" ");
    if real_type.is_empty() {
        return None;
    }
    Some((real_type, field_ident.to_string()))
}

fn summarize_c_type_fields(type_node: Node<'_>, bytes: &[u8]) -> String {
    let Some(body) = type_node.child_by_field_name("body") else {
        return String::new();
    };
    let mut items = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        match child.kind() {
            "field_declaration" => {
                // Skip C++ member function prototypes inside class/struct bodies
                if is_cpp_method_field_declaration(child) {
                    continue;
                }
                let ty_txt = child
                    .child_by_field_name("type")
                    .map(|n| normalize_whitespace(node_text(n, bytes)))
                    .unwrap_or_default();
                if classify_c_qualifier_macro_replacement(ty_txt.as_bytes(), None).is_some() {
                    if let Some((real_ty, real_field)) =
                        recover_c_field_from_raw_text(node_text(child, bytes), None)
                    {
                        items.push(format!("{real_field}: {real_ty}"));
                        continue;
                    }
                }
                if let Some(decl) = child.child_by_field_name("declarator") {
                    if let Some(fname) = extract_declarator_name(decl, bytes) {
                        if !ty_txt.is_empty() {
                            items.push(format!("{fname}: {ty_txt}"));
                        } else {
                            items.push(fname);
                        }
                    }
                }
            }
            "enumerator" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let ename = node_text(name_node, bytes).trim();
                    if let Some(val_node) = child.child_by_field_name("value") {
                        let vtxt = normalize_whitespace(node_text(val_node, bytes));
                        items.push(format!("{ename} = {vtxt}"));
                    } else {
                        items.push(ename.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    format_type_summary_items(items)
}

/// Splits a preprocessor `#define` value into `(clean_value, optional_inline_comment)`,
/// stripping trailing `//...` and `/*...*/` comments while preserving string literals.
fn split_macro_value_and_inline_comment(raw: &str) -> (String, Option<String>) {
    let bytes = raw.as_bytes();
    let mut i = 0usize;
    let mut in_quote: u8 = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if in_quote != 0 {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == in_quote {
                in_quote = 0;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' {
            in_quote = b;
            i += 1;
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            let val = normalize_whitespace(&raw[..i]);
            let comment = clean_inline_macro_comment(&raw[i + 2..]);
            return (val, (!comment.is_empty()).then_some(comment));
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let before = &raw[..i];
            let after_start = i + 2;
            if let Some(end_rel) = raw[after_start..].find("*/") {
                let comment_raw = &raw[after_start..after_start + end_rel];
                let trailing = &raw[after_start + end_rel + 2..];
                let combined_val = format!("{before} {trailing}");
                let val = normalize_whitespace(&combined_val);
                let comment = clean_inline_macro_comment(comment_raw);
                return (val, (!comment.is_empty()).then_some(comment));
            } else {
                let val = normalize_whitespace(before);
                let comment = clean_inline_macro_comment(&raw[after_start..]);
                return (val, (!comment.is_empty()).then_some(comment));
            }
        }
        i += 1;
    }

    (normalize_whitespace(raw), None)
}

fn clean_inline_macro_comment(raw_comment: &str) -> String {
    let s = raw_comment
        .trim()
        .trim_start_matches('/')
        .trim_start_matches('*')
        .trim_start_matches('!')
        .trim_start_matches('<')
        .trim_end_matches("*/")
        .trim_end_matches('*')
        .trim();
    normalize_whitespace(s)
}

fn extract_c_preproc_def(ctx: &mut ExtractContext<'_>, node: Node<'_>, is_fn_like: bool) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return;
    }

    let params_str = if is_fn_like {
        node.child_by_field_name("parameters")
            .map(|p| normalize_whitespace(node_text(p, ctx.bytes)))
            .unwrap_or_default()
    } else {
        String::new()
    };

    let (raw_val, inline_comment) = node
        .child_by_field_name("value")
        .map(|v| split_macro_value_and_inline_comment(node_text(v, ctx.bytes)))
        .unwrap_or_else(|| (String::new(), None));

    // Skip empty header guards like `#define MOTOR_CTRL_H`
    if !is_fn_like
        && raw_val.is_empty()
        && (name.ends_with("_H")
            || name.ends_with("_H_")
            || name.ends_with("_HPP")
            || name.ends_with("_INCLUDED"))
    {
        return;
    }

    let value_or_args = if is_fn_like {
        if raw_val.is_empty() {
            params_str
        } else {
            format!("{params_str} -> {raw_val}")
        }
    } else {
        raw_val.clone()
    };

    let (kind, hex_addr, mut description) =
        classify_macro_value_with_blueprint(&name, &raw_val, is_fn_like, ctx.blueprint);
    if let Some(comment) = inline_comment {
        if !description.contains('(') {
            description = truncate_str(&comment, 160);
        }
    }
    let line = node.start_position().row + 1;

    if matches!(kind, MacroKind::MmioAddress | MacroKind::Bitmask) {
        ctx.raw_xrefs.push(RawXrefSite {
            file: ctx.scanned.rel_path.clone(),
            line,
            enclosing_symbol: None,
            target_name: name.clone(),
            category: "mmio_def".to_string(),
            context: truncate_str(&value_or_args, 120),
        });
    }

    ctx.macros.push(ExtractedMacro {
        name,
        kind,
        value_or_args: truncate_str(&value_or_args, 160),
        hex_addr,
        file: ctx.scanned.rel_path.clone(),
        line,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
        description,
    });
}

fn extract_c_cpp_const_declaration(ctx: &mut ExtractContext<'_>, node: Node<'_>) {
    let text = node_text(node, ctx.bytes);
    if !text.contains("const ") && !text.contains("constexpr ") {
        return;
    }
    let Some(init_decl) = find_first_descendant_of_kind(node, "init_declarator") else {
        return;
    };
    let Some(decl_node) = init_decl.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_declarator_name(decl_node, ctx.bytes) else {
        return;
    };
    let Some(val_node) = init_decl.child_by_field_name("value") else {
        return;
    };
    let raw_val = summarize_const_value_node(val_node, ctx.bytes);
    let (mut kind, hex_addr, mut description) =
        classify_macro_value_with_blueprint(&name, &raw_val, false, ctx.blueprint);
    if kind == MacroKind::ObjectMacro {
        kind = MacroKind::Constant;
        description = "Compile-time constant".to_string();
    }
    let line = node.start_position().row + 1;

    ctx.macros.push(ExtractedMacro {
        name,
        kind,
        value_or_args: truncate_str(&raw_val, 160),
        hex_addr,
        file: ctx.scanned.rel_path.clone(),
        line,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
        description,
    });
}

fn summarize_const_value_node(val_node: Node<'_>, bytes: &[u8]) -> String {
    let raw = node_text(val_node, bytes).trim();
    if (raw.starts_with('"')
        || raw.starts_with('\'')
        || raw.starts_with("r\"")
        || raw.starts_with("r#"))
        && (raw.contains('\n') || raw.contains("\\t") || raw.contains("\\n"))
    {
        return "\"<multiline string>\"".to_string();
    }
    normalize_whitespace(raw)
}

fn extract_c_include(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_fn: Option<(&str, usize)>,
) {
    let Some(path_node) = node.child_by_field_name("path") else {
        return;
    };
    let raw = node_text(path_node, ctx.bytes).trim();
    let is_system = raw.starts_with('<') && raw.ends_with('>');
    let clean_path = raw
        .trim_matches(|c| c == '"' || c == '<' || c == '>')
        .to_string();
    if clean_path.is_empty() {
        return;
    }

    let stem = clean_path
        .rsplit('/')
        .next()
        .unwrap_or(&clean_path)
        .rsplit_once('.')
        .map(|(s, _)| s.to_string())
        .unwrap_or_else(|| clean_path.clone());

    let line = node.start_position().row + 1;
    ctx.imports.push(ExtractedImport {
        file: ctx.scanned.rel_path.clone(),
        line,
        raw_path: clean_path.clone(),
        imported_names: vec![stem],
        is_system,
    });

    ctx.raw_xrefs.push(RawXrefSite {
        file: ctx.scanned.rel_path.clone(),
        line,
        enclosing_symbol: enclosing_fn.map(|(n, _)| n.to_string()),
        target_name: clean_path,
        category: "include".to_string(),
        context: normalize_whitespace(node_text(node, ctx.bytes)),
    });
}

// ============================================================================
// Rust AST Extraction
// ============================================================================

fn handle_rust_node(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind: &str,
    enclosing_type: Option<&str>,
    enclosing_fn: Option<(&str, usize)>,
    next_enclosing_type: &mut Option<String>,
    next_enclosing_fn: &mut Option<(String, usize)>,
) {
    match kind {
        "impl_item" => {
            if let Some(ty_node) = node.child_by_field_name("type") {
                let raw_ty = normalize_whitespace(node_text(ty_node, ctx.bytes));
                let clean_ty = raw_ty
                    .split('<')
                    .next()
                    .unwrap_or(&raw_ty)
                    .trim()
                    .to_string();
                if !clean_ty.is_empty() {
                    *next_enclosing_type = Some(clean_ty);
                }
            }
        }
        "function_item" | "function_signature_item" => {
            if let Some(sym) = extract_rust_function(ctx, node, enclosing_type) {
                *next_enclosing_fn = Some((sym.name.clone(), sym.start_line));
                ctx.symbols.push(sym);
            }
        }
        "struct_item" | "enum_item" | "union_item" | "trait_item" | "type_item" => {
            if let Some(ty_name) = extract_rust_type(ctx, node, kind) {
                if kind == "trait_item" {
                    *next_enclosing_type = Some(ty_name);
                }
            }
        }
        "const_item" | "static_item" => {
            if !ctx.in_test_scope && enclosing_fn.is_none() {
                extract_rust_const_or_static(ctx, node);
            }
        }
        "macro_definition" => {
            extract_rust_macro_def(ctx, node);
        }
        "use_declaration" => {
            extract_rust_use(ctx, node, enclosing_fn);
        }
        "mod_item" => {
            extract_rust_mod(ctx, node);
        }
        "call_expression" => {
            extract_call_site(ctx, node, enclosing_fn);
        }
        "macro_invocation" => {
            extract_rust_macro_invocation_calls(ctx, node, enclosing_fn);
        }
        _ => {}
    }
}

fn extract_rust_function(
    ctx: &ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
) -> Option<ExtractedSymbol> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return None;
    }

    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let doc_summary = extract_preceding_doc(ctx.lines, start_line);
    let has_isr_attr = has_preceding_interrupt_attr(ctx.lines, start_line);
    let decl_header = extract_decl_header(node, ctx.bytes);

    let visibility = extract_rust_node_visibility(node, ctx.bytes);
    let kind = classify_symbol_kind(
        &name,
        enclosing_type,
        has_isr_attr,
        visibility,
        ctx.current_layer(),
        decl_header,
        ctx.blueprint,
    );

    let qualified_name = match enclosing_type {
        Some(enc) => format!("{enc}::{name}"),
        None => name.clone(),
    };
    let symbol_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
    let signature = extract_clean_signature(node, ctx.bytes);

    Some(ExtractedSymbol {
        symbol_id,
        name,
        qualified_name,
        kind,
        visibility,
        file: ctx.scanned.rel_path.clone(),
        start_line,
        end_line,
        signature,
        doc_summary,
        enclosing_type: enclosing_type.map(ToOwned::to_owned),
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
    })
}

fn extract_rust_type(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind_str: &str,
) -> Option<String> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return None;
    }

    let kind = match kind_str {
        "struct_item" => TypeKind::Struct,
        "enum_item" => TypeKind::Enum,
        "union_item" => TypeKind::Union,
        "trait_item" => TypeKind::Trait,
        _ => TypeKind::TypeAlias,
    };

    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let doc_summary = extract_preceding_doc(ctx.lines, start_line);
    let visibility = extract_rust_node_visibility(node, ctx.bytes);
    let fields_summary = summarize_rust_type_fields(node, ctx.bytes);
    let type_id = format!("{}::{}", ctx.scanned.rel_path, name);

    ctx.types.push(ExtractedType {
        type_id,
        name: name.clone(),
        kind,
        visibility,
        file: ctx.scanned.rel_path.clone(),
        start_line,
        end_line,
        fields_summary,
        doc_summary,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
    });

    Some(name)
}

fn summarize_rust_type_fields(node: Node<'_>, bytes: &[u8]) -> String {
    if node.kind() == "type_item" {
        if let Some(ty) = node.child_by_field_name("type") {
            return normalize_whitespace(node_text(ty, bytes));
        }
    }
    let Some(body) = node.child_by_field_name("body") else {
        return String::new();
    };
    let mut items = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        match child.kind() {
            "field_declaration" => {
                let fname = child
                    .child_by_field_name("name")
                    .map(|n| node_text(n, bytes).trim())
                    .unwrap_or("");
                let ftype = child
                    .child_by_field_name("type")
                    .map(|n| normalize_whitespace(node_text(n, bytes)))
                    .unwrap_or_default();
                if !fname.is_empty() {
                    items.push(format!("{fname}: {ftype}"));
                } else if !ftype.is_empty() {
                    items.push(ftype);
                }
            }
            "enum_variant" => {
                if let Some(vname) = child.child_by_field_name("name") {
                    items.push(node_text(vname, bytes).trim().to_string());
                }
            }
            "function_signature_item" | "function_item" => {
                if let Some(mname) = child.child_by_field_name("name") {
                    items.push(format!("fn {}", node_text(mname, bytes).trim()));
                }
            }
            _ => {}
        }
    }
    format_type_summary_items(items)
}

fn extract_rust_const_or_static(ctx: &mut ExtractContext<'_>, node: Node<'_>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return;
    }
    let raw_val = node
        .child_by_field_name("value")
        .map(|v| summarize_const_value_node(v, ctx.bytes))
        .unwrap_or_default();

    let (mut kind, hex_addr, mut description) =
        classify_macro_value_with_blueprint(&name, &raw_val, false, ctx.blueprint);
    if kind == MacroKind::ObjectMacro {
        kind = MacroKind::Constant;
        description = "Rust const/static item".to_string();
    }
    let line = node.start_position().row + 1;

    ctx.macros.push(ExtractedMacro {
        name,
        kind,
        value_or_args: truncate_str(&raw_val, 160),
        hex_addr,
        file: ctx.scanned.rel_path.clone(),
        line,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
        description,
    });
}

fn extract_rust_macro_def(ctx: &mut ExtractContext<'_>, node: Node<'_>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return;
    }
    let line = node.start_position().row + 1;
    let doc = extract_preceding_doc(ctx.lines, line);
    let description = if doc.is_empty() {
        "Rust declarative macro_rules!".to_string()
    } else {
        doc
    };

    ctx.macros.push(ExtractedMacro {
        name: format!("{name}!"),
        kind: MacroKind::FunctionMacro,
        value_or_args: "macro_rules!".to_string(),
        hex_addr: None,
        file: ctx.scanned.rel_path.clone(),
        line,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
        description,
    });
}

fn extract_rust_use(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_fn: Option<(&str, usize)>,
) {
    let full = normalize_whitespace(node_text(node, ctx.bytes));
    let raw_use = full
        .trim_start_matches("pub(crate) ")
        .trim_start_matches("pub(super) ")
        .trim_start_matches("pub ")
        .trim_start_matches("use ")
        .trim_end_matches(';')
        .trim()
        .to_string();
    if raw_use.is_empty() {
        return;
    }

    let is_system = raw_use.starts_with("std::")
        || raw_use.starts_with("core::")
        || raw_use.starts_with("alloc::");
    let imported_names = parse_rust_use_leaves(&raw_use);

    // Strip any grouped `{ ... }`, `*`, or ` as ...` suffix so `raw_path` names the module prefix cleanly
    let raw_path = if let Some((prefix, _)) = raw_use.split_once('{') {
        prefix.trim().trim_end_matches("::").to_string()
    } else if let Some(prefix) = raw_use.strip_suffix("::*") {
        prefix.trim().to_string()
    } else {
        raw_use
            .split_once(" as ")
            .map(|(p, _)| p.trim().to_string())
            .unwrap_or(raw_use)
    };

    let line = node.start_position().row + 1;

    for target in &imported_names {
        ctx.raw_xrefs.push(RawXrefSite {
            file: ctx.scanned.rel_path.clone(),
            line,
            enclosing_symbol: enclosing_fn.map(|(n, _)| n.to_string()),
            target_name: target.clone(),
            category: "import".to_string(),
            context: full.clone(),
        });
    }

    ctx.imports.push(ExtractedImport {
        file: ctx.scanned.rel_path.clone(),
        line,
        raw_path,
        imported_names,
        is_system,
    });
}

fn parse_rust_use_leaves(raw_path: &str) -> Vec<String> {
    if let Some((_, inside)) = raw_path.rsplit_once('{') {
        let inside = inside.trim_end_matches('}');
        inside
            .split(',')
            .map(|s| {
                let s = s.trim();
                let s = s.rsplit("::").next().unwrap_or(s);
                s.rsplit_once(" as ")
                    .map(|(_, alias)| alias)
                    .unwrap_or(s)
                    .trim()
                    .to_string()
            })
            .filter(|s| !s.is_empty() && s != "self" && s != "*")
            .collect()
    } else {
        let leaf = raw_path.rsplit("::").next().unwrap_or(raw_path);
        let leaf = leaf
            .rsplit_once(" as ")
            .map(|(_, alias)| alias)
            .unwrap_or(leaf)
            .trim();
        if leaf.is_empty() || leaf == "*" {
            Vec::new()
        } else {
            vec![leaf.to_string()]
        }
    }
}

fn extract_rust_mod(ctx: &mut ExtractContext<'_>, node: Node<'_>) {
    // Only treat `mod foo;` (without body block) as an external file import
    if node.child_by_field_name("body").is_some() {
        return;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return;
    }
    let line = node.start_position().row + 1;
    ctx.imports.push(ExtractedImport {
        file: ctx.scanned.rel_path.clone(),
        line,
        raw_path: name.clone(),
        imported_names: vec![name],
        is_system: false,
    });
}

fn extract_rust_node_visibility(node: Node<'_>, bytes: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" {
            return parse_rust_visibility(node_text(child, bytes));
        }
    }
    parse_rust_visibility(node_text(node, bytes))
}

fn parse_rust_visibility(text: &str) -> Visibility {
    let mut trimmed = text.trim_start();
    // Strip any leading outer attributes `#[...]` included in raw node slices
    while trimmed.starts_with("#[") {
        if let Some(end_bracket) = trimmed.find(']') {
            trimmed = trimmed[end_bracket + 1..].trim_start();
        } else {
            break;
        }
    }
    if trimmed.starts_with("pub(crate)") || trimmed.starts_with("pub(super)") {
        Visibility::Internal
    } else if trimmed == "pub" || trimmed.starts_with("pub ") || trimmed.starts_with("pub(") {
        Visibility::Public
    } else {
        Visibility::Private
    }
}

// ============================================================================
// Python AST Extraction
// ============================================================================

fn handle_python_node(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind: &str,
    enclosing_type: Option<&str>,
    enclosing_fn: Option<(&str, usize)>,
    next_enclosing_type: &mut Option<String>,
    next_enclosing_fn: &mut Option<(String, usize)>,
) {
    match kind {
        "class_definition" => {
            if let Some(cls_name) = extract_python_class(ctx, node) {
                *next_enclosing_type = Some(cls_name);
            }
        }
        "function_definition" | "async_function_definition" => {
            if let Some(sym) = extract_python_function(ctx, node, enclosing_type) {
                *next_enclosing_fn = Some((sym.name.clone(), sym.start_line));
                ctx.symbols.push(sym);
            }
        }
        "assignment" => {
            if enclosing_fn.is_none() && enclosing_type.is_none() {
                extract_python_top_level_const(ctx, node);
            }
        }
        "import_statement" | "import_from_statement" => {
            extract_python_import(ctx, node, enclosing_fn);
        }
        "call" => {
            extract_call_site(ctx, node, enclosing_fn);
        }
        _ => {}
    }
}

fn extract_python_function(
    ctx: &ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
) -> Option<ExtractedSymbol> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return None;
    }

    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let mut doc_summary = extract_python_docstring(node, ctx.bytes);
    if doc_summary.is_empty() {
        doc_summary = extract_preceding_doc(ctx.lines, start_line);
    }

    let visibility = if name.starts_with('_') && !(name.starts_with("__") && name.ends_with("__")) {
        Visibility::Private
    } else {
        Visibility::Public
    };

    let decl_header = extract_decl_header(node, ctx.bytes);
    let kind = classify_symbol_kind(
        &name,
        enclosing_type,
        false,
        visibility,
        ctx.current_layer(),
        decl_header,
        ctx.blueprint,
    );

    let qualified_name = match enclosing_type {
        Some(enc) => format!("{enc}::{name}"),
        None => name.clone(),
    };
    let symbol_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
    let signature = extract_clean_signature(node, ctx.bytes);

    Some(ExtractedSymbol {
        symbol_id,
        name,
        qualified_name,
        kind,
        visibility,
        file: ctx.scanned.rel_path.clone(),
        start_line,
        end_line,
        signature,
        doc_summary,
        enclosing_type: enclosing_type.map(ToOwned::to_owned),
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
    })
}

fn extract_python_class(ctx: &mut ExtractContext<'_>, node: Node<'_>) -> Option<String> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return None;
    }

    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let mut doc_summary = extract_python_docstring(node, ctx.bytes);
    if doc_summary.is_empty() {
        doc_summary = extract_preceding_doc(ctx.lines, start_line);
    }

    let fields_summary = summarize_python_class_fields(node, ctx.bytes);
    let visibility = if name.starts_with('_') {
        Visibility::Private
    } else {
        Visibility::Public
    };
    let type_id = format!("{}::{}", ctx.scanned.rel_path, name);

    ctx.types.push(ExtractedType {
        type_id,
        name: name.clone(),
        kind: TypeKind::Class,
        visibility,
        file: ctx.scanned.rel_path.clone(),
        start_line,
        end_line,
        fields_summary,
        doc_summary,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
    });

    Some(name)
}

fn summarize_python_class_fields(node: Node<'_>, bytes: &[u8]) -> String {
    let Some(body) = node.child_by_field_name("body") else {
        return String::new();
    };
    let mut items = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        match child.kind() {
            "expression_statement" => {
                if let Some(assign) = child.child(0) {
                    if assign.kind() == "assignment" {
                        if let Some(left) = assign.child_by_field_name("left") {
                            let lname = node_text(left, bytes).trim();
                            if let Some(ty) = assign.child_by_field_name("type") {
                                items.push(format!(
                                    "{lname}: {}",
                                    normalize_whitespace(node_text(ty, bytes))
                                ));
                            } else {
                                items.push(lname.to_string());
                            }
                        }
                    }
                }
            }
            "function_definition" | "async_function_definition" => {
                if let Some(mname) = child.child_by_field_name("name") {
                    items.push(format!("def {}", node_text(mname, bytes).trim()));
                }
            }
            "decorated_definition" => {
                if let Some(def) = child.child_by_field_name("definition") {
                    if matches!(
                        def.kind(),
                        "function_definition" | "async_function_definition"
                    ) {
                        if let Some(mname) = def.child_by_field_name("name") {
                            items.push(format!("def {}", node_text(mname, bytes).trim()));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    format_type_summary_items(items)
}

fn extract_python_docstring(node: Node<'_>, bytes: &[u8]) -> String {
    let Some(body) = node.child_by_field_name("body") else {
        return String::new();
    };
    let Some(first_stmt) = body.named_child(0) else {
        return String::new();
    };
    if first_stmt.kind() != "expression_statement" {
        return String::new();
    }
    let Some(expr) = first_stmt.named_child(0) else {
        return String::new();
    };
    if expr.kind() != "string" {
        return String::new();
    }
    let raw = node_text(expr, bytes).trim();
    let stripped = raw
        .trim_start_matches("\"\"\"")
        .trim_start_matches("'''")
        .trim_start_matches('"')
        .trim_start_matches('\'')
        .trim_end_matches("\"\"\"")
        .trim_end_matches("'''")
        .trim_end_matches('"')
        .trim_end_matches('\'');

    stripped
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| truncate_str(l, 160))
        .unwrap_or_default()
}

fn extract_python_top_level_const(ctx: &mut ExtractContext<'_>, node: Node<'_>) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let name = node_text(left, ctx.bytes).trim().to_string();
    if !is_screaming_snake_case(&name) {
        return;
    }
    let raw_val = node
        .child_by_field_name("right")
        .map(|r| summarize_const_value_node(r, ctx.bytes))
        .unwrap_or_default();

    let (mut kind, hex_addr, mut description) =
        classify_macro_value_with_blueprint(&name, &raw_val, false, ctx.blueprint);
    if kind == MacroKind::ObjectMacro {
        kind = MacroKind::Constant;
        description = "Python module constant".to_string();
    }
    let line = node.start_position().row + 1;

    ctx.macros.push(ExtractedMacro {
        name,
        kind,
        value_or_args: truncate_str(&raw_val, 160),
        hex_addr,
        file: ctx.scanned.rel_path.clone(),
        line,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
        description,
    });
}

fn extract_python_import(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_fn: Option<(&str, usize)>,
) {
    let line = node.start_position().row + 1;
    let full = normalize_whitespace(node_text(node, ctx.bytes));

    if node.kind() == "import_from_statement" {
        let raw_path = node
            .child_by_field_name("module_name")
            .map(|n| node_text(n, ctx.bytes).trim().to_string())
            .unwrap_or_else(|| ".".to_string());

        let mut imported_names = Vec::new();
        let mut cursor = node.walk();
        for child in node.children_by_field_name("name", &mut cursor) {
            let txt = node_text(child, ctx.bytes).trim();
            let sym = txt.split(" as ").next().unwrap_or(txt).trim().to_string();
            if !sym.is_empty() {
                imported_names.push(sym);
            }
        }

        let is_system = !raw_path.starts_with('.');
        for sym in &imported_names {
            ctx.raw_xrefs.push(RawXrefSite {
                file: ctx.scanned.rel_path.clone(),
                line,
                enclosing_symbol: enclosing_fn.map(|(n, _)| n.to_string()),
                target_name: sym.clone(),
                category: "import".to_string(),
                context: full.clone(),
            });
        }

        ctx.imports.push(ExtractedImport {
            file: ctx.scanned.rel_path.clone(),
            line,
            raw_path,
            imported_names,
            is_system,
        });
    } else {
        // `import a, b.c as d`
        let rest = full.trim_start_matches("import ").trim();
        let mut names = Vec::new();
        for part in rest.split(',') {
            let clean = part.split(" as ").next().unwrap_or(part).trim();
            if !clean.is_empty() {
                names.push(clean.to_string());
            }
        }
        if let Some(first) = names.first().cloned() {
            ctx.imports.push(ExtractedImport {
                file: ctx.scanned.rel_path.clone(),
                line,
                raw_path: first,
                imported_names: names,
                is_system: true,
            });
        }
    }
}

// ============================================================================
// TypeScript / JavaScript / TSX / JSX AST Extraction
// ============================================================================

fn handle_ts_js_node(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind: &str,
    enclosing_type: Option<&str>,
    enclosing_fn: Option<(&str, usize)>,
    next_enclosing_type: &mut Option<String>,
    next_enclosing_fn: &mut Option<(String, usize)>,
) {
    match kind {
        "class_declaration" | "abstract_class_declaration" | "interface_declaration" => {
            if let Some(ty_name) = extract_ts_js_type(ctx, node, kind) {
                *next_enclosing_type = Some(ty_name);
            }
        }
        "type_alias_declaration" | "enum_declaration" => {
            extract_ts_js_type(ctx, node, kind);
        }
        "function_declaration"
        | "generator_function_declaration"
        | "method_definition"
        | "method_signature" => {
            if let Some(sym) = extract_ts_js_function(ctx, node, enclosing_type) {
                *next_enclosing_fn = Some((sym.name.clone(), sym.start_line));
                ctx.symbols.push(sym);
            }
        }
        "variable_declarator" => {
            if let Some(sym) = extract_ts_js_arrow_or_const(ctx, node, enclosing_type, enclosing_fn)
            {
                *next_enclosing_fn = Some((sym.name.clone(), sym.start_line));
                ctx.symbols.push(sym);
            }
        }
        "import_statement" => {
            extract_ts_js_import(ctx, node, enclosing_fn);
        }
        "export_statement" => {
            if node.child_by_field_name("source").is_some() {
                extract_ts_js_import(ctx, node, enclosing_fn);
            }
        }
        "jsx_opening_element" | "jsx_self_closing_element" => {
            extract_jsx_component_use(ctx, node, enclosing_fn);
        }
        "call_expression" | "new_expression" => {
            extract_call_site(ctx, node, enclosing_fn);
        }
        _ => {}
    }
}

fn extract_jsx_component_use(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_fn: Option<(&str, usize)>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let raw_name = normalize_whitespace(node_text(name_node, ctx.bytes));
    let Some((callee_name, receiver_or_qualifier)) = parse_callee_expression(&raw_name) else {
        return;
    };
    if !callee_name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
    {
        return;
    }

    let (caller_name, caller_start_line) = match enclosing_fn {
        Some((name, start)) => (name.to_string(), start),
        None => ("<module_init>".to_string(), 1),
    };
    let call_line = node.start_position().row + 1;

    ctx.raw_calls.push(RawCallSite {
        caller_file: ctx.scanned.rel_path.clone(),
        caller_name,
        caller_start_line,
        callee_name,
        receiver_or_qualifier,
        call_line,
    });
}

fn extract_ts_js_method_visibility(
    node: Node<'_>,
    name: &str,
    is_exported: bool,
    enclosing_type: Option<&str>,
    bytes: &[u8],
) -> Visibility {
    if name.starts_with('#') {
        return Visibility::Private;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "accessibility_modifier" {
            match node_text(child, bytes).trim() {
                "private" => return Visibility::Private,
                "protected" => return Visibility::Protected,
                "public" => return Visibility::Public,
                _ => {}
            }
        }
    }
    let decl_header = extract_decl_header(node, bytes).trim_start();
    if decl_header.starts_with("private ") {
        Visibility::Private
    } else if decl_header.starts_with("protected ") {
        Visibility::Protected
    } else if is_exported
        || decl_header.starts_with("public ")
        || matches!(node.kind(), "method_definition" | "method_signature")
        || enclosing_type.is_some()
    {
        Visibility::Public
    } else {
        Visibility::Internal
    }
}

fn extract_ts_js_function(
    ctx: &ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
) -> Option<ExtractedSymbol> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return None;
    }

    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let doc_summary = extract_preceding_doc(ctx.lines, start_line);

    let is_exported = node
        .parent()
        .is_some_and(|p| p.kind() == "export_statement");
    let visibility =
        extract_ts_js_method_visibility(node, &name, is_exported, enclosing_type, ctx.bytes);
    let decl_header = extract_decl_header(node, ctx.bytes);

    let kind = classify_symbol_kind(
        &name,
        enclosing_type,
        false,
        visibility,
        ctx.current_layer(),
        decl_header,
        ctx.blueprint,
    );

    let qualified_name = match enclosing_type {
        Some(enc) => format!("{enc}::{name}"),
        None => name.clone(),
    };
    let symbol_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
    let signature = extract_clean_signature(node, ctx.bytes);

    Some(ExtractedSymbol {
        symbol_id,
        name,
        qualified_name,
        kind,
        visibility,
        file: ctx.scanned.rel_path.clone(),
        start_line,
        end_line,
        signature,
        doc_summary,
        enclosing_type: enclosing_type.map(ToOwned::to_owned),
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
    })
}

fn extract_ts_js_arrow_or_const(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
    enclosing_fn: Option<(&str, usize)>,
) -> Option<ExtractedSymbol> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() || !is_valid_identifier(&name) {
        return None;
    }
    let val_node = node.child_by_field_name("value")?;
    let vkind = val_node.kind();

    let decl_parent = node.parent().unwrap_or(node);
    let export_wrapper = decl_parent
        .parent()
        .filter(|p| p.kind() == "export_statement");
    let is_exported = export_wrapper.is_some();
    let outer_decl = export_wrapper.unwrap_or(decl_parent);

    if vkind == "arrow_function" || vkind == "function_expression" || vkind == "function" {
        let start_line = outer_decl.start_position().row + 1;
        let end_line = node.end_position().row + 1;
        let doc_summary = extract_preceding_doc(ctx.lines, start_line);
        let visibility = if is_exported {
            Visibility::Public
        } else {
            Visibility::Internal
        };
        let decl_header = extract_decl_header(outer_decl, ctx.bytes);
        let kind = classify_symbol_kind(
            &name,
            enclosing_type,
            false,
            visibility,
            ctx.current_layer(),
            decl_header,
            ctx.blueprint,
        );
        let qualified_name = match enclosing_type {
            Some(enc) => format!("{enc}::{name}"),
            None => name.clone(),
        };
        let symbol_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
        let signature = extract_clean_signature(outer_decl, ctx.bytes);

        return Some(ExtractedSymbol {
            symbol_id,
            name,
            qualified_name,
            kind,
            visibility,
            file: ctx.scanned.rel_path.clone(),
            start_line,
            end_line,
            signature,
            doc_summary,
            enclosing_type: enclosing_type.map(ToOwned::to_owned),
            scope: ctx.current_scope(),
            arch_layer: ctx.current_layer(),
            section_id: ctx.section_id.to_string(),
        });
    }

    if enclosing_fn.is_some() {
        return None;
    }

    // Exported function/handler alias: e.g. `export const GET = methodNotAllowed;`
    if is_exported && vkind == "identifier" {
        let target_ident = node_text(val_node, ctx.bytes).trim();
        let references_known_fn = ctx.symbols.iter().any(|s| s.name == target_ident);
        if is_http_method_handler(&name) || references_known_fn {
            let start_line = outer_decl.start_position().row + 1;
            let end_line = node.end_position().row + 1;
            let doc_summary = extract_preceding_doc(ctx.lines, start_line);
            let decl_header = extract_decl_header(outer_decl, ctx.bytes);
            let kind = classify_symbol_kind(
                &name,
                enclosing_type,
                false,
                Visibility::Public,
                ctx.current_layer(),
                decl_header,
                ctx.blueprint,
            );
            let qualified_name = match enclosing_type {
                Some(enc) => format!("{enc}::{name}"),
                None => name.clone(),
            };
            let symbol_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
            let signature = extract_clean_signature(outer_decl, ctx.bytes);

            if is_valid_identifier(target_ident) {
                ctx.raw_calls.push(RawCallSite {
                    caller_file: ctx.scanned.rel_path.clone(),
                    caller_name: name.clone(),
                    caller_start_line: start_line,
                    callee_name: target_ident.to_string(),
                    receiver_or_qualifier: None,
                    call_line: start_line,
                });
            }

            return Some(ExtractedSymbol {
                symbol_id,
                name,
                qualified_name,
                kind,
                visibility: Visibility::Public,
                file: ctx.scanned.rel_path.clone(),
                start_line,
                end_line,
                signature,
                doc_summary,
                enclosing_type: enclosing_type.map(ToOwned::to_owned),
                scope: ctx.current_scope(),
                arch_layer: ctx.current_layer(),
                section_id: ctx.section_id.to_string(),
            });
        }
    }

    // Check top-level SCREAMING_SNAKE_CASE constant or exported module constant
    let is_const_decl = node_text(decl_parent, ctx.bytes)
        .trim_start()
        .starts_with("const ");
    if is_screaming_snake_case(&name) || (is_exported && is_const_decl) {
        let raw_val = summarize_const_value_node(val_node, ctx.bytes);
        let (mut kind, hex_addr, mut description) =
            classify_macro_value_with_blueprint(&name, &raw_val, false, ctx.blueprint);
        if kind == MacroKind::ObjectMacro {
            kind = MacroKind::Constant;
            description = if is_exported {
                "Exported constant".to_string()
            } else {
                "Module constant".to_string()
            };
        }
        let line = node.start_position().row + 1;
        ctx.macros.push(ExtractedMacro {
            name,
            kind,
            value_or_args: truncate_str(&raw_val, 160),
            hex_addr,
            file: ctx.scanned.rel_path.clone(),
            line,
            scope: ctx.current_scope(),
            arch_layer: ctx.current_layer(),
            section_id: ctx.section_id.to_string(),
            description,
        });
    }

    None
}

fn is_http_method_handler(name: &str) -> bool {
    matches!(
        name,
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" | "ALL"
    )
}

fn extract_ts_js_type(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind_str: &str,
) -> Option<String> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return None;
    }

    let kind = match kind_str {
        "class_declaration" => TypeKind::Class,
        "interface_declaration" => TypeKind::Interface,
        "enum_declaration" => TypeKind::Enum,
        _ => TypeKind::TypeAlias,
    };

    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let doc_summary = extract_preceding_doc(ctx.lines, start_line);
    let is_exported = node
        .parent()
        .is_some_and(|p| p.kind() == "export_statement");
    let visibility = if is_exported {
        Visibility::Public
    } else {
        Visibility::Internal
    };
    let fields_summary = summarize_ts_js_type_fields(node, ctx.bytes);
    let type_id = format!("{}::{}", ctx.scanned.rel_path, name);

    ctx.types.push(ExtractedType {
        type_id,
        name: name.clone(),
        kind,
        visibility,
        file: ctx.scanned.rel_path.clone(),
        start_line,
        end_line,
        fields_summary,
        doc_summary,
        scope: ctx.current_scope(),
        arch_layer: ctx.current_layer(),
        section_id: ctx.section_id.to_string(),
    });

    Some(name)
}

fn summarize_ts_js_type_fields(node: Node<'_>, bytes: &[u8]) -> String {
    if node.kind() == "type_alias_declaration" {
        if let Some(val) = node.child_by_field_name("value") {
            return truncate_str(&normalize_whitespace(node_text(val, bytes)), 120);
        }
    }
    let Some(body) = node.child_by_field_name("body") else {
        return String::new();
    };
    let mut items = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        match child.kind() {
            "property_signature" | "public_field_definition" | "field_definition" => {
                let prop = normalize_whitespace(node_text(child, bytes))
                    .trim_end_matches(';')
                    .trim_end_matches(',')
                    .to_string();
                if !prop.is_empty() {
                    items.push(prop);
                }
            }
            "method_signature" | "method_definition" => {
                if let Some(mname) = child.child_by_field_name("name") {
                    items.push(format!("{}()", node_text(mname, bytes).trim()));
                }
            }
            "enum_assignment" | "property_identifier" => {
                let txt = normalize_whitespace(node_text(child, bytes));
                if !txt.is_empty() {
                    items.push(txt);
                }
            }
            _ => {}
        }
    }
    format_type_summary_items(items)
}

fn extract_ts_js_import(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_fn: Option<(&str, usize)>,
) {
    let Some(src_node) = node.child_by_field_name("source") else {
        return;
    };
    let raw_path = node_text(src_node, ctx.bytes)
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .to_string();
    if raw_path.is_empty() {
        return;
    }

    let is_system = !raw_path.starts_with('.') && !raw_path.starts_with('/');
    let mut imported_names = Vec::new();
    collect_ts_import_identifiers(node, ctx.bytes, &mut imported_names);

    let line = node.start_position().row + 1;
    let full = normalize_whitespace(node_text(node, ctx.bytes));
    for name in &imported_names {
        ctx.raw_xrefs.push(RawXrefSite {
            file: ctx.scanned.rel_path.clone(),
            line,
            enclosing_symbol: enclosing_fn.map(|(n, _)| n.to_string()),
            target_name: name.clone(),
            category: "import".to_string(),
            context: full.clone(),
        });
    }

    ctx.imports.push(ExtractedImport {
        file: ctx.scanned.rel_path.clone(),
        line,
        raw_path,
        imported_names,
        is_system,
    });
}

fn collect_ts_import_identifiers(node: Node<'_>, bytes: &[u8], out: &mut Vec<String>) {
    if node.kind() == "import_specifier" {
        let target = node
            .child_by_field_name("alias")
            .or_else(|| node.child_by_field_name("name"))
            .map(|n| node_text(n, bytes).trim().to_string());
        if let Some(t) = target {
            if !t.is_empty() {
                out.push(t);
            }
        }
        return;
    }
    if node.kind() == "identifier"
        && node
            .parent()
            .is_some_and(|p| p.kind() == "import_clause" || p.kind() == "namespace_import")
    {
        let txt = node_text(node, bytes).trim().to_string();
        if !txt.is_empty() {
            out.push(txt);
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_ts_import_identifiers(child, bytes, out);
    }
}

// ============================================================================
// Shared Call-Site & Symbol Classification Helpers
// ============================================================================

const RUST_STD_MACROS: &[&str] = &[
    "format",
    "println",
    "eprintln",
    "print",
    "eprint",
    "write",
    "writeln",
    "vec",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "panic",
    "todo",
    "unimplemented",
    "unreachable",
    "matches",
    "cfg",
    "env",
    "option_env",
    "include_str",
    "include_bytes",
    "concat",
    "stringify",
    "thread_local",
    "bail",
    "anyhow",
];

fn extract_rust_macro_invocation_calls(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_fn: Option<(&str, usize)>,
) {
    if let Some(macro_node) = node
        .child_by_field_name("macro")
        .or_else(|| node.named_child(0))
    {
        let raw_callee = normalize_whitespace(node_text(macro_node, ctx.bytes));
        if let Some((callee_name, mut receiver_or_qualifier)) = parse_callee_expression(&raw_callee)
        {
            if !RUST_STD_MACROS.contains(&callee_name.as_str()) {
                if let Some(ref qual) = receiver_or_qualifier {
                    if let Some(resolved_ty) =
                        resolve_local_receiver_type(qual, &ctx.local_var_types)
                    {
                        receiver_or_qualifier = Some(resolved_ty);
                    }
                }
                let (caller_name, caller_start_line) = match enclosing_fn {
                    Some((name, start)) => (name.to_string(), start),
                    None => ("<module_init>".to_string(), 1),
                };
                let call_line = node.start_position().row + 1;
                ctx.raw_calls.push(RawCallSite {
                    caller_file: ctx.scanned.rel_path.clone(),
                    caller_name,
                    caller_start_line,
                    callee_name,
                    receiver_or_qualifier,
                    call_line,
                });
            }
        }
    }

    // Scan the macro's `token_tree` arguments for nested function calls (e.g. `format!("{}", escape_table(x))`)
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "token_tree" {
            extract_calls_from_rust_token_tree(ctx, child, enclosing_fn);
        }
    }
}

fn extract_calls_from_rust_token_tree(
    ctx: &mut ExtractContext<'_>,
    tt_node: Node<'_>,
    enclosing_fn: Option<(&str, usize)>,
) {
    let mut cursor = tt_node.walk();
    let children: Vec<Node<'_>> = tt_node.children(&mut cursor).collect();

    for i in 0..children.len() {
        let cur = children[i];
        if cur.kind() == "token_tree" {
            let cur_txt = node_text(cur, ctx.bytes).trim();
            if cur_txt.starts_with('(') && i > 0 {
                let prev = children[i - 1];
                if prev.kind() == "identifier" {
                    let callee_leaf = node_text(prev, ctx.bytes).trim();
                    if is_valid_identifier(callee_leaf)
                        && !matches!(
                            callee_leaf,
                            "if" | "else"
                                | "match"
                                | "while"
                                | "for"
                                | "loop"
                                | "return"
                                | "Some"
                                | "Ok"
                                | "Err"
                        )
                    {
                        // Reconstruct optional `Type::` or `recv.` qualifier preceding `prev`
                        let mut qualifier: Option<String> = None;
                        if i >= 3 {
                            let sep = node_text(children[i - 2], ctx.bytes).trim();
                            let before_sep = node_text(children[i - 3], ctx.bytes).trim();
                            if (sep == "::" || sep == ".") && is_valid_identifier(before_sep) {
                                qualifier = Some(before_sep.to_string());
                            }
                        }
                        if let Some(ref qual) = qualifier {
                            if let Some(resolved_ty) =
                                resolve_local_receiver_type(qual, &ctx.local_var_types)
                            {
                                qualifier = Some(resolved_ty);
                            }
                        }
                        let (caller_name, caller_start_line) = match enclosing_fn {
                            Some((name, start)) => (name.to_string(), start),
                            None => ("<module_init>".to_string(), 1),
                        };
                        let call_line = prev.start_position().row + 1;
                        ctx.raw_calls.push(RawCallSite {
                            caller_file: ctx.scanned.rel_path.clone(),
                            caller_name,
                            caller_start_line,
                            callee_name: callee_leaf.to_string(),
                            receiver_or_qualifier: qualifier,
                            call_line,
                        });
                    }
                }
            }
            extract_calls_from_rust_token_tree(ctx, cur, enclosing_fn);
        }
    }
}

fn extract_call_site(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_fn: Option<(&str, usize)>,
) {
    let callee_expr = if node.kind() == "macro_invocation" {
        node.child_by_field_name("macro")
            .or_else(|| node.named_child(0))
    } else {
        node.child_by_field_name("function")
            .or_else(|| node.child_by_field_name("constructor"))
            .or_else(|| node.named_child(0))
    };

    let Some(callee_node) = callee_expr else {
        return;
    };

    let raw_callee = normalize_whitespace(node_text(callee_node, ctx.bytes));
    let Some((callee_name, mut receiver_or_qualifier)) = parse_callee_expression(&raw_callee)
    else {
        return;
    };

    // Idea 3: Resolve local variable / parameter receiver (`uart.send()`) to its static type (`UartDriver`)
    if let Some(ref qual) = receiver_or_qualifier {
        if let Some(resolved_ty) = resolve_local_receiver_type(qual, &ctx.local_var_types) {
            receiver_or_qualifier = Some(resolved_ty);
        }
    }

    let (caller_name, caller_start_line) = match enclosing_fn {
        Some((name, start)) => (name.to_string(), start),
        None => ("<module_init>".to_string(), 1),
    };

    let call_line = node.start_position().row + 1;

    ctx.raw_calls.push(RawCallSite {
        caller_file: ctx.scanned.rel_path.clone(),
        caller_name,
        caller_start_line,
        callee_name,
        receiver_or_qualifier,
        call_line,
    });
}

fn parse_callee_expression(raw: &str) -> Option<(String, Option<String>)> {
    let mut cleaned = raw.trim().trim_end_matches('!');
    // Strip trailing Rust turbofish `::<...>` or C++/TS generic `<...>`
    if let Some((before_gen, _)) = cleaned.rsplit_once("::<") {
        cleaned = before_gen.trim();
    } else if cleaned.ends_with('>') {
        if let Some((before_gen, _)) = cleaned.rsplit_once('<') {
            cleaned = before_gen.trim();
        }
    }

    if cleaned.is_empty() {
        return None;
    }

    let (qualifier, leaf) = if let Some((q, l)) = cleaned.rsplit_once("::") {
        (Some(q.trim().to_string()), l.trim())
    } else if let Some((q, l)) = cleaned.rsplit_once("->") {
        (Some(q.trim().to_string()), l.trim())
    } else if let Some((q, l)) = cleaned.rsplit_once("?.") {
        (Some(q.trim().to_string()), l.trim())
    } else if let Some((q, l)) = cleaned.rsplit_once('.') {
        (Some(q.trim().trim_end_matches('?').to_string()), l.trim())
    } else {
        (None, cleaned)
    };

    if !is_valid_identifier(leaf) {
        return None;
    }

    let qualifier = qualifier.filter(|q| !q.is_empty());
    Some((leaf.to_string(), qualifier))
}

#[allow(clippy::too_many_arguments)]
fn classify_symbol_kind(
    name: &str,
    enclosing_type: Option<&str>,
    has_isr_attr: bool,
    visibility: Visibility,
    arch_layer: ArchLayer,
    decl_header: &str,
    blueprint: Option<&RepoBlueprint>,
) -> SymbolKind {
    // 0. Blueprint overrides for entrypoints and ISR patterns
    if let Some(bp) = blueprint {
        if bp.entrypoints.iter().any(|e| e == name) {
            return SymbolKind::Entrypoint;
        }
        if bp.isr_patterns.iter().any(|pat| {
            !pat.is_empty()
                && (name == pat
                    || name.ends_with(pat.as_str())
                    || name.starts_with(pat.as_str())
                    || decl_header.contains(pat.as_str()))
        }) {
            return SymbolKind::Isr;
        }
    }

    // 1. Entrypoints (`main`, `Reset_Handler`, `app_main`, `setup`, `loop`, etc.)
    if matches!(
        name,
        "main" | "Reset_Handler" | "app_main" | "setup" | "loop" | "_start" | "SystemInit"
    ) {
        return SymbolKind::Entrypoint;
    }

    // 2. ISR handlers (checked strictly against `decl_header` and `has_isr_attr`, never the function body)
    let is_isr_name = name.ends_with("IRQHandler")
        || name.ends_with("IrqHandler")
        || name.ends_with("_ISR")
        || (name.ends_with("_Handler")
            && !matches!(
                name,
                "Error_Handler" | "Assert_Handler" | "assert_failed" | "Default_Handler_Weak"
            ));
    if has_isr_attr
        || is_isr_name
        || name.starts_with("ISR(")
        || name.starts_with("SIGNAL(")
        || name.starts_with("__vector_")
        || decl_header.contains("__irq")
        || (decl_header.contains("interrupt") && decl_header.contains("#["))
    {
        return SymbolKind::Isr;
    }

    // 3. Constructors
    if matches!(
        name,
        "__init__" | "__new__" | "new" | "constructor" | "default"
    ) || (enclosing_type.is_some() && (name.starts_with("new_") || enclosing_type == Some(name)))
    {
        return SymbolKind::Constructor;
    }

    // 4. Methods inside an enclosing class/struct/trait/impl/interface
    if enclosing_type.is_some() {
        return SymbolKind::Method;
    }

    // 5. Top-level CLI/API/App entrypoints
    let has_route_evidence = decl_header.contains("@app.")
        || decl_header.contains("@router.")
        || decl_header.contains("#[get")
        || decl_header.contains("#[post")
        || decl_header.contains("#[put")
        || decl_header.contains("#[delete")
        || decl_header.contains("app.get(")
        || decl_header.contains("router.");
    let is_handle_entrypoint = name.starts_with("handle_")
        && (has_route_evidence
            || (arch_layer == ArchLayer::Api && visibility == Visibility::Public));

    if matches!(arch_layer, ArchLayer::Cli | ArchLayer::Api | ArchLayer::App)
        && (name.starts_with("cmd_")
            || is_handle_entrypoint
            || is_http_method_handler(name)
            || has_route_evidence)
    {
        return SymbolKind::Entrypoint;
    }

    SymbolKind::Function
}

// ============================================================================
// Ideas 3, 4 & 5: Local Type Binding, Fn-Ptr Candidates & Field Mutability
// ============================================================================

fn resolve_local_receiver_type(
    raw_qual: &str,
    local_var_types: &FxHashMap<String, String>,
) -> Option<String> {
    let trimmed = raw_qual
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim_start_matches('*')
        .trim();
    if let Some(ty) = local_var_types.get(trimmed) {
        return Some(ty.clone());
    }
    let stripped_self = trimmed
        .strip_prefix("self.")
        .or_else(|| trimmed.strip_prefix("this."))
        .or_else(|| trimmed.strip_prefix("this->"));
    if let Some(field_key) = stripped_self {
        if let Some(ty) = local_var_types.get(field_key.trim()) {
            return Some(ty.clone());
        }
    }
    None
}

fn clean_type_name(raw_type: &str) -> Option<String> {
    let mut s = raw_type
        .trim()
        .trim_start_matches(':')
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim_start_matches("const ")
        .trim_start_matches("volatile ")
        .trim_start_matches("struct ")
        .trim_start_matches("class ")
        .trim_start_matches("enum ")
        .trim_start_matches("interface ")
        .trim_start_matches("dyn ")
        .trim_start_matches("impl ")
        .trim_end_matches('*')
        .trim_end_matches('&')
        .trim_end_matches("const")
        .trim();

    // Unwrap common smart-pointer / container wrappers (`Arc<T>`, `Box<T>`, `Rc<T>`, `Mutex<T>`, `RefCell<T>`, `Option<T>`, `std::unique_ptr<T>`, `std::shared_ptr<T>`)
    for wrapper in [
        "Arc<",
        "Box<",
        "Rc<",
        "Mutex<",
        "RwLock<",
        "RefCell<",
        "Option<",
        "NonNull<",
        "Pin<",
        "unique_ptr<",
        "shared_ptr<",
        "std::unique_ptr<",
        "std::shared_ptr<",
    ] {
        if let Some(inner) = s.strip_prefix(wrapper).and_then(|r| r.strip_suffix('>')) {
            s = inner
                .trim()
                .trim_start_matches('&')
                .trim_start_matches("mut ")
                .trim_start_matches("dyn ")
                .trim_end_matches('*')
                .trim();
        }
    }

    // Strip generic parameters `<...>` or array `[...]`
    if let Some((before_gen, _)) = s.split_once('<') {
        s = before_gen.trim();
    }
    if let Some((before_arr, _)) = s.split_once('[') {
        s = before_arr.trim();
    }
    // Take leaf identifier after `::` or `.`
    if let Some((_, leaf)) = s.rsplit_once("::") {
        s = leaf.trim();
    } else if let Some((_, leaf)) = s.rsplit_once('.') {
        s = leaf.trim();
    }

    if !is_valid_identifier(s) || is_builtin_or_primitive_type(s) {
        return None;
    }
    Some(s.to_string())
}

/// Extracts the element or payload type `T` from collection, slice, iterator, option, result,
/// or map type annotations (`&[T]`, `&mut [T]`, `Vec<T>`, `Option<T>`, `Box<[T]>`,
/// `impl Iterator<Item = T>`, `[T; N]`, `List[T]`, `T[]`, `Array<T>`, `BTreeMap<K, V>`).
fn elem_type_of(raw_type: &str) -> Option<String> {
    let mut s = raw_type
        .trim()
        .trim_start_matches(':')
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim_start_matches("const ")
        .trim();

    if let Some(after_item) = s.find("Item") {
        let rest = &s[after_item + 4..];
        if let Some(eq_idx) = rest.find('=') {
            let after_eq = rest[eq_idx + 1..].trim();
            let inner = after_eq.split(['>', ',']).next().unwrap_or(after_eq).trim();
            return elem_type_of(inner).or_else(|| clean_type_name(inner));
        }
    }

    if let Some(inner) = s.strip_prefix("Box<[").and_then(|r| r.strip_suffix("]>")) {
        return elem_type_of(inner).or_else(|| clean_type_name(inner));
    }

    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        let elem_part = inner.split(';').next().unwrap_or(inner).trim();
        return elem_type_of(elem_part).or_else(|| clean_type_name(elem_part));
    }

    if let Some(inner) = s.strip_suffix("[]") {
        return elem_type_of(inner).or_else(|| clean_type_name(inner));
    }

    if let Some((wrapper, rest)) = s.split_once('<') {
        if let Some(inner) = rest.strip_suffix('>') {
            let w_leaf = wrapper
                .trim()
                .rsplit_once("::")
                .map(|(_, l)| l.trim())
                .unwrap_or(wrapper.trim());
            match w_leaf {
                "Vec" | "Option" | "Array" | "ReadonlyArray" | "Set" | "BTreeSet" | "HashSet"
                | "FxHashSet" | "VecDeque" | "SmallVec" | "LinkedList" | "Arc" | "Rc" | "Box" => {
                    return elem_type_of(inner).or_else(|| clean_type_name(inner));
                }
                "Result" => {
                    let ok_part = split_top_level_comma(inner)
                        .first()
                        .copied()
                        .unwrap_or(inner);
                    return elem_type_of(ok_part).or_else(|| clean_type_name(ok_part));
                }
                "BTreeMap" | "HashMap" | "FxHashMap" | "Map" => {
                    let parts = split_top_level_comma(inner);
                    if parts.len() >= 2 {
                        let val_part = parts[1];
                        return elem_type_of(val_part).or_else(|| clean_type_name(val_part));
                    }
                }
                _ => {}
            }
        }
    }

    if let Some((wrapper, rest)) = s.split_once('[') {
        if let Some(inner) = rest.strip_suffix(']') {
            let w_leaf = wrapper
                .trim()
                .rsplit_once('.')
                .map(|(_, l)| l.trim())
                .unwrap_or(wrapper.trim());
            if matches!(
                w_leaf,
                "List" | "list" | "Sequence" | "Iterable" | "Optional" | "Set" | "set" | "Tuple"
            ) {
                let first_part = split_top_level_comma(inner)
                    .first()
                    .copied()
                    .unwrap_or(inner);
                return elem_type_of(first_part).or_else(|| clean_type_name(first_part));
            }
        }
    }

    s = s.trim_end_matches('*').trim();
    let _ = s;
    None
}

fn split_top_level_comma(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (idx, ch) in s.char_indices() {
        match ch {
            '<' | '(' | '[' | '{' => depth += 1,
            '>' | ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(s[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    out.push(s[start..].trim());
    out
}

fn extract_root_collection_ident(expr_txt: &str) -> Option<&str> {
    let mut s = expr_txt.trim();
    while let Some(rest) = s
        .strip_prefix('&')
        .or_else(|| s.strip_prefix("mut "))
        .or_else(|| s.strip_prefix('*'))
        .or_else(|| s.strip_prefix('('))
    {
        s = rest.trim();
    }
    let head = s
        .split(['.', '(', '[', '?'])
        .next()
        .unwrap_or(s)
        .trim()
        .trim_end_matches(')');
    if is_valid_identifier(head) {
        Some(head)
    } else {
        None
    }
}

fn resolve_collection_elem_type(
    expr_txt: &str,
    local_collection_elem_types: &FxHashMap<String, String>,
    local_var_types: &FxHashMap<String, String>,
) -> Option<String> {
    if let Some(root) = extract_root_collection_ident(expr_txt) {
        if let Some(elem_ty) = local_collection_elem_types.get(root) {
            return Some(elem_ty.clone());
        }
        if let Some(var_ty) = local_var_types.get(root) {
            return Some(var_ty.clone());
        }
    }
    None
}

fn clean_loop_pattern_ident(raw_pat: &str) -> Option<String> {
    let mut s = raw_pat.trim();
    for prefix in ["const ", "let ", "var ", "auto "] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.trim();
        }
    }
    loop {
        if let Some(rest) = s.strip_prefix('&') {
            s = rest.trim();
        } else if let Some(rest) = s.strip_prefix("mut ") {
            s = rest.trim();
        } else if let Some(rest) = s.strip_prefix("ref ") {
            s = rest.trim();
        } else if let Some(rest) = s.strip_prefix('*') {
            s = rest.trim();
        } else {
            break;
        }
    }
    if is_valid_identifier(s) {
        Some(s.to_string())
    } else {
        None
    }
}

fn extract_unwrapped_pattern_ident(raw_pat: &str) -> Option<String> {
    let trimmed = raw_pat.trim();
    for wrapper in ["Some(", "Ok(", "Err("] {
        if let Some(inner) = trimmed
            .strip_prefix(wrapper)
            .and_then(|r| r.strip_suffix(')'))
        {
            return clean_loop_pattern_ident(inner);
        }
    }
    None
}

fn is_builtin_or_primitive_type(s: &str) -> bool {
    matches!(
        s,
        "void"
            | "int"
            | "char"
            | "short"
            | "long"
            | "float"
            | "double"
            | "bool"
            | "_Bool"
            | "auto"
            | "var"
            | "let"
            | "const"
            | "unsigned"
            | "signed"
            | "size_t"
            | "ssize_t"
            | "uintptr_t"
            | "intptr_t"
            | "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "u8"
            | "u16"
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
            | "f32"
            | "f64"
            | "str"
            | "String"
            | "string"
            | "number"
            | "boolean"
            | "any"
            | "unknown"
            | "never"
            | "object"
            | "dict"
            | "list"
            | "tuple"
            | "set"
            | "bytes"
            | "Self"
    )
}

fn extract_function_parameters(ctx: &mut ExtractContext<'_>, fn_node: Node<'_>) {
    let params_node = fn_node.child_by_field_name("parameters").or_else(|| {
        fn_node
            .child_by_field_name("declarator")
            .and_then(|d| find_descendant_by_kind(d, "parameter_list"))
    });
    let Some(params) = params_node else {
        return;
    };

    let mut cursor = params.walk();
    for param in params.children(&mut cursor) {
        match param.kind() {
            "parameter_declaration" => {
                // C/C++ parameter: `type` + `declarator`
                let var_name = param
                    .child_by_field_name("declarator")
                    .and_then(|d| extract_declarator_name(d, ctx.bytes))
                    .map(|s| {
                        s.trim_start_matches('*')
                            .trim_start_matches('&')
                            .trim()
                            .to_string()
                    });
                let raw_ty = param
                    .child_by_field_name("type")
                    .map(|t| node_text(t, ctx.bytes));
                let ty_name = raw_ty.and_then(clean_type_name);
                let elem_ty = raw_ty.and_then(elem_type_of);
                if let Some(vn) = var_name {
                    if is_valid_identifier(&vn) {
                        ctx.local_vars.insert(vn.clone());
                        if let Some(et) = elem_ty {
                            ctx.local_collection_elem_types.insert(vn.clone(), et);
                        }
                        if let Some(tn) = ty_name {
                            ctx.local_var_types.insert(vn, tn);
                        }
                    }
                }
            }
            "parameter" => {
                // Rust parameter: `pattern` + `type`
                let var_name = param.child_by_field_name("pattern").map(|p| {
                    node_text(p, ctx.bytes)
                        .trim()
                        .trim_start_matches("mut ")
                        .trim_start_matches('&')
                        .trim()
                        .to_string()
                });
                let raw_ty = param
                    .child_by_field_name("type")
                    .map(|t| node_text(t, ctx.bytes));
                let ty_name = raw_ty.and_then(clean_type_name);
                let elem_ty = raw_ty.and_then(elem_type_of);
                if let Some(vn) = var_name {
                    if is_valid_identifier(&vn) {
                        ctx.local_vars.insert(vn.clone());
                        if let Some(et) = elem_ty {
                            ctx.local_collection_elem_types.insert(vn.clone(), et);
                        }
                        if let Some(tn) = ty_name {
                            ctx.local_var_types.insert(vn, tn);
                        }
                    }
                }
            }
            "typed_parameter" | "typed_default_parameter" | "default_parameter" | "identifier" => {
                // Python parameter
                let var_name = if param.kind() == "identifier" {
                    Some(node_text(param, ctx.bytes).trim().to_string())
                } else {
                    param
                        .child_by_field_name("name")
                        .or_else(|| param.named_child(0))
                        .map(|n| node_text(n, ctx.bytes).trim().to_string())
                };
                let raw_ty = param
                    .child_by_field_name("type")
                    .map(|t| node_text(t, ctx.bytes));
                let ty_name = raw_ty.and_then(clean_type_name);
                let elem_ty = raw_ty.and_then(elem_type_of);
                if let Some(vn) = var_name {
                    if is_valid_identifier(&vn) && vn != "self" && vn != "cls" {
                        ctx.local_vars.insert(vn.clone());
                        if let Some(et) = elem_ty {
                            ctx.local_collection_elem_types.insert(vn.clone(), et);
                        }
                        if let Some(tn) = ty_name {
                            ctx.local_var_types.insert(vn, tn);
                        }
                    }
                }
            }
            "required_parameter" | "optional_parameter" => {
                // TS/JS parameter
                let var_name = param
                    .child_by_field_name("pattern")
                    .or_else(|| param.named_child(0))
                    .map(|p| node_text(p, ctx.bytes).trim().to_string());
                let raw_ty = param
                    .child_by_field_name("type")
                    .map(|t| node_text(t, ctx.bytes));
                let ty_name = raw_ty.and_then(clean_type_name);
                let elem_ty = raw_ty.and_then(elem_type_of);
                if let Some(vn) = var_name {
                    if is_valid_identifier(&vn) && vn != "this" {
                        ctx.local_vars.insert(vn.clone());
                        if let Some(et) = elem_ty {
                            ctx.local_collection_elem_types.insert(vn.clone(), et);
                        }
                        if let Some(tn) = ty_name {
                            ctx.local_var_types.insert(vn, tn);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn find_descendant_by_kind<'a>(node: Node<'a>, target_kind: &str) -> Option<Node<'a>> {
    if node.kind() == target_kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_descendant_by_kind(child, target_kind) {
            return Some(found);
        }
    }
    None
}

fn infer_type_from_init_expr(val_node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match val_node.kind() {
        "new_expression" => val_node
            .child_by_field_name("constructor")
            .or_else(|| val_node.named_child(0))
            .map(|n| node_text(n, bytes))
            .and_then(clean_type_name),
        "struct_expression" => val_node
            .child_by_field_name("name")
            .map(|n| node_text(n, bytes))
            .and_then(clean_type_name),
        "call_expression" | "call" => {
            let func_node = val_node
                .child_by_field_name("function")
                .or_else(|| val_node.named_child(0))?;
            let raw_fn = normalize_whitespace(node_text(func_node, bytes));
            let (callee_name, qualifier) = parse_callee_expression(&raw_fn)?;
            if matches!(
                callee_name.as_str(),
                "new" | "default" | "init" | "create" | "open" | "from" | "build"
            ) {
                if let Some(q) = qualifier {
                    return clean_type_name(&q);
                }
            }
            // Direct constructor call (`MotorController(...)` in Python/C++)
            if callee_name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase())
                && !is_screaming_snake_case(&callee_name)
            {
                return clean_type_name(&callee_name);
            }
            None
        }
        _ => None,
    }
}

fn extract_local_var_binding(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind: &str,
    enclosing_fn: Option<(&str, usize)>,
) {
    if enclosing_fn.is_none() {
        return;
    }

    match kind {
        "declaration" => {
            // C/C++ local variable declaration: `UartDriver uart;` or `auto drv = UartDriver::create();`
            let explicit_ty = node
                .child_by_field_name("type")
                .map(|t| node_text(t, ctx.bytes))
                .and_then(clean_type_name);

            let mut cursor = node.walk();
            for child in node.children_by_field_name("declarator", &mut cursor) {
                let (var_name, init_val) = if child.kind() == "init_declarator" {
                    let vn = child
                        .child_by_field_name("declarator")
                        .and_then(|d| extract_declarator_name(d, ctx.bytes));
                    let val = child.child_by_field_name("value");
                    (vn, val)
                } else {
                    (extract_declarator_name(child, ctx.bytes), None)
                };

                if let Some(raw_vn) = var_name {
                    let vn = raw_vn
                        .trim_start_matches('*')
                        .trim_start_matches('&')
                        .trim()
                        .to_string();
                    if is_valid_identifier(&vn) {
                        ctx.local_vars.insert(vn.clone());
                        let resolved_ty = explicit_ty.clone().or_else(|| {
                            init_val.and_then(|v| infer_type_from_init_expr(v, ctx.bytes))
                        });
                        if let Some(ty) = resolved_ty {
                            ctx.local_var_types.insert(vn, ty);
                        }
                    }
                }
            }
        }
        "let_declaration" => {
            // Rust `let [mut] var[: Type] = expr;` or `let (a, b)[: (TA, TB)] = expr;`
            let Some(pat) = node.child_by_field_name("pattern") else {
                return;
            };
            let raw_ty = node
                .child_by_field_name("type")
                .map(|t| node_text(t, ctx.bytes));

            if pat.kind() == "tuple_pattern" {
                let pat_inner = node_text(pat, ctx.bytes)
                    .trim()
                    .trim_start_matches('(')
                    .trim_end_matches(')');
                let pat_vars: Vec<&str> = split_top_level_comma(pat_inner);
                let ty_elems: Vec<&str> = raw_ty
                    .map(|rt| {
                        let inner = rt.trim().trim_start_matches('(').trim_end_matches(')');
                        split_top_level_comma(inner)
                    })
                    .unwrap_or_default();

                for (idx, raw_v) in pat_vars.into_iter().enumerate() {
                    if let Some(vn) = clean_loop_pattern_ident(raw_v) {
                        ctx.local_vars.insert(vn.clone());
                        if let Some(&ty_str) = ty_elems.get(idx) {
                            if let Some(et) = elem_type_of(ty_str) {
                                ctx.local_collection_elem_types.insert(vn.clone(), et);
                            }
                            if let Some(tn) = clean_type_name(ty_str) {
                                ctx.local_var_types.insert(vn, tn);
                            }
                        }
                    }
                }
                return;
            }

            let Some(vn) = clean_loop_pattern_ident(node_text(pat, ctx.bytes)) else {
                return;
            };
            ctx.local_vars.insert(vn.clone());

            let elem_ty = raw_ty.and_then(elem_type_of).or_else(|| {
                node.child_by_field_name("value").and_then(|v| {
                    resolve_collection_elem_type(
                        node_text(v, ctx.bytes),
                        &ctx.local_collection_elem_types,
                        &ctx.local_var_types,
                    )
                })
            });
            if let Some(et) = elem_ty {
                ctx.local_collection_elem_types.insert(vn.clone(), et);
            }

            let resolved_ty = raw_ty.and_then(clean_type_name).or_else(|| {
                node.child_by_field_name("value")
                    .and_then(|v| infer_type_from_init_expr(v, ctx.bytes))
            });
            if let Some(ty) = resolved_ty {
                ctx.local_var_types.insert(vn, ty);
            }
        }
        "let_condition" => {
            // Rust `if let Some(x) = expr` / `while let Ok(x) = expr`
            let Some(pat) = node.child_by_field_name("pattern") else {
                return;
            };
            let Some(vn) = extract_unwrapped_pattern_ident(node_text(pat, ctx.bytes)) else {
                return;
            };
            ctx.local_vars.insert(vn.clone());
            if let Some(val_node) = node.child_by_field_name("value") {
                let val_txt = node_text(val_node, ctx.bytes);
                let resolved_ty = resolve_collection_elem_type(
                    val_txt,
                    &ctx.local_collection_elem_types,
                    &ctx.local_var_types,
                )
                .or_else(|| infer_type_from_init_expr(val_node, ctx.bytes));
                if let Some(ty) = resolved_ty {
                    ctx.local_var_types.insert(vn, ty);
                }
            }
        }
        "for_expression" => {
            // Rust `for var in expr { ... }`
            let Some(pat) = node.child_by_field_name("pattern") else {
                return;
            };
            let Some(vn) = clean_loop_pattern_ident(node_text(pat, ctx.bytes)) else {
                return;
            };
            ctx.local_vars.insert(vn.clone());
            if let Some(val_node) = node.child_by_field_name("value") {
                let val_txt = node_text(val_node, ctx.bytes);
                if let Some(ty) = resolve_collection_elem_type(
                    val_txt,
                    &ctx.local_collection_elem_types,
                    &ctx.local_var_types,
                ) {
                    ctx.local_var_types.insert(vn, ty);
                }
            }
        }
        "for_statement" | "for_in_statement" | "for_of_statement" => {
            // Python `for x in items:` and JS/TS `for (const x of items)` / `for (const k in obj)`
            let Some(left) = node.child_by_field_name("left") else {
                return;
            };
            let Some(vn) = clean_loop_pattern_ident(node_text(left, ctx.bytes)) else {
                return;
            };
            ctx.local_vars.insert(vn.clone());
            if let Some(right) = node.child_by_field_name("right") {
                let right_txt = node_text(right, ctx.bytes);
                if let Some(ty) = resolve_collection_elem_type(
                    right_txt,
                    &ctx.local_collection_elem_types,
                    &ctx.local_var_types,
                ) {
                    ctx.local_var_types.insert(vn, ty);
                }
            }
        }
        "for_range_loop" => {
            // C++ `for (const auto& x : items)`
            let decl = node.child_by_field_name("declarator");
            let vn_opt = decl
                .and_then(|d| extract_declarator_name(d, ctx.bytes))
                .and_then(|s| clean_loop_pattern_ident(&s));
            let Some(vn) = vn_opt else {
                return;
            };
            ctx.local_vars.insert(vn.clone());
            let explicit_ty = node
                .child_by_field_name("type")
                .map(|t| node_text(t, ctx.bytes))
                .and_then(clean_type_name);
            let resolved_ty = explicit_ty.or_else(|| {
                node.child_by_field_name("right").and_then(|r| {
                    resolve_collection_elem_type(
                        node_text(r, ctx.bytes),
                        &ctx.local_collection_elem_types,
                        &ctx.local_var_types,
                    )
                })
            });
            if let Some(ty) = resolved_ty {
                ctx.local_var_types.insert(vn, ty);
            }
        }
        "closure_expression" => {
            // Rust closure `|unit| { ... }` inside `.filter(|unit| ...)` / `.map(|unit| ...)`
            let Some(params) = node.child_by_field_name("parameters") else {
                return;
            };
            let raw_params = node_text(params, ctx.bytes).trim().trim_matches('|').trim();
            if raw_params.contains(',') || raw_params.is_empty() {
                return;
            }
            let (raw_pat, explicit_ty) = match raw_params.split_once(':') {
                Some((p, t)) => (p.trim(), clean_type_name(t)),
                None => (raw_params, None),
            };
            let Some(vn) = clean_loop_pattern_ident(raw_pat) else {
                return;
            };
            ctx.local_vars.insert(vn.clone());
            if let Some(ty) = explicit_ty {
                ctx.local_var_types.insert(vn, ty);
                return;
            }
            if let Some(call_parent) = node
                .parent()
                .and_then(|p| p.parent())
                .filter(|gp| gp.kind() == "call_expression")
            {
                if let Some(fn_node) = call_parent.child_by_field_name("function") {
                    let fn_txt = node_text(fn_node, ctx.bytes);
                    if let Some(ty) = resolve_collection_elem_type(
                        fn_txt,
                        &ctx.local_collection_elem_types,
                        &ctx.local_var_types,
                    ) {
                        ctx.local_var_types.insert(vn, ty);
                    }
                }
            }
        }
        "assignment" => {
            // Python local variable or `self.field` binding
            let Some(left) = node.child_by_field_name("left") else {
                return;
            };
            let raw_left = node_text(left, ctx.bytes).trim();
            let vn = raw_left
                .strip_prefix("self.")
                .unwrap_or(raw_left)
                .trim()
                .to_string();
            if !is_valid_identifier(&vn) {
                return;
            }
            if !raw_left.starts_with("self.") {
                ctx.local_vars.insert(vn.clone());
            }
            let raw_ty = node
                .child_by_field_name("type")
                .map(|t| node_text(t, ctx.bytes));
            if let Some(et) = raw_ty.and_then(elem_type_of) {
                ctx.local_collection_elem_types.insert(vn.clone(), et);
            }
            let resolved_ty = raw_ty.and_then(clean_type_name).or_else(|| {
                node.child_by_field_name("right")
                    .and_then(|v| infer_type_from_init_expr(v, ctx.bytes))
            });
            if let Some(ty) = resolved_ty {
                ctx.local_var_types.insert(vn, ty);
            }
        }
        "variable_declarator" => {
            // TS/JS local variable binding (`const svc: AuthService = ...` or `const svc = new AuthService()`)
            if matches!(
                ctx.scanned.language,
                LanguageKind::TypeScript
                    | LanguageKind::Tsx
                    | LanguageKind::JavaScript
                    | LanguageKind::Jsx
            ) {
                let Some(name_node) = node.child_by_field_name("name") else {
                    return;
                };
                let vn = node_text(name_node, ctx.bytes).trim().to_string();
                if !is_valid_identifier(&vn) {
                    return;
                }
                ctx.local_vars.insert(vn.clone());
                let raw_ty = node
                    .child_by_field_name("type")
                    .map(|t| node_text(t, ctx.bytes));
                if let Some(et) = raw_ty.and_then(elem_type_of) {
                    ctx.local_collection_elem_types.insert(vn.clone(), et);
                }
                let resolved_ty = raw_ty.and_then(clean_type_name).or_else(|| {
                    node.child_by_field_name("value")
                        .and_then(|v| infer_type_from_init_expr(v, ctx.bytes))
                });
                if let Some(ty) = resolved_ty {
                    ctx.local_var_types.insert(vn, ty);
                }
            }
        }
        _ => {}
    }
}

fn extract_candidate_fn_identifier(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" => {
            let txt = node_text(node, bytes).trim();
            if is_valid_identifier(txt) {
                Some(txt.to_string())
            } else {
                None
            }
        }
        "scoped_identifier" | "qualified_identifier" => {
            let txt = normalize_whitespace(node_text(node, bytes));
            let (_, leaf) = txt.rsplit_once("::")?;
            let leaf = leaf.trim();
            if is_valid_identifier(leaf) {
                Some(leaf.to_string())
            } else {
                None
            }
        }
        "pointer_expression" | "reference_expression" | "unary_expression" => {
            let txt = node_text(node, bytes).trim();
            if let Some(rest) = txt.strip_prefix('&') {
                let clean = rest.trim();
                if is_valid_identifier(clean) {
                    return Some(clean.to_string());
                }
                if let Some((_, leaf)) = clean.rsplit_once("::") {
                    if is_valid_identifier(leaf.trim()) {
                        return Some(leaf.trim().to_string());
                    }
                }
            }
            None
        }
        "cast_expression" | "parenthesized_expression" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() != "type_descriptor" && child.kind() != "type_identifier" {
                    if let Some(found) = extract_candidate_fn_identifier(child, bytes) {
                        return Some(found);
                    }
                }
            }
            None
        }
        "keyword_argument" => node
            .child_by_field_name("value")
            .and_then(|v| extract_candidate_fn_identifier(v, bytes)),
        _ => None,
    }
}

fn is_plausible_fn_ptr_identifier(ident: &str, local_vars: &FxHashSet<String>) -> bool {
    if !is_valid_identifier(ident) || local_vars.contains(ident) {
        return false;
    }
    if matches!(
        ident,
        "self"
            | "this"
            | "cls"
            | "true"
            | "false"
            | "TRUE"
            | "FALSE"
            | "null"
            | "nullptr"
            | "NULL"
            | "None"
            | "undefined"
            | "Ok"
            | "Err"
            | "Some"
    ) {
        return false;
    }
    if is_screaming_snake_case(ident)
        && !ident.ends_with("_Handler")
        && !ident.ends_with("_IRQHandler")
        && !ident.ends_with("_ISR")
    {
        return false;
    }
    true
}

fn record_fn_ptr_candidate(
    ctx: &mut ExtractContext<'_>,
    line: usize,
    target_name: String,
    enclosing_fn: Option<(&str, usize)>,
) {
    if !is_plausible_fn_ptr_identifier(&target_name, &ctx.local_vars) {
        return;
    }
    if !ctx
        .seen_fn_ptr_candidates
        .insert((line, target_name.clone()))
    {
        return;
    }
    let context_line = ctx
        .lines
        .get(line.saturating_sub(1))
        .map(|l| l.trim().to_string())
        .unwrap_or_default();

    ctx.raw_xrefs.push(RawXrefSite {
        file: ctx.scanned.rel_path.clone(),
        line,
        enclosing_symbol: enclosing_fn.map(|(n, _)| n.to_string()),
        target_name,
        category: "fn_ptr_candidate".to_string(),
        context: truncate_str(&context_line, 120),
    });
}

fn extract_fn_ptr_candidates_from_node(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind: &str,
    enclosing_fn: Option<(&str, usize)>,
) {
    match kind {
        "initializer_pair" | "field_initializer" | "pair" => {
            // C designated initializer `.on_rx = uart_rx_isr`, Rust `on_rx: uart_rx_isr`, JS/Py `{ on_rx: uart_rx_isr }`
            let val_node = node
                .child_by_field_name("value")
                .or_else(|| node.named_child(node.named_child_count().saturating_sub(1)));
            if let Some(val) = val_node {
                if let Some(cand) = extract_candidate_fn_identifier(val, ctx.bytes) {
                    let line = val.start_position().row + 1;
                    record_fn_ptr_candidate(ctx, line, cand, enclosing_fn);
                }
            }
        }
        "initializer_list" => {
            // C/C++ array or positional struct initializer `{ Reset_Handler, NMI_Handler, SysTick_Handler }`
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "initializer_pair" || child.kind() == "initializer_list" {
                    continue;
                }
                if let Some(cand) = extract_candidate_fn_identifier(child, ctx.bytes) {
                    let line = child.start_position().row + 1;
                    record_fn_ptr_candidate(ctx, line, cand, enclosing_fn);
                }
            }
        }
        "argument_list" | "arguments" => {
            // Callback arguments passed to a function call: `register_irq(UART_IRQn, uart_rx_isr)`
            let mut cursor = node.walk();
            for arg in node.named_children(&mut cursor) {
                if let Some(cand) = extract_candidate_fn_identifier(arg, ctx.bytes) {
                    let line = arg.start_position().row + 1;
                    record_fn_ptr_candidate(ctx, line, cand, enclosing_fn);
                }
            }
        }
        _ => {}
    }
}

fn extract_field_access_mutability(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind: &str,
    enclosing_type: Option<&str>,
    enclosing_fn: Option<(&str, usize)>,
) {
    let (recv_node, field_node) = match kind {
        "field_expression" => (
            node.child_by_field_name("argument")
                .or_else(|| node.child_by_field_name("value")),
            node.child_by_field_name("field"),
        ),
        "member_expression" => (
            node.child_by_field_name("object"),
            node.child_by_field_name("property"),
        ),
        "attribute" => (
            node.child_by_field_name("object"),
            node.child_by_field_name("attribute"),
        ),
        _ => return,
    };

    let (Some(recv_node), Some(field_node)) = (recv_node, field_node) else {
        return;
    };

    // Skip if this member expression is the direct callee of a function/method call (`obj.method()`)
    if let Some(parent) = node.parent() {
        let pk = parent.kind();
        if matches!(pk, "call_expression" | "call" | "new_expression") {
            let callee = parent
                .child_by_field_name("function")
                .or_else(|| parent.child_by_field_name("constructor"))
                .or_else(|| parent.named_child(0));
            if callee.is_some_and(|c| c.id() == node.id()) {
                return;
            }
        }
    }

    let field_name = node_text(field_node, ctx.bytes).trim();
    if !is_valid_identifier(field_name) {
        return;
    }

    let recv_raw = normalize_whitespace(node_text(recv_node, ctx.bytes));
    let recv_clean = recv_raw
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim_start_matches('*')
        .trim();

    // Skip C/C++ MMIO `PERIPH->REG` where `mmio.rs` already emits `mmio_write` / `mmio_read`
    let full_expr = node_text(node, ctx.bytes);
    if full_expr.contains("->") && is_screaming_snake_case(recv_clean) {
        return;
    }

    // Resolve receiver type via `self`/`this` -> `enclosing_type`, or `local_var_types`
    let resolved_type = if matches!(recv_clean, "self" | "this") {
        enclosing_type.map(ToOwned::to_owned)
    } else {
        resolve_local_receiver_type(&recv_raw, &ctx.local_var_types)
    };

    let target_name = if let Some(ty) = resolved_type {
        format!("{ty}::{field_name}")
    } else if is_valid_identifier(recv_clean)
        && !matches!(recv_clean, "self" | "this" | "super" | "cls")
    {
        format!("{recv_clean}.{field_name}")
    } else {
        return;
    };

    let is_write = is_node_mutation_lhs(node);
    let line = node.start_position().row + 1;
    if !ctx
        .seen_field_xrefs
        .insert((line, target_name.clone(), is_write))
    {
        return;
    }

    let context_line = ctx
        .lines
        .get(line.saturating_sub(1))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| truncate_str(&normalize_whitespace(full_expr), 120));

    ctx.raw_xrefs.push(RawXrefSite {
        file: ctx.scanned.rel_path.clone(),
        line,
        enclosing_symbol: enclosing_fn.map(|(n, _)| n.to_string()),
        target_name,
        category: if is_write {
            "field_write".to_string()
        } else {
            "field_read".to_string()
        },
        context: truncate_str(&context_line, 120),
    });
}

fn is_node_mutation_lhs(node: Node<'_>) -> bool {
    let mut cur = node;
    while let Some(parent) = cur.parent() {
        match parent.kind() {
            "assignment_expression"
            | "augmented_assignment_expression"
            | "compound_assignment_expr"
            | "assignment" => {
                if let Some(left) = parent.child_by_field_name("left") {
                    if left.id() == cur.id() {
                        return true;
                    }
                }
                return false;
            }
            "update_expression" => return true,
            "parenthesized_expression" => {
                cur = parent;
            }
            _ => return false,
        }
    }
    false
}

fn extract_declarator_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" | "destructor_name" => {
            Some(node_text(node, bytes).trim().to_string())
        }
        "qualified_identifier" | "scoped_identifier" => {
            Some(normalize_whitespace(node_text(node, bytes)))
        }
        "function_declarator"
        | "pointer_declarator"
        | "reference_declarator"
        | "array_declarator"
        | "parenthesized_declarator"
        | "attributed_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                if let Some(res) = extract_declarator_name(inner, bytes) {
                    return Some(res);
                }
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(res) = extract_declarator_name(child, bytes) {
                    return Some(res);
                }
            }
            None
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(res) = extract_declarator_name(child, bytes) {
                    return Some(res);
                }
            }
            None
        }
    }
}

fn extract_clean_signature(node: Node<'_>, bytes: &[u8]) -> String {
    let start = node.start_byte();
    let mut has_block_body = false;
    let end = if let Some(body) = node.child_by_field_name("body") {
        has_block_body = true;
        body.start_byte()
    } else if let Some(fn_node) = find_first_descendant_of_kind(node, "arrow_function")
        .or_else(|| find_first_descendant_of_kind(node, "function_expression"))
        .or_else(|| find_first_descendant_of_kind(node, "function"))
        .or_else(|| find_first_descendant_of_kind(node, "generator_function"))
    {
        if let Some(body) = fn_node.child_by_field_name("body") {
            if matches!(
                body.kind(),
                "statement_block" | "compound_statement" | "block"
            ) {
                has_block_body = true;
                body.start_byte()
            } else {
                // Concise expression-body arrow function: keep the declaration header or one-liner
                has_block_body = true;
                node.end_byte()
            }
        } else {
            node.end_byte()
        }
    } else {
        node.end_byte()
    };

    let slice = if end > start && end <= bytes.len() {
        std::str::from_utf8(&bytes[start..end]).unwrap_or("")
    } else {
        node_text(node, bytes)
    };

    // Only cut at `{` outside `(...)` when no block body boundary was resolved via AST
    let before_brace = if has_block_body {
        slice
    } else {
        split_at_top_level_brace(slice)
    };
    let normalized = normalize_whitespace(before_brace);
    let trimmed = normalized
        .trim_end_matches('{')
        .trim_end_matches(';')
        .trim_end_matches(':')
        .trim();

    truncate_str(trimmed, 160)
}

fn split_at_top_level_brace(slice: &str) -> &str {
    let mut paren_depth = 0usize;
    for (idx, ch) in slice.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '{' if paren_depth == 0 => return &slice[..idx],
            _ => {}
        }
    }
    slice
}

fn extract_preceding_doc(lines: &[&str], start_line: usize) -> String {
    if start_line <= 1 || lines.is_empty() {
        return String::new();
    }

    let mut idx = start_line - 2; // 0-based index of line immediately above `start_line`
    let mut doc_lines = Vec::new();
    let mut in_block_comment = false;

    while let Some(raw_line) = lines.get(idx) {
        let trimmed = raw_line.trim();

        // Skip attribute or decorator lines between doc comment and item
        if doc_lines.is_empty()
            && !in_block_comment
            && (trimmed.starts_with("#[")
                || trimmed.starts_with('@')
                || trimmed.starts_with("__attribute__"))
        {
            if idx == 0 {
                break;
            }
            idx -= 1;
            continue;
        }

        if in_block_comment {
            let cleaned = clean_doc_line(trimmed);
            if !cleaned.is_empty() && !is_decorative_doc_line(&cleaned) {
                doc_lines.push(cleaned);
            }
            if trimmed.starts_with("/*") {
                break;
            }
        } else if trimmed.starts_with("///")
            || trimmed.starts_with("//!")
            || trimmed.starts_with("//")
            || (trimmed.starts_with('#')
                && !trimmed.starts_with("#[")
                && !trimmed.starts_with("#include")
                && !trimmed.starts_with("#define")
                && !trimmed.starts_with("#if")
                && !trimmed.starts_with("#endif")
                && !trimmed.starts_with("#pragma"))
        {
            let cleaned = clean_doc_line(trimmed);
            if !cleaned.is_empty() && !is_decorative_doc_line(&cleaned) {
                doc_lines.push(cleaned);
            }
        } else if trimmed.ends_with("*/") {
            let cleaned = clean_doc_line(trimmed);
            if !cleaned.is_empty() && !is_decorative_doc_line(&cleaned) {
                doc_lines.push(cleaned);
            }
            if trimmed.starts_with("/*") {
                break;
            }
            in_block_comment = true;
        } else {
            break;
        }

        if idx == 0 {
            break;
        }
        idx -= 1;
    }

    doc_lines.reverse();
    let first_meaningful = doc_lines
        .into_iter()
        .find(|l| {
            !l.is_empty()
                && !is_decorative_doc_line(l)
                && !l.starts_with('@')
                && !l.starts_with("\\brief")
        })
        .unwrap_or_default();

    truncate_str(&first_meaningful, 160)
}

/// Returns true when a comment line carries no descriptive text — i.e. it is an empty line or a
/// purely decorative ASCII divider/banner (`----`, `====`, `****`, `####`, `~~~~`, `____`, ...).
///
/// Such lines are ignored when locating the doc summary of a symbol or type, so a decorative
/// divider placed directly above or below a real description does not hide it.
fn is_decorative_doc_line(cleaned: &str) -> bool {
    if !cleaned.chars().any(|c| c.is_alphanumeric()) {
        return true;
    }
    let trimmed = cleaned.trim();
    if (trimmed.starts_with("---") && trimmed.ends_with("---"))
        || (trimmed.starts_with("===") && trimmed.ends_with("==="))
    {
        return true;
    }
    false
}

fn clean_doc_line(trimmed: &str) -> String {
    let s = trimmed
        .trim_start_matches("/**")
        .trim_start_matches("/*!")
        .trim_start_matches("/*")
        .trim_end_matches("*/")
        .trim_start_matches("///")
        .trim_start_matches("//!")
        .trim_start_matches("//")
        .trim_start_matches('#')
        .trim_start_matches('*')
        .trim();
    let s = s
        .strip_prefix("@brief ")
        .or_else(|| s.strip_prefix("\\brief "))
        .unwrap_or(s)
        .trim();
    s.to_string()
}

fn has_preceding_interrupt_attr(lines: &[&str], start_line: usize) -> bool {
    let start_idx = start_line.saturating_sub(4);
    let end_idx = start_line.saturating_sub(1);
    for idx in start_idx..end_idx {
        if let Some(line) = lines.get(idx) {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
                continue;
            }
            if (t.starts_with("#[") && (t.contains("interrupt") || t.contains("exception")))
                || t.contains("__interrupt")
                || (t.contains("interrupt") && t.contains("__attribute__"))
            {
                return true;
            }
        }
    }
    false
}

fn find_first_descendant_of_kind<'a>(node: Node<'a>, target_kind: &str) -> Option<Node<'a>> {
    if node.kind() == target_kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_first_descendant_of_kind(child, target_kind) {
            return Some(found);
        }
    }
    None
}

fn has_descendant_kind(node: Node<'_>, target_kind: &str) -> bool {
    find_first_descendant_of_kind(node, target_kind).is_some()
}

fn node_text<'a>(node: Node<'_>, bytes: &'a [u8]) -> &'a str {
    node.utf8_text(bytes).unwrap_or("")
}

fn normalize_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn is_screaming_snake_case(s: &str) -> bool {
    s.len() >= 2
        && s.bytes().any(|b| b.is_ascii_uppercase())
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

// ============================================================================
// Single-File Component (`.astro`, `.vue`, `.svelte`) Preprocessing & Template Extraction
// ============================================================================

/// Builds a byte-aligned TSX buffer of the exact same byte length as `source`, preserving all
/// `\n` and `\r` characters at their original byte offsets while blanking non-script markup to
/// spaces (`b' '`). Copies Astro `---` frontmatter and `<script>` blocks verbatim so Tree-sitter
/// TSX parses all embedded TypeScript/JavaScript with 1:1 line and byte coordinates.
fn preprocess_sfc_to_tsx(source: &str, rel_path: &str) -> Vec<u8> {
    let bytes = source.as_bytes();
    let mut out: Vec<u8> = bytes
        .iter()
        .map(|&b| if b == b'\n' || b == b'\r' { b } else { b' ' })
        .collect();

    for (start, end) in collect_sfc_code_ranges(source, rel_path) {
        if start < end && end <= bytes.len() {
            out[start..end].copy_from_slice(&bytes[start..end]);
        }
    }

    out
}

fn collect_sfc_code_ranges(source: &str, rel_path: &str) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let len = bytes.len();
    let mut ranges = Vec::new();
    let mut scan_pos = 0usize;

    // 1. Astro frontmatter fence `--- ... ---` at top of file
    if rel_path.to_ascii_lowercase().ends_with(".astro") {
        let mut p = 0usize;
        if source.starts_with('\u{feff}') {
            p += '\u{feff}'.len_utf8();
        }
        while p < len && matches!(bytes[p], b' ' | b'\t' | b'\r' | b'\n') {
            p += 1;
        }
        if source[p..].starts_with("---") {
            let mut line_end = p + 3;
            while line_end < len && matches!(bytes[line_end], b' ' | b'\t' | b'\r') {
                line_end += 1;
            }
            if line_end < len && bytes[line_end] == b'\n' {
                let fm_start = line_end + 1;
                let mut cur = fm_start;
                while cur < len {
                    let mut line_p = cur;
                    while line_p < len && matches!(bytes[line_p], b' ' | b'\t') {
                        line_p += 1;
                    }
                    if source[line_p..].starts_with("---") {
                        let mut after_fence = line_p + 3;
                        while after_fence < len
                            && matches!(bytes[after_fence], b' ' | b'\t' | b'\r')
                        {
                            after_fence += 1;
                        }
                        if after_fence == len || bytes[after_fence] == b'\n' {
                            ranges.push((fm_start, cur));
                            scan_pos = if after_fence < len {
                                after_fence + 1
                            } else {
                                len
                            };
                            break;
                        }
                    }
                    match bytes[cur..].iter().position(|&b| b == b'\n') {
                        Some(nl) => cur += nl + 1,
                        None => break,
                    }
                }
            }
        }
    }

    // 2. `<script ...> ... </script>` blocks
    let mut i = scan_pos;
    while i + 7 <= len {
        if bytes[i] == b'<' && source[i + 1..].len() >= 6 {
            let candidate = &bytes[i + 1..i + 7];
            if candidate.eq_ignore_ascii_case(b"script") {
                let next_b = bytes.get(i + 7).copied().unwrap_or(b'>');
                if matches!(next_b, b'>' | b' ' | b'\t' | b'\r' | b'\n' | b'/') {
                    // Find closing `>` of opening `<script...>` tag
                    let mut tag_end = i + 7;
                    let mut in_quote: u8 = 0;
                    while tag_end < len {
                        let b = bytes[tag_end];
                        if in_quote != 0 {
                            if b == in_quote {
                                in_quote = 0;
                            }
                        } else if b == b'"' || b == b'\'' {
                            in_quote = b;
                        } else if b == b'>' {
                            break;
                        }
                        tag_end += 1;
                    }
                    if tag_end >= len {
                        break;
                    }
                    // Skip self-closing `<script ... />`
                    let mut before_gt = tag_end;
                    while before_gt > i && matches!(bytes[before_gt - 1], b' ' | b'\t' | b'\r') {
                        before_gt -= 1;
                    }
                    if before_gt > i && bytes[before_gt - 1] == b'/' {
                        i = tag_end + 1;
                        continue;
                    }

                    let body_start = tag_end + 1;
                    let mut close_idx = body_start;
                    let mut found_close = None;
                    while close_idx + 9 <= len {
                        if bytes[close_idx] == b'<'
                            && bytes[close_idx + 1] == b'/'
                            && bytes[close_idx + 2..close_idx + 8].eq_ignore_ascii_case(b"script")
                        {
                            let mut close_gt = close_idx + 8;
                            while close_gt < len
                                && matches!(bytes[close_gt], b' ' | b'\t' | b'\r' | b'\n')
                            {
                                close_gt += 1;
                            }
                            if close_gt < len && bytes[close_gt] == b'>' {
                                found_close = Some((close_idx, close_gt + 1));
                                break;
                            }
                        }
                        close_idx += 1;
                    }

                    if let Some((body_end, next_scan)) = found_close {
                        ranges.push((body_start, body_end));
                        i = next_scan;
                        continue;
                    } else {
                        break;
                    }
                }
            }
        }
        i += 1;
    }

    ranges
}

fn derive_sfc_component_name(rel_path: &str) -> String {
    let file_name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    let stem = file_name
        .rsplit_once('.')
        .map(|(s, _)| s)
        .unwrap_or(file_name);
    let mut sanitized = String::with_capacity(stem.len() + 5);
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        return "Component".to_string();
    }
    if trimmed.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        format!("Page_{trimmed}")
    } else {
        trimmed.to_string()
    }
}

fn extract_sfc_component_and_template(ctx: &mut ExtractContext<'_>, source: &str) {
    let comp_name = derive_sfc_component_name(&ctx.scanned.rel_path);
    let has_props_type = ctx.types.iter().any(|t| t.name == "Props");
    let is_page = ctx.scanned.arch_layer == ArchLayer::App
        || ctx.scanned.rel_path.starts_with("pages/")
        || ctx.scanned.rel_path.contains("/pages/");

    if !ctx.symbols.iter().any(|s| s.name == comp_name) {
        let kind = if is_page {
            SymbolKind::Entrypoint
        } else {
            SymbolKind::Function
        };
        let signature = if has_props_type {
            format!("component {comp_name}(props: Props)")
        } else {
            format!("component {comp_name}()")
        };
        let symbol_id = format!("{}::{}", ctx.scanned.rel_path, comp_name);
        ctx.symbols.insert(
            0,
            ExtractedSymbol {
                symbol_id,
                name: comp_name.clone(),
                qualified_name: comp_name.clone(),
                kind,
                visibility: Visibility::Public,
                file: ctx.scanned.rel_path.clone(),
                start_line: 1,
                end_line: ctx.scanned.line_count.max(1),
                signature,
                doc_summary: String::new(),
                enclosing_type: None,
                scope: ctx.scanned.scope,
                arch_layer: ctx.scanned.arch_layer,
                section_id: ctx.section_id.to_string(),
            },
        );
    }

    // Attribute module-init calls inside frontmatter / top-level script to the SFC component
    for call in &mut ctx.raw_calls {
        if call.caller_name == "<module_init>" {
            call.caller_name = comp_name.clone();
            call.caller_start_line = 1;
        }
    }
    for xref in &mut ctx.raw_xrefs {
        if xref.enclosing_symbol.as_deref() == Some("<module_init>") {
            xref.enclosing_symbol = Some(comp_name.clone());
        }
    }

    let code_ranges = collect_sfc_code_ranges(source, &ctx.scanned.rel_path);
    let bytes = source.as_bytes();
    let len = bytes.len();
    let is_in_code = |pos: usize| code_ranges.iter().any(|&(s, e)| pos >= s && pos < e);

    let mut i = 0usize;
    let mut line_num = 1usize;
    while i < len {
        if is_in_code(i) {
            if bytes[i] == b'\n' {
                line_num += 1;
            }
            i += 1;
            continue;
        }

        // Skip HTML comments `<!-- ... -->`
        if i + 4 <= len && &bytes[i..i + 4] == b"<!--" {
            i += 4;
            while i < len {
                if bytes[i] == b'\n' {
                    line_num += 1;
                }
                if i + 3 <= len && &bytes[i..i + 3] == b"-->" {
                    i += 3;
                    break;
                }
                i += 1;
            }
            continue;
        }

        // Skip `<style ...> ... </style>` blocks
        if i + 6 <= len
            && bytes[i] == b'<'
            && bytes[i + 1..i + 6].eq_ignore_ascii_case(b"style")
            && matches!(
                bytes.get(i + 6).copied().unwrap_or(b'>'),
                b'>' | b' ' | b'\t' | b'\r' | b'\n'
            )
        {
            i += 6;
            while i < len {
                if bytes[i] == b'\n' {
                    line_num += 1;
                }
                if i + 8 <= len
                    && bytes[i] == b'<'
                    && bytes[i + 1] == b'/'
                    && bytes[i + 2..i + 7].eq_ignore_ascii_case(b"style")
                {
                    i += 7;
                    break;
                }
                i += 1;
            }
            continue;
        }

        // Detect PascalCase component tag `<ComponentName`
        if bytes[i] == b'<' && i + 1 < len && bytes[i + 1].is_ascii_uppercase() {
            let start = i + 1;
            let mut end = start + 1;
            while end < len
                && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_' || bytes[end] == b'.')
            {
                end += 1;
            }
            let raw_tag = &source[start..end];
            if let Some((callee_name, receiver_or_qualifier)) = parse_callee_expression(raw_tag) {
                ctx.raw_calls.push(RawCallSite {
                    caller_file: ctx.scanned.rel_path.clone(),
                    caller_name: comp_name.clone(),
                    caller_start_line: 1,
                    callee_name,
                    receiver_or_qualifier,
                    call_line: line_num,
                });
            }
            i = end;
            continue;
        }

        // Detect template helper calls `helperFn(` referencing local or imported symbols
        if (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_')
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'))
        {
            let start = i;
            let mut end = start + 1;
            while end < len && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            if end < len && bytes[end] == b'(' {
                let ident = &source[start..end];
                let is_known_target = ctx
                    .symbols
                    .iter()
                    .any(|s| s.name == ident && s.name != comp_name)
                    || ctx
                        .imports
                        .iter()
                        .any(|imp| imp.imported_names.iter().any(|n| n == ident));
                if is_known_target {
                    ctx.raw_calls.push(RawCallSite {
                        caller_file: ctx.scanned.rel_path.clone(),
                        caller_name: comp_name.clone(),
                        caller_start_line: 1,
                        callee_name: ident.to_string(),
                        receiver_or_qualifier: None,
                        call_line: line_num,
                    });
                }
            }
            i = end;
            continue;
        }

        if bytes[i] == b'\n' {
            line_num += 1;
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FileScope;
    use std::path::PathBuf;

    fn dummy_scanned(rel_path: &str, language: LanguageKind) -> ScannedFile {
        ScannedFile {
            rel_path: rel_path.to_string(),
            abs_path: PathBuf::from(rel_path),
            language,
            scope: FileScope::FirstParty,
            arch_layer: ArchLayer::Drivers,
            size_bytes: 512,
            mtime_secs: 0,
            blake3_hash: "0123456789abcdef".to_string(),
            line_count: 30,
        }
    }

    #[test]
    fn test_parse_c_typedef_struct_and_mmio() {
        let src = r#"
#include "vendor_chip.h"

#define VENDOR_TIM1_BASE 0x40010000UL
#define TIM_CR1_CEN_MSK  (1UL << 0)

/** Motor configuration parameters */
typedef struct {
    uint32_t pwm_freq_hz;
    uint16_t max_duty;
    uint8_t pole_pairs;
} MotorConfig_t;

/// Updates PWM duty cycle on TIM1 CCR1.
void motor_set_duty(const MotorConfig_t *cfg, uint16_t duty) {
    VENDOR_TIM1->CCR1 = duty;
    helper_clamp(duty, cfg->max_duty);
}

void TIM1_UP_IRQHandler(void) {
    VENDOR_TIM1->SR = 0;
}
"#;
        let scanned = dummy_scanned("fw/drvs/motor_ctrl.c", LanguageKind::C);
        let unit = parse_source_str(&scanned, src).expect("parse C file");

        assert_eq!(unit.parse_errors, 0);
        // Check typedef struct extraction
        assert_eq!(unit.types.len(), 1);
        assert_eq!(unit.types[0].name, "MotorConfig_t");
        assert!(unit.types[0]
            .fields_summary
            .contains("pwm_freq_hz: uint32_t"));
        assert!(unit.types[0].fields_summary.contains("max_duty: uint16_t"));

        // Check functions and ISR classification
        let duty_fn = unit
            .symbols
            .iter()
            .find(|s| s.name == "motor_set_duty")
            .expect("motor_set_duty symbol");
        assert_eq!(duty_fn.kind, SymbolKind::Function);
        assert_eq!(duty_fn.doc_summary, "Updates PWM duty cycle on TIM1 CCR1.");

        let isr_fn = unit
            .symbols
            .iter()
            .find(|s| s.name == "TIM1_UP_IRQHandler")
            .expect("ISR symbol");
        assert_eq!(isr_fn.kind, SymbolKind::Isr);

        // Check macros & MMIO register access
        assert!(unit
            .macros
            .iter()
            .any(|m| m.name == "VENDOR_TIM1_BASE" && m.kind == MacroKind::MmioAddress));
        assert!(unit
            .macros
            .iter()
            .any(|m| m.name == "TIM_CR1_CEN_MSK" && m.kind == MacroKind::Bitmask));
        assert!(unit
            .macros
            .iter()
            .any(|m| m.name == "VENDOR_TIM1->CCR1" && m.kind == MacroKind::RegisterAccess));

        // Check call site
        assert!(unit
            .raw_calls
            .iter()
            .any(|c| c.caller_name == "motor_set_duty" && c.callee_name == "helper_clamp"));
    }

    #[test]
    fn test_parse_c_header_prototypes() {
        let src = r#"
#ifndef MOTOR_CTRL_H
#define MOTOR_CTRL_H

#include <stdint.h>

/** Initialize motor subsystem. */
int motor_init(uint32_t freq_hz);
void motor_stop(void);

#endif
"#;
        let scanned = dummy_scanned("fw/drvs/motor_ctrl.h", LanguageKind::C);
        let unit = parse_source_str(&scanned, src).expect("parse C header");
        assert_eq!(unit.symbols.len(), 2);
        assert!(unit.symbols.iter().any(|s| s.name == "motor_init"));
        assert!(unit.symbols.iter().any(|s| s.name == "motor_stop"));
    }

    #[test]
    fn test_parse_rust_impl_methods_and_calls() {
        let src = r#"
use crate::cleaner::clean_text;

/// Driver state container.
pub struct Driver {
    pub id: u32,
}

impl Driver {
    pub fn new(id: u32) -> Self {
        Self { id }
    }

    pub fn process(&self, input: &str) -> String {
        let s = crate::cleaner::clean_text(input);
        self.helper(&s)
    }

    fn helper(&self, s: &str) -> String {
        s.to_string()
    }
}
"#;
        let scanned = dummy_scanned("crates/chipsrc-core/src/driver.rs", LanguageKind::Rust);
        let unit = parse_source_str(&scanned, src).expect("parse Rust file");

        assert_eq!(unit.types.len(), 1);
        assert_eq!(unit.types[0].name, "Driver");

        let new_sym = unit.symbols.iter().find(|s| s.name == "new").unwrap();
        assert_eq!(new_sym.kind, SymbolKind::Constructor);
        assert_eq!(new_sym.qualified_name, "Driver::new");

        let proc_sym = unit.symbols.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(proc_sym.kind, SymbolKind::Method);

        assert!(unit.raw_calls.iter().any(|c| {
            c.caller_name == "process"
                && c.callee_name == "clean_text"
                && c.receiver_or_qualifier.as_deref() == Some("crate::cleaner")
        }));
    }

    #[test]
    fn test_parse_python_and_typescript() {
        let py_src = r#"
from .models import TelemetryPacket

MAX_RETRIES = 5

class SyncClient:
    """Handles cloud telemetry sync."""
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    def push_batch(self, batch: list) -> bool:
        """Uploads a batch of packets."""
        return self.db.query(batch)
"#;
        let py_scanned = dummy_scanned("services/sync_client.py", LanguageKind::Python);
        let py_unit = parse_source_str(&py_scanned, py_src).expect("parse Python");
        assert_eq!(py_unit.types.len(), 1);
        assert_eq!(py_unit.types[0].name, "SyncClient");
        assert_eq!(
            py_unit.types[0].doc_summary,
            "Handles cloud telemetry sync."
        );
        assert!(py_unit
            .macros
            .iter()
            .any(|m| m.name == "MAX_RETRIES" && m.kind == MacroKind::Constant));
        assert!(py_unit.raw_calls.iter().any(|c| {
            c.caller_name == "push_batch"
                && c.callee_name == "query"
                && c.receiver_or_qualifier.as_deref() == Some("self.db")
        }));

        let ts_src = r#"
import { Packet } from './packet';

export interface TelemetryService {
    send(pkt: Packet): Promise<void>;
}

export const formatPacket = (pkt: Packet): string => {
    return JSON.stringify(pkt);
};
"#;
        let ts_scanned = dummy_scanned("api/telemetry.ts", LanguageKind::TypeScript);
        let ts_unit = parse_source_str(&ts_scanned, ts_src).expect("parse TypeScript");
        assert!(ts_unit
            .types
            .iter()
            .any(|t| t.name == "TelemetryService" && t.kind == TypeKind::Interface));
        assert!(ts_unit
            .symbols
            .iter()
            .any(|s| s.name == "formatPacket" && s.visibility == Visibility::Public));
    }

    #[test]
    fn test_c_qualifier_macro_normalization_lengths_and_safety() {
        for tok in [
            "STATIC",
            "INLINE",
            "__INLINE",
            "__STATIC_INLINE",
            "__STATIC_FORCEINLINE",
            "STATIC_INLINE",
            "FORCE_INLINE",
            "ALWAYS_INLINE",
            "WEAK",
            "__WEAK",
            "SYSCONFIG_WEAK",
            "TI_WEAK",
            "HAL_WEAK",
            "CONST",
            "RAMFUNC",
            "__RAMFUNC",
        ] {
            let rep = classify_c_qualifier_macro_replacement(tok.as_bytes(), None)
                .unwrap_or_else(|| panic!("expected replacement for {tok}"));
            assert!(
                rep.len() <= tok.len(),
                "replacement prefix for `{tok}` must fit within original token byte length"
            );
            let snippet = format!("{tok} void f(void) {{}}");
            let norm = normalize_c_qualifier_macros(&snippet, None)
                .unwrap_or_else(|| panic!("expected normalization for `{tok}`"));
            assert_eq!(
                norm.len(),
                snippet.len(),
                "normalized buffer for `{tok}` must preserve exact byte length"
            );
        }

        // Verify that `enum { STATIC = 0, CONST = 1 };` inside braces is NEVER corrupted,
        // and that storage/qualifier macros normalize cleanly without CST errors.
        let src = r#"
#include <stdint.h>

#define STATIC static
#define VENDOR_FAST __STATIC_INLINE

enum Mode {
    STATIC = 0,
    CONST = 1,
    INLINE = 2,
};

TI_WEAK void board_hook(void) {}

STATIC void helper_reset(void) {
    uint32_t tmp = 0;
    STATIC_guard(&tmp);
}

__STATIC_INLINE void fast_op(void) {
    do_fast();
}

__STATIC_FORCEINLINE void forced_op(void) {
    do_forced();
}

const void *CONST_PTR;

static void plain_static(void) {}

void public_entry(void) {
    static uint32_t call_count = 0;
    (void)call_count;
}
"#;
        let scanned = dummy_scanned("fw/drvs/qualifier_macros.c", LanguageKind::C);
        let unit = parse_source_str(&scanned, src).expect("parse C file");
        assert_eq!(
            unit.parse_errors, 0,
            "qualifier macros must not produce Tree-sitter errors"
        );
        assert!(unit.types.iter().any(|t| t.name == "Mode"));
        assert!(unit.symbols.iter().any(|s| s.name == "board_hook"));

        let vis = |name: &str| {
            unit.symbols
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("missing symbol {name}"))
                .visibility
        };
        assert_eq!(vis("helper_reset"), Visibility::Static);
        assert_eq!(vis("fast_op"), Visibility::Static);
        assert_eq!(vis("forced_op"), Visibility::Static);
        assert_eq!(vis("plain_static"), Visibility::Static);
        assert_eq!(vis("public_entry"), Visibility::Public);

        assert!(unit.macros.iter().any(|m| m.name == "STATIC"));
        assert!(unit.macros.iter().any(|m| m.name == "VENDOR_FAST"));
    }

    #[test]
    fn test_parse_astro_sfc_frontmatter_script_and_template() {
        let astro_src = r#"---
import Button from '../ui/Button.astro';
import { anchorHref } from './site';

export interface Props {
  title: string;
}

const { title } = Astro.props;
---
<header>
  <h1>{title}</h1>
  <a href={anchorHref('#kontakt', '/')}>Kontakt</a>
  <Button label="Start" />
</header>
<script>
  function initHeader(): void {
    console.log('ready');
  }
  initHeader();
</script>
"#;
        let scanned = dummy_scanned("src/plugins/shell/Header.astro", LanguageKind::Tsx);
        let unit = parse_source_str(&scanned, astro_src).expect("parse .astro file");
        assert_eq!(unit.parse_errors, 0);
        assert!(unit.types.iter().any(|t| t.name == "Props"));
        assert!(unit.symbols.iter().any(|s| s.name == "Header"));
        assert!(unit.symbols.iter().any(|s| s.name == "initHeader"));
        assert!(unit
            .raw_calls
            .iter()
            .any(|c| c.caller_name == "Header" && c.callee_name == "Button"));
        assert!(unit
            .raw_calls
            .iter()
            .any(|c| c.caller_name == "Header" && c.callee_name == "anchorHref"));
        assert!(unit
            .raw_calls
            .iter()
            .any(|c| c.caller_name == "Header" && c.callee_name == "initHeader"));
    }

    #[test]
    fn test_cpp_class_methods_excluded_from_fields_and_rust_test_scope() {
        let cpp_src = r#"
class MotorController {
public:
    MotorController();
    void setSpeed(int rpm);
    int getSpeed() const;
private:
    int current_rpm_;
    bool enabled_;
};
"#;
        let cpp_scanned = dummy_scanned("src/drvs/motor.hpp", LanguageKind::Cpp);
        let cpp_unit = parse_source_str(&cpp_scanned, cpp_src).expect("parse C++ header");
        let cls = cpp_unit
            .types
            .iter()
            .find(|t| t.name == "MotorController")
            .expect("MotorController class");
        assert!(cls.fields_summary.contains("current_rpm_: int"));
        assert!(cls.fields_summary.contains("enabled_: bool"));
        assert!(!cls.fields_summary.contains("setSpeed"));
        assert!(!cls.fields_summary.contains("getSpeed"));

        let rs_src = r##"
use crate::model::{SymbolKind, Visibility};

#[allow(clippy::too_many_arguments)]
pub fn check_isr_header(sig: &str) -> String {
    let _ = "__attribute__((interrupt)) #[interrupt]";
    format!("sig={}", helper_escape(sig))
}

fn helper_escape(s: &str) -> &str {
    s
}

#[cfg(test)]
mod tests {
    const SAMPLE_RAW: &str = r#"
         TIM1->CCR1 = 0x40010000;
    "#;

    #[test]
    fn test_sample() {
        let _ = SAMPLE_RAW;
    }
}
"##;
        let rs_scanned = dummy_scanned("crates/chipsrc-core/src/parser.rs", LanguageKind::Rust);
        let rs_unit = parse_source_str(&rs_scanned, rs_src).expect("parse Rust");
        let check_fn = rs_unit
            .symbols
            .iter()
            .find(|s| s.name == "check_isr_header")
            .expect("check_isr_header");
        assert_eq!(check_fn.visibility, Visibility::Public);
        assert_eq!(
            check_fn.kind,
            SymbolKind::Function,
            "string literals inside body must not trigger SymbolKind::Isr"
        );
        assert!(
            rs_unit
                .raw_calls
                .iter()
                .any(|c| c.caller_name == "check_isr_header" && c.callee_name == "helper_escape"),
            "calls nested inside format! macro must be extracted"
        );
        let test_fn = rs_unit
            .symbols
            .iter()
            .find(|s| s.name == "test_sample")
            .expect("test_sample");
        assert_eq!(test_fn.scope, FileScope::Test);
        assert!(
            !rs_unit.macros.iter().any(|m| m.name == "SAMPLE_RAW"),
            "const items inside #[cfg(test)] must not pollute macros"
        );
        let imp = &rs_unit.imports[0];
        assert_eq!(imp.raw_path, "crate::model");
    }

    #[test]
    fn test_python_async_def_and_ts_method_visibility() {
        let py_src = r#"
class AsyncService:
    async def fetch_items(self) -> list:
        return []

async def run_pipeline() -> None:
    pass
"#;
        let py_scanned = dummy_scanned("services/pipeline.py", LanguageKind::Python);
        let py_unit = parse_source_str(&py_scanned, py_src).expect("parse Python");
        assert!(py_unit
            .symbols
            .iter()
            .any(|s| s.name == "fetch_items" && s.kind == SymbolKind::Method));
        assert!(py_unit
            .symbols
            .iter()
            .any(|s| s.name == "run_pipeline" && s.kind == SymbolKind::Function));

        let ts_src = r#"
export class ApiClient {
    fetchData(): void {}
    private secretHelper(): void {}
}
"#;
        let ts_scanned = dummy_scanned("src/api/client.ts", LanguageKind::TypeScript);
        let ts_unit = parse_source_str(&ts_scanned, ts_src).expect("parse TS");
        let fetch_m = ts_unit
            .symbols
            .iter()
            .find(|s| s.name == "fetchData")
            .unwrap();
        assert_eq!(fetch_m.visibility, Visibility::Public);
        let secret_m = ts_unit
            .symbols
            .iter()
            .find(|s| s.name == "secretHelper")
            .unwrap();
        assert_eq!(secret_m.visibility, Visibility::Private);
    }

    #[test]
    fn test_doc_summary_skips_ascii_divider_lines() {
        let src = r#"
// Initializes the peripheral clock tree.
//-------------------------------------------------------------------------//
void foo_init(void) {
    do_init();
}

//---------------------------------------------------------------------//
void divider_only_init(void) {
    do_init();
}

/* ===================================================================== */
void banner_only_init(void) {}

/* Configures the DMA channel.
 * ===================================================================== */
void baz_init(void) {}
"#;
        let scanned = dummy_scanned("fw/drvs/divider_docs.c", LanguageKind::C);
        let unit = parse_source_str(&scanned, src).expect("parse C file");
        assert_eq!(unit.parse_errors, 0);

        let doc = |name: &str| {
            unit.symbols
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("missing symbol {name}"))
                .doc_summary
                .clone()
        };
        assert_eq!(doc("foo_init"), "Initializes the peripheral clock tree.");
        assert_eq!(doc("baz_init"), "Configures the DMA channel.");
        // Divider-only comment blocks must not become a doc summary.
        assert_eq!(doc("divider_only_init"), "");
        assert_eq!(doc("banner_only_init"), "");
    }
}
