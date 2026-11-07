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

const MAX_TYPE_SUMMARY_ITEMS: usize = 16;

/// Parses all scanned files with an optional blueprint and reuses matching cache entries.
pub fn parse_files_incremental_with_blueprint(
    scanned_files: &[ScannedFile],
    existing_cache: Option<IncrementalAstCache>,
    blueprint: Option<&RepoBlueprint>,
) -> Result<(Vec<ParsedFileUnit>, usize, usize)> {
    let mut cache_map: std::collections::BTreeMap<String, ParsedFileUnit> =
        existing_cache.map(|c| c.files).unwrap_or_default();
    parse_files_into_cache_map(scanned_files, &mut cache_map, blueprint)
}

/// Parses scanned files, reusing matching entries from cache_map.
pub fn parse_files_into_cache_map(
    scanned_files: &[ScannedFile],
    cache_map: &mut std::collections::BTreeMap<String, ParsedFileUnit>,
    blueprint: Option<&RepoBlueprint>,
) -> Result<(Vec<ParsedFileUnit>, usize, usize)> {
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

/// Parses a single scanned file from disk with an optional blueprint.
pub fn parse_single_file_with_blueprint(
    scanned: &ScannedFile,
    blueprint: Option<&RepoBlueprint>,
) -> Result<ParsedFileUnit> {
    let raw_bytes =
        fs::read(&scanned.abs_path).map_err(|e| ChipsrcError::io(&scanned.abs_path, e))?;
    let source = String::from_utf8_lossy(&raw_bytes);
    parse_source_str_with_blueprint(scanned, &source, blueprint)
}

/// Parses an in-memory source string for a scanned file with an optional blueprint.
pub fn parse_source_str_with_blueprint(
    scanned: &ScannedFile,
    source: &str,
    blueprint: Option<&RepoBlueprint>,
) -> Result<ParsedFileUnit> {
    let is_sfc = is_sfc_file(&scanned.rel_path);

    let normalized_source = if is_sfc {
        Some(preprocess_sfc_to_tsx(source, &scanned.rel_path))
    } else {
        match scanned.language {
            LanguageKind::C | LanguageKind::Cpp => {
                let qualifier_normalized = normalize_c_qualifier_macros(source, blueprint);
                if scanned.language == LanguageKind::Cpp {
                    match qualifier_normalized {
                        Some(buf) => normalize_cpp_macro_annotations(&buf).or(Some(buf)),
                        None => normalize_cpp_macro_annotations(source.as_bytes()),
                    }
                } else {
                    qualifier_normalized
                }
            }
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
    walk_ast(&mut ctx, root, None, None, None, None);

    if is_sfc {
        extract_sfc_component_and_template(&mut ctx, source);
    }

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

    let (mmio_macros, mut mmio_xrefs) = extract_mmio_and_linker_constructs(
        &scanned.rel_path,
        source,
        scanned.scope,
        scanned.arch_layer,
        &section_id,
    );

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

fn line_is_preproc_directive(bytes: &[u8], line_start: usize, pos: usize) -> bool {
    for &b in bytes.get(line_start..pos).unwrap_or_default() {
        if b == b' ' || b == b'\t' || b == b'\r' {
            continue;
        }
        return b == b'#';
    }
    false
}

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
    Transparent,
    Aggregate,
    Block,
}

fn blank_range_preserving_newlines(buf: &mut [u8], start: usize, end: usize) {
    for b in &mut buf[start..end] {
        if *b != b'\n' && *b != b'\r' {
            *b = b' ';
        }
    }
}

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

        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

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

fn is_cpp_macro_like_token(word: &[u8]) -> bool {
    if word.len() < 2
        || !word
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
    {
        return false;
    }
    let uppercase = word.iter().filter(|b| b.is_ascii_uppercase()).count();
    word.contains(&b'_') || uppercase >= 2
}

fn find_matching_paren_bytes(src: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < src.len() {
        match src[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'"' | b'\'' => {
                let quote = src[i];
                i += 1;
                while i < src.len() {
                    if src[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if src[i] == quote || src[i] == b'\n' {
                        break;
                    }
                    i += 1;
                }
            }
            b'/' if src.get(i + 1) == Some(&b'/') => {
                while i < src.len() && src[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if src.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < src.len() {
                    if src[i] == b'*' && src[i + 1] == b'/' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[derive(Clone, PartialEq, Eq)]
enum BraceCtx {
    Class(String),
    Function,
    Other,
}

fn in_function_body(stack: &[BraceCtx]) -> bool {
    stack
        .iter()
        .any(|frame| matches!(frame, BraceCtx::Function))
}

fn normalize_cpp_macro_annotations(src: &[u8]) -> Option<Vec<u8>> {
    if !src.iter().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let n = src.len();
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0usize;
    let mut line_start = true;
    let mut prev_sig: u8 = 0;
    let mut prev_word: (usize, usize) = (0, 0);
    let mut synthetic_counter: usize = 0;
    let mut conditional_branches: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut brace_stack: Vec<BraceCtx> = Vec::new();
    let mut pending_class = false;
    let mut pending_namespace = false;
    let mut pending_class_name: Option<String> = None;
    let mut saw_paren = false;
    let mut template_params_pending = false;
    let mut angle_depth = 0usize;
    let mut pending_class_from_template = false;
    let mut prev_paren_closed_control = false;
    let mut paren_control_stack: Vec<bool> = Vec::new();

    while i < n {
        let b = src[i];
        match b {
            b'\n' => {
                line_start = true;
                i += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' => {
                i += 1;
                continue;
            }
            _ => {}
        }
        if line_start && b == b'#' {
            let directive_start = i;
            let mut kw_start = i + 1;
            while kw_start < n && matches!(src[kw_start], b' ' | b'\t') {
                kw_start += 1;
            }
            let mut kw_end = kw_start;
            while kw_end < n && is_c_ident_continue(src[kw_end]) {
                kw_end += 1;
            }
            let keyword = &src[kw_start..kw_end];
            let conditional = matches!(
                keyword,
                b"if" | b"ifdef" | b"ifndef" | b"elif" | b"else" | b"endif"
            );
            while i < n {
                if src[i] == b'\\' && i + 1 < n && matches!(src[i + 1], b'\n' | b'\r') {
                    i += 1;
                    if i < n && src[i] == b'\r' {
                        i += 1;
                    }
                    if i < n && src[i] == b'\n' {
                        i += 1;
                    }
                    continue;
                }
                if src[i] == b'\n' {
                    break;
                }
                i += 1;
            }
            if conditional {
                let buf = out.get_or_insert_with(|| src.to_vec());
                blank_range_preserving_newlines(buf, directive_start, i);
                let content_start = if src.get(i) == Some(&b'\n') { i + 1 } else { i };
                match keyword {
                    b"if" | b"ifdef" | b"ifndef" => {
                        conditional_branches.push(vec![(content_start, content_start)]);
                    }
                    b"elif" | b"else" => {
                        if let Some(branches) = conditional_branches.last_mut() {
                            if let Some(last) = branches.last_mut() {
                                last.1 = directive_start;
                            }
                            branches.push((content_start, content_start));
                        }
                    }
                    b"endif" => {
                        if let Some(mut branches) = conditional_branches.pop() {
                            if let Some(last) = branches.last_mut() {
                                last.1 = directive_start;
                            }
                            let shared_body = matches!(
                                src.get(cpp_skip_ws_and_directives(src, content_start)),
                                Some(b'{') | Some(b':')
                            );
                            if shared_body
                                && branches.len() >= 2
                                && branches
                                    .iter()
                                    .all(|&(s, e)| cpp_range_is_partial_declaration(src, s, e))
                            {
                                let keep_from = branches[branches.len() - 1].0;
                                blank_range_preserving_newlines(buf, branches[0].0, keep_from);
                            }
                        }
                    }
                    _ => {}
                }
            }
            line_start = true;
            continue;
        }
        line_start = false;

        if b == b'/' && i + 1 < n && src[i + 1] == b'/' {
            while i < n && src[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && i + 1 < n && src[i + 1] == b'*' {
            i += 2;
            while i + 1 < n {
                if src[i] == b'*' && src[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if b == b'"' || b == b'\'' {
            let quote = b;
            i += 1;
            while i < n {
                if src[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if src[i] == quote || src[i] == b'\n' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            prev_sig = quote;
            while i < n && src[i] == b'"' {
                i += 1;
            }
            continue;
        }

        if is_c_ident_start(b) {
            let start = i;
            while i < n && is_c_ident_continue(src[i]) {
                i += 1;
            }
            let word = &src[start..i];
            if matches!(word, b"class" | b"struct" | b"union" | b"enum") {
                pending_class = true;
                pending_namespace = false;
                pending_class_name = None;
                pending_class_from_template = angle_depth > 0;
            } else if word == b"namespace" {
                pending_namespace = true;
                pending_class = false;
                pending_class_name = None;
            } else if (pending_class || pending_namespace)
                && pending_class_name.is_none()
                && !matches!(
                    word,
                    b"final" | b"alignas" | b"public" | b"private" | b"protected" | b"virtual"
                )
            {
                pending_class_name = Some(String::from_utf8_lossy(word).into_owned());
            }
            let is_macro = is_cpp_macro_like_token(word);
            if !is_macro && word != b"operator" && word != b"typename" {
                if word == b"template" {
                    template_params_pending = true;
                }
                prev_sig = word[word.len() - 1];
                prev_word = (start, i);
                continue;
            }

            let p = cpp_skip_ws_and_directives(src, i);
            let prev_paren_was_control = prev_paren_closed_control && prev_sig == b')';
            prev_paren_closed_control = false;
            let prev_word_text = std::str::from_utf8(&src[prev_word.0..prev_word.1]).unwrap_or("");
            let prev_qualifier = matches!(
                prev_word_text,
                "const" | "volatile" | "noexcept" | "override" | "final" | "mutable"
            );
            let prev_control = matches!(prev_word_text, "if" | "while" | "switch" | "for");
            let statement_start = matches!(prev_sig, 0 | b'{' | b'}' | b';');

            let member_operator =
                (prev_sig == b'>' && start >= 2 && src[start - 2] == b'-') || prev_sig == b'.';
            if word == b"operator" && member_operator {
                let mut sym_start = i;
                while sym_start < n && matches!(src[sym_start], b' ' | b'\t') {
                    sym_start += 1;
                }
                let sym_end =
                    if src.get(sym_start) == Some(&b'(') && src.get(sym_start + 1) == Some(&b')') {
                        sym_start + 2
                    } else {
                        let mut q = sym_start;
                        while q < n && !matches!(src[q], b' ' | b'\t' | b'\r' | b'\n' | b'(') {
                            q += 1;
                        }
                        q
                    };
                let after_sym = cpp_skip_plain_ws(src, sym_end);
                if sym_end > sym_start && src.get(after_sym) == Some(&b'(') {
                    let buf = out.get_or_insert_with(|| src.to_vec());
                    blank_range_preserving_newlines(buf, start, sym_end);
                    let label = format!("q{}", synthetic_counter % 1000);
                    synthetic_counter += 1;
                    let bytes = label.as_bytes();
                    let take = bytes.len().min(i - start);
                    buf[start..start + take].copy_from_slice(&bytes[..take]);
                    i = sym_end;
                    prev_sig = b'0';
                    continue;
                }
            }
            if word == b"typename"
                && (matches!(prev_word_text, "using" | "return") || matches!(prev_sig, b'(' | b'='))
            {
                let buf = out.get_or_insert_with(|| src.to_vec());
                blank_range_preserving_newlines(buf, start, i);
                prev_sig = b' ';
                continue;
            }
            if !is_macro {
                prev_sig = word[word.len() - 1];
                prev_word = (start, i);
                continue;
            }
            if prev_control
                && prev_word.1 <= start
                && src[prev_word.1..start]
                    .iter()
                    .all(|b| b.is_ascii_whitespace())
                && src.get(p) == Some(&b'(')
            {
                let buf = out.get_or_insert_with(|| src.to_vec());
                blank_range_preserving_newlines(buf, start, i);
                prev_sig = b' ';
                continue;
            }

            if src.get(p) == Some(&b'(') {
                if let Some(close) = find_matching_paren_bytes(src, p) {
                    let after_idx = cpp_skip_plain_ws(src, close + 1);
                    let after = src.get(after_idx).copied().unwrap_or(0);
                    let trailing_annotation = (matches!(prev_sig, b')') || prev_qualifier)
                        && !prev_paren_was_control
                        && !(in_function_body(&brace_stack) && after != b'{');
                    if trailing_annotation {
                        let buf = out.get_or_insert_with(|| src.to_vec());
                        blank_range_preserving_newlines(buf, start, after_idx);
                        i = after_idx;
                        saw_paren = true;
                        continue;
                    }
                    let next_word_start = cpp_skip_ws_and_directives(src, after_idx);
                    let mut next_word_end = next_word_start;
                    while next_word_end < n && is_c_ident_continue(src[next_word_end]) {
                        next_word_end += 1;
                    }
                    let next_word = &src[next_word_start..next_word_end];
                    let next_is_macro = is_cpp_macro_like_token(next_word);
                    let prev_word_is_control_or_specifier = matches!(
                        prev_word_text,
                        "if" | "else"
                            | "while"
                            | "for"
                            | "switch"
                            | "do"
                            | "return"
                            | "case"
                            | "default"
                            | "goto"
                            | "sizeof"
                            | "new"
                            | "delete"
                            | "throw"
                            | "co_return"
                            | "co_await"
                            | "co_yield"
                            | "public"
                            | "private"
                            | "protected"
                    ) || is_cpp_declaration_keyword(
                        &src[prev_word.0..prev_word.1],
                    ) || prev_qualifier;
                    let prev_word_adjacent = !prev_word_text.is_empty()
                        && prev_word.1 <= start
                        && start > prev_word.1
                        && !prev_word_is_control_or_specifier
                        && {
                            let gap = &src[prev_word.1..start];
                            let mut j = 0usize;
                            let mut adjacent = true;
                            while j < gap.len() {
                                match gap[j] {
                                    b' ' | b'\t' | b'\r' | b'\n' | b'*' | b'&' | b'~' | b'<'
                                    | b'>' | b',' => j += 1,
                                    b':' if gap.get(j + 1) == Some(&b':') => j += 2,
                                    _ => {
                                        adjacent = false;
                                        break;
                                    }
                                }
                            }
                            adjacent
                        };
                    let constructor_name = brace_stack.iter().rev().find_map(|frame| match frame {
                        BraceCtx::Class(name) => Some(name.as_str()),
                        _ => None,
                    });
                    let in_constructor_context = constructor_name.is_some_and(|name| {
                        !name.is_empty()
                            && std::str::from_utf8(word)
                                .is_ok_and(|word| word.eq_ignore_ascii_case(name))
                    });
                    let prefix_end = cpp_skip_ws_and_comments_backwards(src, start);
                    let qualified_prefix = if prefix_end >= 2
                        && ((src[prefix_end - 2] == b':' && src[prefix_end - 1] == b':')
                            || (src[prefix_end - 2] == b'-' && src[prefix_end - 1] == b'>'))
                    {
                        true
                    } else {
                        prefix_end >= 1 && matches!(src[prefix_end - 1], b'.' | b'~')
                    };
                    let is_normal_declarator =
                        prev_word_adjacent || in_constructor_context || qualified_prefix;
                    if after == b'{' && (statement_start || prev_sig == b'>') {
                        if !is_normal_declarator {
                            let buf = out.get_or_insert_with(|| src.to_vec());
                            if cpp_block_has_access_specifier(src, after_idx) {
                                blank_range_preserving_newlines(buf, start, after_idx);
                                let take = 5.min(after_idx - start);
                                buf[start..start + take].copy_from_slice(&b"class"[..take]);
                                prev_sig = *buf.get(after_idx - 1).unwrap_or(&b' ');
                            } else {
                                blank_range_preserving_newlines(buf, start, i);
                                let label = format!("q{}", synthetic_counter % 1000);
                                synthetic_counter += 1;
                                let bytes = label.as_bytes();
                                let take = bytes.len().min(i - start);
                                buf[start..start + take].copy_from_slice(&bytes[..take]);
                                prev_sig = b'0';
                            }
                            i = after_idx;
                            saw_paren = true;
                            continue;
                        }
                        i = after_idx;
                        prev_sig = b')';
                        saw_paren = true;
                        continue;
                    }
                    if !is_normal_declarator
                        && is_c_ident_start(after)
                        && !matches!(
                            next_word,
                            b"const" | b"volatile" | b"noexcept" | b"override" | b"final"
                        )
                    {
                        let buf = out.get_or_insert_with(|| src.to_vec());
                        if is_cpp_declaration_keyword(next_word) || next_is_macro {
                            blank_range_preserving_newlines(buf, start, after_idx);
                            prev_sig = b' ';
                        } else {
                            blank_range_preserving_newlines(buf, start, after_idx);
                            let label = format!("q{}", synthetic_counter % 1000);
                            synthetic_counter += 1;
                            let bytes = label.as_bytes();
                            let take = bytes.len().min(i - start);
                            buf[start..start + take].copy_from_slice(&bytes[..take]);
                            prev_sig = b'0';
                        }
                        i = after_idx;
                        continue;
                    }
                    let code_fragment_arguments =
                        statement_start && cpp_invocation_arguments_are_code(src, p, close);
                    if !is_normal_declarator
                        && (!in_function_body(&brace_stack) || code_fragment_arguments)
                    {
                        let buf = out.get_or_insert_with(|| src.to_vec());
                        let blank_statement = statement_start && matches!(after, b';' | b'}');
                        blank_range_preserving_newlines(buf, start, after_idx);
                        if !blank_statement {
                            let label = format!("q{}", synthetic_counter % 1000);
                            synthetic_counter += 1;
                            let bytes = label.as_bytes();
                            let take = bytes.len().min(i - start);
                            buf[start..start + take].copy_from_slice(&bytes[..take]);
                            prev_sig = b'0';
                        } else {
                            prev_sig = b' ';
                        }
                        i = after_idx;
                        continue;
                    }
                    i = after_idx;
                    prev_sig = b')';
                    saw_paren = true;
                    continue;
                }
            } else {
                let next = src.get(p).copied().unwrap_or(0);
                let next_is_macro = if is_c_ident_start(next) {
                    let mut e = p;
                    while e < n && is_c_ident_continue(src[e]) {
                        e += 1;
                    }
                    is_cpp_macro_like_token(&src[p..e])
                } else {
                    false
                };
                if (matches!(prev_sig, b')') || prev_qualifier)
                    && (!prev_paren_was_control || next == b'{')
                    && !(in_function_body(&brace_stack) && next != b'{')
                    && (matches!(next, b';' | b'{' | b':' | b',' | b')' | b'=') || next_is_macro)
                {
                    let buf = out.get_or_insert_with(|| src.to_vec());
                    blank_range_preserving_newlines(buf, start, i);
                    continue;
                }
                if statement_start && matches!(next, b';' | b'}' | b')') {
                    let buf = out.get_or_insert_with(|| src.to_vec());
                    blank_range_preserving_newlines(buf, start, i);
                    continue;
                }
                if cpp_macro_is_leading_specifier(src, i, prev_sig, prev_word) {
                    let buf = out.get_or_insert_with(|| src.to_vec());
                    blank_range_preserving_newlines(buf, start, i);
                    continue;
                }
            }
            prev_sig = word[word.len() - 1];
            prev_word = (start, i);
            continue;
        }

        if b == b':'
            && src.get(i + 1) == Some(&b':')
            && (src[i + 2..].starts_with(b"new") || src[i + 2..].starts_with(b"delete"))
        {
            let buf = out.get_or_insert_with(|| src.to_vec());
            blank_range_preserving_newlines(buf, i, i + 2);
            i += 2;
            prev_sig = b' ';
            continue;
        }
        if b == b'-' && src.get(i + 1) == Some(&b'>') && src.get(i + 2) == Some(&b'*') {
            let buf = out.get_or_insert_with(|| src.to_vec());
            buf[i + 2] = b' ';
            i += 3;
            prev_sig = b'>';
            continue;
        }
        if b == b'.' && src.get(i + 1) == Some(&b'*') {
            let buf = out.get_or_insert_with(|| src.to_vec());
            buf[i + 1] = b' ';
            i += 2;
            prev_sig = b'.';
            continue;
        }
        if b == b':' && src.get(i + 1) == Some(&b':') && src.get(i + 2) == Some(&b'*') {
            let buf = out.get_or_insert_with(|| src.to_vec());
            blank_range_preserving_newlines(buf, i, i + 2);
            i += 2;
            prev_sig = b' ';
            continue;
        }

        match b {
            b'{' => {
                let frame = if pending_class {
                    BraceCtx::Class(pending_class_name.take().unwrap_or_default())
                } else if pending_namespace || !saw_paren {
                    BraceCtx::Other
                } else {
                    BraceCtx::Function
                };
                pending_class = false;
                pending_namespace = false;
                pending_class_name = None;
                pending_class_from_template = false;
                saw_paren = false;
                brace_stack.push(frame);
            }
            b'}' => {
                brace_stack.pop();
                pending_class = false;
                pending_namespace = false;
                pending_class_name = None;
                pending_class_from_template = false;
                saw_paren = false;
            }
            b';' => {
                pending_class = false;
                pending_namespace = false;
                pending_class_name = None;
                pending_class_from_template = false;
                saw_paren = false;
            }
            b'(' => {
                saw_paren = true;
                if pending_class_name.is_none() {
                    pending_class = false;
                    pending_class_from_template = false;
                }
                let prev_word_text =
                    std::str::from_utf8(&src[prev_word.0..prev_word.1]).unwrap_or("");
                let control_header = matches!(prev_word_text, "if" | "while" | "for" | "switch")
                    && prev_word.1 <= i
                    && src[prev_word.1..i].iter().all(|b| b.is_ascii_whitespace());
                paren_control_stack.push(control_header);
            }
            b')' => {
                prev_paren_closed_control = paren_control_stack.pop().unwrap_or(false);
            }
            b'<' if template_params_pending => {
                template_params_pending = false;
                angle_depth += 1;
            }
            b'>' if angle_depth > 0 => {
                angle_depth -= 1;
                if angle_depth == 0 && pending_class_from_template {
                    pending_class = false;
                    pending_class_name = None;
                    pending_class_from_template = false;
                }
            }
            _ => {}
        }

        prev_sig = b;
        i += 1;
    }

    out
}

fn cpp_skip_plain_ws(src: &[u8], mut p: usize) -> usize {
    while p < src.len() && matches!(src[p], b' ' | b'\t' | b'\r' | b'\n') {
        p += 1;
    }
    p
}

fn cpp_range_is_partial_declaration(src: &[u8], start: usize, end: usize) -> bool {
    let mut i = start;
    let end = end.min(src.len());
    let mut last = 0u8;
    while i < end {
        let b = src[i];
        if b == b'/' && src.get(i + 1) == Some(&b'/') {
            while i < end && src[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && src.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < end {
                if src[i] == b'*' && src[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if b == b'"' || b == b'\'' {
            let quote = b;
            i += 1;
            while i < end {
                if src[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if src[i] == quote || src[i] == b'\n' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            last = quote;
            continue;
        }
        if b == b'#' {
            while i < end && src[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            last = b;
        }
        i += 1;
    }
    last != 0 && !matches!(last, b';' | b'{' | b'}')
}

fn cpp_block_has_access_specifier(src: &[u8], open: usize) -> bool {
    let mut depth = 0usize;
    let mut i = open;
    while i < src.len() {
        match src[i] {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return false;
                }
            }
            _ => {}
        }
        if depth == 1 && is_c_ident_start(src[i]) {
            let start = i;
            while i < src.len() && is_c_ident_continue(src[i]) {
                i += 1;
            }
            let word = &src[start..i];
            if matches!(word, b"public" | b"private" | b"protected") {
                let after = cpp_skip_plain_ws(src, i);
                if src.get(after) == Some(&b':') {
                    return true;
                }
            }
            continue;
        }
        i += 1;
    }
    false
}

fn is_cpp_declaration_keyword(word: &[u8]) -> bool {
    matches!(
        word,
        b"static"
            | b"const"
            | b"constexpr"
            | b"consteval"
            | b"constinit"
            | b"inline"
            | b"virtual"
            | b"explicit"
            | b"friend"
            | b"typedef"
            | b"using"
            | b"template"
            | b"class"
            | b"struct"
            | b"union"
            | b"enum"
            | b"namespace"
            | b"extern"
            | b"typename"
            | b"mutable"
            | b"volatile"
            | b"register"
            | b"thread_local"
    )
}

fn cpp_skip_ws_and_directives(src: &[u8], mut p: usize) -> usize {
    loop {
        while p < src.len() && matches!(src[p], b' ' | b'\t' | b'\r' | b'\n') {
            p += 1;
        }
        if src.get(p) != Some(&b'#') {
            return p;
        }
        let mut line_start = p;
        while line_start > 0 && src[line_start - 1] != b'\n' {
            line_start -= 1;
        }
        if !src[line_start..p]
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\r'))
        {
            return p;
        }
        while p < src.len() {
            if src[p] == b'\\' && p + 1 < src.len() && matches!(src[p + 1], b'\n' | b'\r') {
                p += 1;
                if p < src.len() && src[p] == b'\r' {
                    p += 1;
                }
                if p < src.len() && src[p] == b'\n' {
                    p += 1;
                }
                continue;
            }
            if src[p] == b'\n' {
                break;
            }
            p += 1;
        }
    }
}

fn cpp_macro_is_leading_specifier(
    src: &[u8],
    end: usize,
    prev_sig: u8,
    prev_word: (usize, usize),
) -> bool {
    let prev_word_text = std::str::from_utf8(&src[prev_word.0..prev_word.1]).unwrap_or("");
    let prev_word_is_type_keyword = matches!(
        prev_word_text,
        "class" | "struct" | "union" | "enum" | "namespace"
    );
    if prev_word_is_type_keyword {
        return src
            .get(cpp_skip_ws_and_directives(src, end))
            .is_some_and(|&b| is_c_ident_start(b));
    }
    let prev_word_is_specifier = !prev_word_text.is_empty()
        && matches!(
            prev_word_text,
            "static"
                | "const"
                | "constexpr"
                | "consteval"
                | "constinit"
                | "inline"
                | "virtual"
                | "explicit"
                | "friend"
                | "volatile"
                | "mutable"
                | "register"
                | "extern"
                | "typename"
                | "thread_local"
        );
    if !(matches!(prev_sig, 0 | b'{' | b'}' | b';' | b':' | b'(' | b',' | b'>')
        || prev_word_is_specifier)
    {
        return false;
    }

    let mut p = cpp_skip_ws_and_directives(src, end);
    if !src.get(p).is_some_and(|&b| is_c_ident_start(b)) {
        return false;
    }
    let mut q = p;
    while q < src.len() && is_c_ident_continue(src[q]) {
        q += 1;
    }
    if is_cpp_macro_like_token(&src[p..q]) {
        return true;
    }
    p = cpp_skip_ws_and_directives(src, q);
    let after_next = src.get(p).copied().unwrap_or(0);
    if matches!(after_next, b'*' | b'&' | b'<') {
        return true;
    }
    if after_next == b'(' {
        let explicit_ctor = prev_word_is_specifier
            && std::str::from_utf8(&src[prev_word.0..prev_word.1])
                .map(|w| w == "explicit")
                .unwrap_or(false);
        if explicit_ctor {
            return true;
        }
        if let Some(close) = find_matching_paren_bytes(src, p) {
            let mut q = cpp_skip_ws_and_directives(src, close + 1);
            loop {
                let next = src.get(q).copied().unwrap_or(0);
                if matches!(next, b':' | b'{') {
                    return true;
                }
                if next == b';' || next == 0 {
                    return false;
                }
                if is_c_ident_start(next) {
                    let word_start = q;
                    while q < src.len() && is_c_ident_continue(src[q]) {
                        q += 1;
                    }
                    if !is_cpp_macro_like_token(&src[word_start..q]) {
                        return false;
                    }
                    let p2 = cpp_skip_ws_and_directives(src, q);
                    if src.get(p2) == Some(&b'(') {
                        match find_matching_paren_bytes(src, p2) {
                            Some(c2) => {
                                q = cpp_skip_ws_and_directives(src, c2 + 1);
                                continue;
                            }
                            None => return false,
                        }
                    }
                    q = p2;
                    continue;
                }
                return false;
            }
        }
        return false;
    }
    if after_next == b':' && src.get(p + 1) == Some(&b':') {
        return true;
    }
    is_c_ident_start(after_next)
}

struct CppTemplateSpec {
    display: String,
    raw_len: usize,
}

impl CppTemplateSpec {
    fn prefix(&self) -> &str {
        if self.raw_len > 80 || self.display.len() > 80 {
            "template<...>"
        } else {
            &self.display
        }
    }
}

fn join_cpp_scope(outer: Option<&str>, name: &str) -> String {
    match outer {
        Some(o) if !o.is_empty() => format!("{o}::{name}"),
        _ => name.to_string(),
    }
}

fn compose_cpp_enclosing_scope(enclosing_namespace: Option<&str>, clean_scope: &str) -> String {
    let scope = clean_scope.trim();
    let Some(ns) = enclosing_namespace
        .map(str::trim)
        .filter(|ns| !ns.is_empty())
    else {
        return scope.trim_start_matches("::").to_string();
    };
    let already_qualified = scope.starts_with("::")
        || scope == ns
        || scope
            .strip_prefix(ns)
            .is_some_and(|rest| rest.starts_with("::"));
    if already_qualified {
        scope.trim_start_matches("::").to_string()
    } else {
        format!("{ns}::{scope}")
    }
}

fn strip_cpp_template_arguments(raw: &str) -> String {
    if raw.contains("operator") {
        return raw.trim().to_string();
    }
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '<' {
            let mut depth = 0usize;
            let mut j = i;
            while j < chars.len() {
                match chars[j] {
                    '<' => depth += 1,
                    '>' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if j < chars.len() {
                i = j + 1;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out.trim().to_string()
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
    enclosing_namespace: Option<&str>,
    template_spec: Option<&CppTemplateSpec>,
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
    let mut next_enclosing_namespace: Option<String> = enclosing_namespace.map(ToOwned::to_owned);
    let local_template: Option<CppTemplateSpec> =
        if ctx.scanned.language == LanguageKind::Cpp && kind == "template_declaration" {
            extract_cpp_template_spec(ctx, node)
        } else {
            None
        };

    match ctx.scanned.language {
        LanguageKind::C | LanguageKind::Cpp => {
            handle_c_cpp_node(
                ctx,
                node,
                kind,
                enclosing_type,
                enclosing_fn,
                enclosing_namespace,
                template_spec,
                &mut next_enclosing_type,
                &mut next_enclosing_fn,
                &mut next_enclosing_namespace,
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
    let active_namespace = next_enclosing_namespace.as_deref();

    extract_local_var_binding(ctx, node, kind, active_fn);
    extract_fn_ptr_candidates_from_node(ctx, node, kind, active_fn);
    extract_field_access_mutability(ctx, node, kind, active_type, active_fn);

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let child_template = match local_template.as_ref() {
            Some(spec) if child.kind() != "template_parameter_list" => Some(spec),
            _ => template_spec,
        };
        walk_ast(
            ctx,
            child,
            active_type,
            active_fn,
            active_namespace,
            child_template,
        );
    }

    if let Some((prev_types, prev_elems, prev_vars)) = saved_scope {
        ctx.local_var_types = prev_types;
        ctx.local_collection_elem_types = prev_elems;
        ctx.local_vars = prev_vars;
    }
    ctx.in_test_scope = prev_test_scope;
}

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

#[allow(clippy::too_many_arguments)]
fn handle_c_cpp_node(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    kind: &str,
    enclosing_type: Option<&str>,
    enclosing_fn: Option<(&str, usize)>,
    enclosing_namespace: Option<&str>,
    template_spec: Option<&CppTemplateSpec>,
    next_enclosing_type: &mut Option<String>,
    next_enclosing_fn: &mut Option<(String, usize)>,
    next_enclosing_namespace: &mut Option<String>,
) {
    match kind {
        "namespace_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let raw = normalize_whitespace(node_text(name_node, ctx.bytes));
                let raw = raw.strip_prefix("inline ").unwrap_or(&raw).trim();
                let cleaned = strip_cpp_template_arguments(raw);
                if !cleaned.is_empty() && cleaned != "inline" {
                    *next_enclosing_namespace = Some(join_cpp_scope(enclosing_namespace, &cleaned));
                }
            }
        }
        "function_definition" => {
            if let Some(sym) = extract_c_cpp_function(
                ctx,
                node,
                enclosing_type,
                enclosing_namespace,
                template_spec,
                false,
            ) {
                *next_enclosing_fn = Some((sym.name.clone(), sym.start_line));
                ctx.symbols.push(sym);
            }
        }
        "declaration" => {
            if ctx.is_header && is_cpp_method_field_declaration(node) {
                let text = node_text(node, ctx.bytes);
                if !text.trim_start().starts_with("typedef") {
                    if let Some(sym) = extract_c_cpp_function(
                        ctx,
                        node,
                        enclosing_type,
                        enclosing_namespace,
                        template_spec,
                        true,
                    ) {
                        ctx.header_prototypes.push(sym);
                    }
                }
            } else if has_descendant_kind(node, "operator_cast") {
                if let Some(sym) = extract_c_cpp_function(
                    ctx,
                    node,
                    enclosing_type,
                    enclosing_namespace,
                    template_spec,
                    true,
                ) {
                    if ctx.is_header {
                        ctx.header_prototypes.push(sym);
                    } else {
                        ctx.symbols.push(sym);
                    }
                }
            } else if enclosing_fn.is_none() {
                extract_c_cpp_const_declaration(ctx, node);
            }
        }
        "field_declaration" => {
            if ctx.is_header
                && !has_cpp_type_specifier_child(node)
                && is_cpp_method_field_declaration(node)
            {
                if let Some(sym) = extract_c_cpp_function(
                    ctx,
                    node,
                    enclosing_type,
                    enclosing_namespace,
                    template_spec,
                    true,
                ) {
                    ctx.header_prototypes.push(sym);
                }
            }
        }
        "alias_declaration" => {
            extract_cpp_alias(ctx, node, enclosing_type, enclosing_namespace);
        }
        "type_definition" => {
            extract_c_typedef(ctx, node, enclosing_type, enclosing_namespace);
        }
        "struct_specifier" | "union_specifier" | "enum_specifier" | "class_specifier" => {
            let type_kind = match kind {
                "struct_specifier" => TypeKind::Struct,
                "union_specifier" => TypeKind::Union,
                "enum_specifier" => TypeKind::Enum,
                _ => TypeKind::Class,
            };
            if let Some(ty_name) =
                extract_c_specifier_type(ctx, node, type_kind, enclosing_type, enclosing_namespace)
            {
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

fn has_cpp_type_specifier_child(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    let mut found = false;
    for child in node.children(&mut cursor) {
        if matches!(
            child.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
        ) {
            found = true;
            break;
        }
    }
    found
}

fn extract_cpp_template_spec(ctx: &ExtractContext<'_>, node: Node<'_>) -> Option<CppTemplateSpec> {
    let mut decl_start = node.end_byte();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "template_parameter_list" {
            decl_start = child.start_byte();
            break;
        }
    }
    if decl_start <= node.start_byte() {
        return None;
    }
    let raw = std::str::from_utf8(ctx.bytes.get(node.start_byte()..decl_start)?).ok()?;
    let display = normalize_whitespace(raw);
    if !display.starts_with("template") || !display.contains('<') {
        return None;
    }
    Some(CppTemplateSpec {
        display,
        raw_len: raw.trim_end().len(),
    })
}

fn extract_cpp_alias(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
    enclosing_namespace: Option<&str>,
) {
    let name_node = node
        .child_by_field_name("name")
        .or_else(|| node.named_child(0));
    let Some(name_node) = name_node else {
        return;
    };
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() || !is_valid_identifier(&name) {
        return;
    }
    let fields_summary = node
        .child_by_field_name("type")
        .map(|t| normalize_whitespace(node_text(t, ctx.bytes)))
        .unwrap_or_default();
    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let doc_summary = extract_preceding_doc(ctx.lines, start_line);
    let scope = enclosing_type
        .map(ToOwned::to_owned)
        .or_else(|| enclosing_namespace.map(ToOwned::to_owned));
    let qualified_name = join_cpp_scope(scope.as_deref(), &name);
    let type_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
    ctx.types.push(ExtractedType {
        type_id,
        name,
        kind: TypeKind::Typedef,
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

fn declarator_is_buffer_repair(node: Node<'_>, bytes: &[u8]) -> bool {
    let start = node.start_byte();
    let end = node.end_byte();
    start < end
        && end < bytes.len()
        && is_c_ident_continue(bytes[end])
        && bytes[start..end].iter().all(|b| is_c_ident_continue(*b))
}

fn extract_c_cpp_function(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
    enclosing_namespace: Option<&str>,
    template_spec: Option<&CppTemplateSpec>,
    is_prototype: bool,
) -> Option<ExtractedSymbol> {
    let fn_decl = find_first_descendant_of_kind(node, "function_declarator");
    let raw_decl_name = if let Some(fn_decl) = fn_decl {
        let decl_target = fn_decl.child_by_field_name("declarator").unwrap_or(fn_decl);
        extract_declarator_name(decl_target, ctx.bytes)?
    } else {
        let cast = find_first_descendant_of_kind(node, "operator_cast")?;
        match node.child_by_field_name("declarator") {
            Some(decl) if matches!(decl.kind(), "qualified_identifier" | "scoped_identifier") => {
                let text = normalize_whitespace(node_text(decl, ctx.bytes));
                let idx = text.rfind("operator").unwrap_or(0);
                let leaf = &text[idx..];
                let op_name = if leaf.starts_with("operator()") {
                    "operator()".to_string()
                } else {
                    leaf.split('(').next().unwrap_or(leaf).trim().to_string()
                };
                let scope = strip_cpp_template_arguments(
                    text[..idx]
                        .trim()
                        .trim_end_matches(':')
                        .trim_end_matches(':'),
                );
                if scope.is_empty() {
                    op_name
                } else {
                    format!("{scope}::{op_name}")
                }
            }
            _ => extract_declarator_name(cast, ctx.bytes)?,
        }
    };
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

    let (mut name, mut forced_isr) =
        if (raw_decl_name == "ISR" || raw_decl_name == "SIGNAL") && !is_prototype {
            if let Some(params) = fn_decl.and_then(|n| n.child_by_field_name("parameters")) {
                let param_txt = node_text(params, ctx.bytes).trim();
                (format!("{raw_decl_name}{param_txt}"), true)
            } else {
                (raw_decl_name, true)
            }
        } else {
            (raw_decl_name, false)
        };

    if ctx.scanned.language == LanguageKind::Cpp && !forced_isr {
        let decl_node = fn_decl
            .and_then(|n| n.child_by_field_name("declarator"))
            .or(fn_decl)
            .unwrap_or(node);
        if declarator_is_buffer_repair(decl_node, ctx.bytes) {
            return None;
        }
    }

    let mut effective_enclosing: Option<String> = enclosing_type.map(ToOwned::to_owned);
    let mut namespace_scope: Option<String> = enclosing_namespace.map(ToOwned::to_owned);
    if let Some((scope_part, leaf_part)) = name.rsplit_once("::") {
        let clean_scope = strip_cpp_template_arguments(scope_part);
        let clean_leaf = strip_cpp_template_arguments(leaf_part);
        if !clean_scope.is_empty() && !clean_leaf.is_empty() {
            effective_enclosing = Some(compose_cpp_enclosing_scope(
                enclosing_namespace,
                &clean_scope,
            ));
            namespace_scope = None;
            name = clean_leaf;
        }
    } else {
        name = strip_cpp_template_arguments(&name);
    }

    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let doc_summary = extract_preceding_doc(ctx.lines, start_line);
    let has_isr_attr = has_preceding_interrupt_attr(ctx.lines, start_line);
    if has_isr_attr {
        forced_isr = true;
    }

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
        Some(enc) => join_cpp_scope(Some(enc), &name),
        None => join_cpp_scope(namespace_scope.as_deref(), &name),
    };
    let symbol_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
    let mut signature = extract_clean_signature(node, ctx.bytes);
    if let Some(spec) = template_spec {
        signature = truncate_str(&format!("{} {}", spec.prefix(), signature), 160);
    }

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

fn extract_c_typedef(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
    enclosing_namespace: Option<&str>,
) {
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

    let type_scope = enclosing_type.or(enclosing_namespace);
    let qualified_name = join_cpp_scope(type_scope, &typedef_name);
    let type_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
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
    enclosing_type: Option<&str>,
    enclosing_namespace: Option<&str>,
) -> Option<String> {
    let range = (node.start_byte(), node.end_byte());
    let raw_name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.bytes).trim().to_string())?;
    let name = strip_cpp_template_arguments(&raw_name);
    if ctx.handled_type_ranges.contains(&range) {
        return Some(name);
    }

    let _body = node.child_by_field_name("body")?;
    if name.is_empty() {
        return None;
    }
    let qualified_name = if name.contains("::") {
        name.clone()
    } else if let Some(enc) = enclosing_type {
        join_cpp_scope(Some(enc), &name)
    } else {
        join_cpp_scope(enclosing_namespace, &name)
    };

    ctx.handled_type_ranges.insert(range);
    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;
    let doc_summary = extract_preceding_doc(ctx.lines, start_line);
    let fields_summary = summarize_c_type_fields(node, ctx.bytes);

    let type_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
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

    Some(qualified_name)
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

    if matches!(
        name,
        "main" | "Reset_Handler" | "app_main" | "setup" | "loop" | "_start" | "SystemInit"
    ) {
        return SymbolKind::Entrypoint;
    }

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

    let enclosing_leaf = enclosing_type
        .and_then(|enc| enc.rsplit("::").next())
        .unwrap_or("");
    if matches!(
        name,
        "__init__" | "__new__" | "new" | "constructor" | "default"
    ) || (enclosing_type.is_some()
        && (name.starts_with("new_") || (enclosing_leaf == name && !name.starts_with('~'))))
    {
        return SymbolKind::Constructor;
    }

    if enclosing_type.is_some() {
        return SymbolKind::Method;
    }

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

    if let Some((before_gen, _)) = s.split_once('<') {
        s = before_gen.trim();
    }
    if let Some((before_arr, _)) = s.split_once('[') {
        s = before_arr.trim();
    }
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

    let full_expr = node_text(node, ctx.bytes);
    if full_expr.contains("->") && is_screaming_snake_case(recv_clean) {
        return;
    }

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

fn cpp_skip_literal_or_comment(src: &[u8], i: usize) -> Option<usize> {
    let n = src.len();
    match *src.get(i)? {
        b'"' | b'\'' => {
            let quote = src[i];
            let mut j = i + 1;
            while j < n {
                match src[j] {
                    b'\\' => j += 2,
                    b'\n' => return Some(j + 1),
                    b if b == quote => return Some(j + 1),
                    _ => j += 1,
                }
            }
            Some(n)
        }
        b'R' if src.get(i + 1) == Some(&b'"') && (i == 0 || !is_c_ident_continue(src[i - 1])) => {
            let delim_start = i + 2;
            let mut delim_end = delim_start;
            while delim_end < n
                && delim_end - delim_start < 16
                && !matches!(src[delim_end], b'(' | b')' | b'\\')
                && !src[delim_end].is_ascii_whitespace()
            {
                delim_end += 1;
            }
            if src.get(delim_end) != Some(&b'(') {
                return cpp_skip_literal_or_comment(src, i + 1);
            }
            let delim = &src[delim_start..delim_end];
            let mut j = delim_end + 1;
            while j < n {
                if src[j] == b')'
                    && src.get(j + 1..j + 1 + delim.len()) == Some(delim)
                    && src.get(j + 1 + delim.len()) == Some(&b'"')
                {
                    return Some(j + 2 + delim.len());
                }
                j += 1;
            }
            Some(n)
        }
        b'/' if src.get(i + 1) == Some(&b'/') => {
            let mut j = i + 2;
            while j < n {
                if src[j] == b'\\' && src.get(j + 1) == Some(&b'\n') {
                    j += 2;
                    continue;
                }
                if src[j] == b'\\' && src.get(j + 1) == Some(&b'\r') {
                    j += 2;
                    if src.get(j) == Some(&b'\n') {
                        j += 1;
                    }
                    continue;
                }
                if src[j] == b'\n' {
                    break;
                }
                j += 1;
            }
            Some(j)
        }
        b'/' if src.get(i + 1) == Some(&b'*') => {
            let mut j = i + 2;
            while j + 1 < n {
                if src[j] == b'*' && src[j + 1] == b'/' {
                    return Some(j + 2);
                }
                j += 1;
            }
            Some(n)
        }
        _ => None,
    }
}

fn cpp_skip_ws_and_comments_backwards(src: &[u8], mut end: usize) -> usize {
    loop {
        while end > 0 && src[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        if end == 0 {
            return 0;
        }
        if end >= 2 && src[end - 2] == b'*' && src[end - 1] == b'/' {
            let mut j = end - 2;
            let mut comment_start = None;
            while j >= 2 {
                if src[j - 2] == b'/' && src[j - 1] == b'*' {
                    comment_start = Some(j - 2);
                    break;
                }
                j -= 1;
            }
            match comment_start {
                Some(start) => {
                    end = start;
                    continue;
                }
                None => return end,
            }
        }
        let line_start = src[..end]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |p| p + 1);
        let line = &src[line_start..end];
        if let Some(offset) = line.windows(2).position(|w| w == b"//") {
            if line[..offset].iter().all(|b| b.is_ascii_whitespace()) {
                end = line_start;
                continue;
            }
        }
        return end;
    }
}

fn cpp_skip_ws_and_block_comments_backwards(src: &[u8], mut end: usize, floor: usize) -> usize {
    loop {
        while end > floor && src[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        if end < floor + 2 || src[end - 2] != b'*' || src[end - 1] != b'/' {
            return end;
        }
        let mut j = end - 2;
        let mut comment_start = None;
        while j >= floor + 2 {
            if src[j - 2] == b'/' && src[j - 1] == b'*' {
                comment_start = Some(j - 2);
                break;
            }
            j -= 1;
        }
        match comment_start {
            Some(start) => end = start,
            None => return end,
        }
    }
}

fn cpp_invocation_arguments_are_code(src: &[u8], open: usize, close: usize) -> bool {
    let mut depth = 0usize;
    let mut argument_start = open + 1;
    let mut i = open + 1;
    while i < close {
        if let Some(next) = cpp_skip_literal_or_comment(src, i) {
            i = next;
            continue;
        }
        match src[i] {
            b'(' => {
                if depth == 0 && cpp_declaration_before_paren(src, argument_start, i) {
                    return true;
                }
                depth += 1;
            }
            b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b';' if depth == 0 => return true,
            b',' if depth == 0 => argument_start = i + 1,
            _ => {}
        }
        i += 1;
    }
    false
}

fn cpp_declaration_before_paren(src: &[u8], argument_start: usize, pos: usize) -> bool {
    let mut end = cpp_skip_ws_and_block_comments_backwards(src, pos, argument_start);
    let name_end = end;
    while end > argument_start && is_c_ident_continue(src[end - 1]) {
        end -= 1;
    }
    if end == name_end {
        return false;
    }
    let before = cpp_skip_ws_and_block_comments_backwards(src, end, argument_start);
    if before == argument_start {
        return false;
    }
    let previous = src[before - 1];
    if previous == b'.' || previous == b':' {
        return false;
    }
    if previous == b'>' && before >= 2 && src[before - 2] == b'-' {
        return false;
    }
    previous.is_ascii_alphanumeric()
        || previous == b'_'
        || matches!(previous, b'>' | b'*' | b'&' | b']')
}

fn extract_declarator_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" | "destructor_name" => {
            Some(node_text(node, bytes).trim().to_string())
        }
        "operator_name" | "literal_operator_name" => {
            Some(normalize_whitespace(node_text(node, bytes)))
        }
        "operator_cast" => {
            let text = node_text(node, bytes);
            Some(text.split('(').next().unwrap_or(text).trim().to_string())
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

    let mut idx = start_line - 2;
    let mut doc_lines = Vec::new();
    let mut in_block_comment = false;

    while let Some(raw_line) = lines.get(idx) {
        let trimmed = raw_line.trim();

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

    let mut i = scan_pos;
    while i + 7 <= len {
        if bytes[i] == b'<' && source[i + 1..].len() >= 6 {
            let candidate = &bytes[i + 1..i + 7];
            if candidate.eq_ignore_ascii_case(b"script") {
                let next_b = bytes.get(i + 7).copied().unwrap_or(b'>');
                if matches!(next_b, b'>' | b' ' | b'\t' | b'\r' | b'\n' | b'/') {
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
