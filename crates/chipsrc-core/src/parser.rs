//! Layer 1 — Multi-language Tree-sitter CST parser and incremental AST extractor.
//!
//! Supports C, C++, Rust, Python, TypeScript, TSX, JavaScript, and JSX.
//! Extracts symbols, types, macros/constants, MMIO register accesses, imports,
//! call sites, and cross-reference sites in a single pass per file.

use crate::error::{ChipsrcError, Result};
use crate::mmio::{classify_macro_value, extract_mmio_and_linker_constructs};
use crate::model::{
    ArchLayer, ExtractedImport, ExtractedMacro, ExtractedSymbol, ExtractedType,
    IncrementalAstCache, LanguageKind, MacroKind, ParsedFileUnit, RawCallSite, RawXrefSite,
    ScannedFile, SymbolKind, TypeKind, Visibility,
};
use crate::scanner::assign_section_id;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs;
use tree_sitter::{Language, Node, Parser};

/// Parses all `scanned_files`, reusing unchanged entries from `existing_cache` when
/// `size_bytes` and `blake3_hash` match, and parsing new or modified files in parallel via Rayon.
///
/// Returns `(all_units_sorted_by_rel_path, reused_count, reparsed_count)`.
pub fn parse_files_incremental(
    scanned_files: &[ScannedFile],
    existing_cache: Option<&IncrementalAstCache>,
) -> Result<(Vec<ParsedFileUnit>, usize, usize)> {
    let mut reused_units = Vec::new();
    let mut to_parse = Vec::new();

    for scanned in scanned_files {
        let cached_hit = existing_cache
            .and_then(|cache| cache.files.get(&scanned.rel_path))
            .filter(|unit| {
                unit.scanned.size_bytes == scanned.size_bytes
                    && unit.scanned.blake3_hash == scanned.blake3_hash
            });

        if let Some(cached_unit) = cached_hit {
            let mut unit = cached_unit.clone();
            unit.scanned = scanned.clone();
            reused_units.push(unit);
        } else {
            to_parse.push(scanned);
        }
    }

    let reused_count = reused_units.len();
    let reparsed_count = to_parse.len();

    let parsed_results: Vec<Result<ParsedFileUnit>> =
        to_parse.into_par_iter().map(parse_single_file).collect();

    let mut all_units = Vec::with_capacity(reused_count + reparsed_count);
    all_units.extend(reused_units);
    for res in parsed_results {
        all_units.push(res?);
    }

    all_units.sort_by(|a, b| a.scanned.rel_path.cmp(&b.scanned.rel_path));
    Ok((all_units, reused_count, reparsed_count))
}

/// Parses a single `ScannedFile` from disk using Tree-sitter and extracts all symbols,
/// types, macros, MMIO register accesses, imports, and call sites.
pub fn parse_single_file(scanned: &ScannedFile) -> Result<ParsedFileUnit> {
    let raw_bytes =
        fs::read(&scanned.abs_path).map_err(|e| ChipsrcError::io(&scanned.abs_path, e))?;
    let source = String::from_utf8_lossy(&raw_bytes);
    parse_source_str(scanned, &source)
}

/// Parses an in-memory `source` string for a given `ScannedFile` descriptor.
pub fn parse_source_str(scanned: &ScannedFile, source: &str) -> Result<ParsedFileUnit> {
    let mut parser = Parser::new();
    let ts_lang = tree_sitter_language(scanned.language);
    parser
        .set_language(&ts_lang)
        .map_err(|e| ChipsrcError::ParserConfig(e.to_string()))?;

    let tree = parser.parse(source.as_bytes(), None).ok_or_else(|| {
        ChipsrcError::ParserConfig(format!(
            "Tree-sitter returned None for {}",
            scanned.rel_path
        ))
    })?;

    let (section_id, _, _) =
        assign_section_id(&scanned.rel_path, scanned.scope, scanned.arch_layer);
    let lines: Vec<&str> = source.lines().collect();

    let mut ctx = ExtractContext {
        scanned,
        bytes: source.as_bytes(),
        lines: &lines,
        section_id: &section_id,
        is_header: is_c_or_cpp_header(&scanned.rel_path),
        symbols: Vec::new(),
        header_prototypes: Vec::new(),
        types: Vec::new(),
        macros: Vec::new(),
        imports: Vec::new(),
        raw_calls: Vec::new(),
        raw_xrefs: Vec::new(),
        handled_type_ranges: HashSet::new(),
        parse_errors: 0,
    };

    let root = tree.root_node();
    walk_ast(&mut ctx, root, None, None);

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

struct ExtractContext<'a> {
    scanned: &'a ScannedFile,
    bytes: &'a [u8],
    lines: &'a [&'a str],
    section_id: &'a str,
    is_header: bool,
    symbols: Vec<ExtractedSymbol>,
    header_prototypes: Vec<ExtractedSymbol>,
    types: Vec<ExtractedType>,
    macros: Vec<ExtractedMacro>,
    imports: Vec<ExtractedImport>,
    raw_calls: Vec<RawCallSite>,
    raw_xrefs: Vec<RawXrefSite>,
    handled_type_ranges: HashSet<(usize, usize)>,
    parse_errors: usize,
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

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_ast(
            ctx,
            child,
            next_enclosing_type.as_deref(),
            next_enclosing_fn.as_ref().map(|(n, l)| (n.as_str(), *l)),
        );
    }
}

// ============================================================================
// C / C++ AST Extraction
// ============================================================================

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
            if ctx.is_header && has_descendant_kind(node, "function_declarator") {
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
            // C++ method declaration inside class/struct or top-level function pointer field
            if has_descendant_kind(node, "function_declarator")
                && (ctx.is_header || enclosing_type.is_none())
            {
                if let Some(sym) = extract_c_cpp_function(ctx, node, enclosing_type, true) {
                    if ctx.is_header {
                        ctx.header_prototypes.push(sym);
                    } else {
                        ctx.symbols.push(sym);
                    }
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

fn extract_c_cpp_function(
    ctx: &ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
    is_prototype: bool,
) -> Option<ExtractedSymbol> {
    let fn_decl = find_first_descendant_of_kind(node, "function_declarator")?;
    let decl_target = fn_decl.child_by_field_name("declarator").unwrap_or(fn_decl);
    let raw_decl_name = extract_declarator_name(decl_target, ctx.bytes)?;
    if raw_decl_name.is_empty() {
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

    let full_text = node_text(node, ctx.bytes);
    let visibility = if full_text.starts_with("static ")
        || full_text.contains("\nstatic ")
        || full_text.contains(" static ")
    {
        Visibility::Static
    } else {
        Visibility::Public
    };

    let kind = classify_symbol_kind(
        &name,
        effective_enclosing.as_deref(),
        forced_isr,
        ctx.scanned.arch_layer,
        full_text,
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
        section_id: ctx.section_id.to_string(),
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
        section_id: ctx.section_id.to_string(),
    });

    Some(name)
}

fn summarize_c_type_fields(type_node: Node<'_>, bytes: &[u8]) -> String {
    let Some(body) = type_node.child_by_field_name("body") else {
        return String::new();
    };
    let mut items = Vec::new();
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if items.len() >= 6 {
            break;
        }
        match child.kind() {
            "field_declaration" => {
                let ty_txt = child
                    .child_by_field_name("type")
                    .map(|n| normalize_whitespace(node_text(n, bytes)))
                    .unwrap_or_default();
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
    items.join(", ")
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

    let raw_val = node
        .child_by_field_name("value")
        .map(|v| normalize_whitespace(node_text(v, ctx.bytes)))
        .unwrap_or_default();

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

    let (kind, hex_addr, description) = classify_macro_value(&name, &raw_val, is_fn_like);
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
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
    let raw_val = normalize_whitespace(node_text(val_node, ctx.bytes));
    let (mut kind, hex_addr, mut description) = classify_macro_value(&name, &raw_val, false);
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
        section_id: ctx.section_id.to_string(),
        description,
    });
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
            extract_rust_const_or_static(ctx, node);
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
        "call_expression" | "macro_invocation" => {
            extract_call_site(ctx, node, enclosing_fn);
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
    let full_text = node_text(node, ctx.bytes);

    let visibility = parse_rust_visibility(full_text);
    let kind = classify_symbol_kind(
        &name,
        enclosing_type,
        has_isr_attr,
        ctx.scanned.arch_layer,
        full_text,
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
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
    let visibility = parse_rust_visibility(node_text(node, ctx.bytes));
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
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
        if items.len() >= 6 {
            break;
        }
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
    items.join(", ")
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
        .map(|v| normalize_whitespace(node_text(v, ctx.bytes)))
        .unwrap_or_default();

    let (mut kind, hex_addr, mut description) = classify_macro_value(&name, &raw_val, false);
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
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
    let raw_path = full
        .trim_start_matches("pub(crate) ")
        .trim_start_matches("pub ")
        .trim_start_matches("use ")
        .trim_end_matches(';')
        .trim()
        .to_string();
    if raw_path.is_empty() {
        return;
    }

    let is_system = raw_path.starts_with("std::")
        || raw_path.starts_with("core::")
        || raw_path.starts_with("alloc::");
    let imported_names = parse_rust_use_leaves(&raw_path);
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

fn parse_rust_visibility(text: &str) -> Visibility {
    let trimmed = text.trim_start();
    if trimmed.starts_with("pub(crate)") || trimmed.starts_with("pub(super)") {
        Visibility::Internal
    } else if trimmed.starts_with("pub ") || trimmed.starts_with("pub(") {
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
        "function_definition" => {
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

    let full_text = node_text(node, ctx.bytes);
    let kind = classify_symbol_kind(
        &name,
        enclosing_type,
        false,
        ctx.scanned.arch_layer,
        full_text,
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
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
        if items.len() >= 6 {
            break;
        }
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
            "function_definition" => {
                if let Some(mname) = child.child_by_field_name("name") {
                    items.push(format!("def {}", node_text(mname, bytes).trim()));
                }
            }
            _ => {}
        }
    }
    items.join(", ")
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
        .map(|r| normalize_whitespace(node_text(r, ctx.bytes)))
        .unwrap_or_default();

    let (mut kind, hex_addr, mut description) = classify_macro_value(&name, &raw_val, false);
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
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
        "class_declaration" | "interface_declaration" => {
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
            if enclosing_fn.is_none() {
                if let Some(sym) = extract_ts_js_arrow_or_const(ctx, node, enclosing_type) {
                    *next_enclosing_fn = Some((sym.name.clone(), sym.start_line));
                    ctx.symbols.push(sym);
                }
            }
        }
        "import_statement" => {
            extract_ts_js_import(ctx, node, enclosing_fn);
        }
        "call_expression" | "new_expression" => {
            extract_call_site(ctx, node, enclosing_fn);
        }
        _ => {}
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
    let full_text = node_text(node, ctx.bytes);
    let visibility =
        if is_exported || full_text.starts_with("public ") || node.kind() == "method_signature" {
            Visibility::Public
        } else if full_text.starts_with("private ") || name.starts_with('#') {
            Visibility::Private
        } else if full_text.starts_with("protected ") {
            Visibility::Protected
        } else {
            Visibility::Internal
        };

    let kind = classify_symbol_kind(
        &name,
        enclosing_type,
        false,
        ctx.scanned.arch_layer,
        full_text,
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
        section_id: ctx.section_id.to_string(),
    })
}

fn extract_ts_js_arrow_or_const(
    ctx: &mut ExtractContext<'_>,
    node: Node<'_>,
    enclosing_type: Option<&str>,
) -> Option<ExtractedSymbol> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.bytes).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let val_node = node.child_by_field_name("value")?;
    let vkind = val_node.kind();

    let decl_parent = node.parent().unwrap_or(node);
    let is_exported = decl_parent
        .parent()
        .is_some_and(|p| p.kind() == "export_statement");

    if vkind == "arrow_function" || vkind == "function_expression" || vkind == "function" {
        let start_line = decl_parent.start_position().row + 1;
        let end_line = node.end_position().row + 1;
        let doc_summary = extract_preceding_doc(ctx.lines, start_line);
        let visibility = if is_exported {
            Visibility::Public
        } else {
            Visibility::Internal
        };
        let full_text = node_text(decl_parent, ctx.bytes);
        let kind = classify_symbol_kind(
            &name,
            enclosing_type,
            false,
            ctx.scanned.arch_layer,
            full_text,
        );
        let qualified_name = match enclosing_type {
            Some(enc) => format!("{enc}::{name}"),
            None => name.clone(),
        };
        let symbol_id = format!("{}::{}", ctx.scanned.rel_path, qualified_name);
        let signature = extract_clean_signature(decl_parent, ctx.bytes);

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
            scope: ctx.scanned.scope,
            arch_layer: ctx.scanned.arch_layer,
            section_id: ctx.section_id.to_string(),
        });
    }

    // Check top-level SCREAMING_SNAKE_CASE constant
    if is_screaming_snake_case(&name) {
        let raw_val = normalize_whitespace(node_text(val_node, ctx.bytes));
        let (mut kind, hex_addr, mut description) = classify_macro_value(&name, &raw_val, false);
        if kind == MacroKind::ObjectMacro {
            kind = MacroKind::Constant;
            description = "Module constant".to_string();
        }
        let line = node.start_position().row + 1;
        ctx.macros.push(ExtractedMacro {
            name,
            kind,
            value_or_args: truncate_str(&raw_val, 160),
            hex_addr,
            file: ctx.scanned.rel_path.clone(),
            line,
            scope: ctx.scanned.scope,
            arch_layer: ctx.scanned.arch_layer,
            section_id: ctx.section_id.to_string(),
            description,
        });
    }

    None
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
        scope: ctx.scanned.scope,
        arch_layer: ctx.scanned.arch_layer,
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
        if items.len() >= 6 {
            break;
        }
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
    items.join(", ")
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
    let Some((callee_name, receiver_or_qualifier)) = parse_callee_expression(&raw_callee) else {
        return;
    };

    let (caller_name, caller_start_line) = match enclosing_fn {
        Some((name, start)) => (name.to_string(), start),
        None => ("<module_init>".to_string(), 1),
    };

    let call_line = node.start_position().row + 1;
    let context_line = ctx
        .lines
        .get(call_line.saturating_sub(1))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| truncate_str(&normalize_whitespace(node_text(node, ctx.bytes)), 120));

    ctx.raw_calls.push(RawCallSite {
        caller_file: ctx.scanned.rel_path.clone(),
        caller_name: caller_name.clone(),
        caller_start_line,
        callee_name: callee_name.clone(),
        receiver_or_qualifier,
        call_line,
    });

    ctx.raw_xrefs.push(RawXrefSite {
        file: ctx.scanned.rel_path.clone(),
        line: call_line,
        enclosing_symbol: Some(caller_name),
        target_name: callee_name,
        category: "call".to_string(),
        context: truncate_str(&context_line, 120),
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
    } else if let Some((q, l)) = cleaned.rsplit_once('.') {
        (Some(q.trim().to_string()), l.trim())
    } else {
        (None, cleaned)
    };

    if !is_valid_identifier(leaf) {
        return None;
    }

    let qualifier = qualifier.filter(|q| !q.is_empty());
    Some((leaf.to_string(), qualifier))
}

fn classify_symbol_kind(
    name: &str,
    enclosing_type: Option<&str>,
    has_isr_attr: bool,
    arch_layer: ArchLayer,
    full_text: &str,
) -> SymbolKind {
    // 1. Entrypoints (`main`, `Reset_Handler`, `app_main`, `setup`, `loop`, etc.)
    if matches!(
        name,
        "main" | "Reset_Handler" | "app_main" | "setup" | "loop" | "_start" | "SystemInit"
    ) {
        return SymbolKind::Entrypoint;
    }

    // 2. ISR handlers
    if has_isr_attr
        || name.ends_with("_IRQHandler")
        || name.ends_with("_Handler")
        || name.starts_with("ISR(")
        || name.starts_with("SIGNAL(")
        || name.starts_with("__vector_")
        || full_text.contains("__irq")
        || full_text.contains("interrupt") && full_text.contains("#[")
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

    // 5. Top-level CLI/API entrypoints
    if matches!(arch_layer, ArchLayer::Cli | ArchLayer::Api)
        && (name.starts_with("cmd_")
            || name.starts_with("handle_")
            || full_text.contains("@app.")
            || full_text.contains("@router."))
    {
        return SymbolKind::Entrypoint;
    }

    SymbolKind::Function
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
    let end = node
        .child_by_field_name("body")
        .map(|b| b.start_byte())
        .unwrap_or_else(|| node.end_byte());

    let slice = if end > start && end <= bytes.len() {
        std::str::from_utf8(&bytes[start..end]).unwrap_or("")
    } else {
        node_text(node, bytes)
    };

    // Cut at `{` if body start was not a named field (e.g. arrow function or prototype)
    let before_brace = slice.split('{').next().unwrap_or(slice);
    let normalized = normalize_whitespace(before_brace);
    let trimmed = normalized
        .trim_end_matches('{')
        .trim_end_matches(';')
        .trim_end_matches(':')
        .trim();

    truncate_str(trimmed, 160)
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
            if !cleaned.is_empty() {
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
            if !cleaned.is_empty() {
                doc_lines.push(cleaned);
            }
        } else if trimmed.ends_with("*/") {
            let cleaned = clean_doc_line(trimmed);
            if !cleaned.is_empty() {
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
        .find(|l| !l.is_empty() && !l.starts_with('@') && !l.starts_with("\\brief"))
        .unwrap_or_default();

    truncate_str(&first_meaningful, 160)
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
            if t.contains("#[interrupt")
                || t.contains("#[exception")
                || t.contains("__interrupt")
                || t.contains("interrupt") && t.contains("__attribute__")
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
}
