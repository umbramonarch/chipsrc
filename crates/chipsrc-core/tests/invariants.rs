//! Round 2 Structural Invariant & Defect Regression Suite (`Bugs #1..#20`).
//!
//! Validates all global bundle invariants (`INV-1`..`INV-7`) across synthetic C/CMSIS firmware
//! (`fw_cmsis_like`), Rust workspace (`rs_workspace`), and Web SFC monorepo (`web_monorepo`)
//! fixtures as well as the live `chipsrc` repository.

use chipsrc_core::mmio::{classify_macro_value_with_blueprint, normalize_hex_literal};
use chipsrc_core::query::{
    parallel_bundle_search, parse_symbol_id, query_call_path, query_callees, query_callers,
    query_impact, query_macros, query_sections, query_subcommand_json, query_symbols,
    query_targets_file, query_types, query_xref, workspace_status,
};
use chipsrc_core::scanner::{
    count_source_lines, has_bundle_cache, load_cache_manifest, load_cache_shard_unit, stamp_check,
};
use chipsrc_core::{
    convert_repo, inspect_repo, ArchLayer, ConversionBundle, ConvertConfig, FileScope, MacroKind,
    ResolutionTier, SymbolKind, VendorMode, CACHE_PACK_UNITS,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

struct TestTempDir(PathBuf);

impl TestTempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "chipsrc_invariants_{label}_{}_{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Asserts global structural invariants `INV-1` through `INV-5` on any `ConversionBundle`.
fn assert_global_bundle_invariants(bundle: &ConversionBundle) {
    let dir = &bundle.output_dir;
    assert!(
        bundle.sanity.score >= 90,
        "Sanity score must be >= 90, got {} (warnings: {:?})",
        bundle.sanity.score,
        bundle.sanity.warnings
    );

    // INV-1: Every symbol, type, and macro's `section_id` must name a shard whose `files` list contains its `file`.
    let shard_files: BTreeMap<&str, BTreeSet<&str>> = bundle
        .sections
        .iter()
        .map(|s| {
            let files: BTreeSet<&str> = s.files.iter().map(|f| f.as_str()).collect();
            (s.summary.section_id.as_str(), files)
        })
        .collect();

    for rs in &bundle.indexes.symbols {
        let files = shard_files
            .get(rs.symbol.section_id.as_str())
            .unwrap_or_else(|| {
                panic!(
                    "Symbol {} has unknown section_id {}",
                    rs.symbol.symbol_id, rs.symbol.section_id
                )
            });
        assert!(
            files.contains(rs.symbol.file.as_str()),
            "Orphan symbol {} infile {} assigned to shard {} (shard files: {:?})",
            rs.symbol.symbol_id,
            rs.symbol.file,
            rs.symbol.section_id,
            files
        );
    }
    for t in &bundle.indexes.types {
        let files = shard_files.get(t.section_id.as_str()).unwrap_or_else(|| {
            panic!("Type {} has unknown section_id {}", t.type_id, t.section_id)
        });
        assert!(
            files.contains(t.file.as_str()),
            "Orphan type {} in file {} assigned to shard {}",
            t.type_id,
            t.file,
            t.section_id
        );
    }
    for m in &bundle.indexes.macros {
        let files = shard_files
            .get(m.section_id.as_str())
            .unwrap_or_else(|| panic!("Macro {} has unknown section_id {}", m.name, m.section_id));
        assert!(
            files.contains(m.file.as_str()),
            "Orphan macro {} in file {} assigned to shard {}",
            m.name,
            m.file,
            m.section_id
        );
    }

    // INV-2: Sum of per-shard counts == index/*.tsv row counts == meta.json counts
    let sum_syms: usize = bundle.indexes.sections.iter().map(|s| s.symbol_count).sum();
    let sum_types: usize = bundle.indexes.sections.iter().map(|s| s.type_count).sum();
    let sum_macros: usize = bundle.indexes.sections.iter().map(|s| s.macro_count).sum();

    assert_eq!(sum_syms, bundle.indexes.symbols.len());
    assert_eq!(sum_types, bundle.indexes.types.len());
    assert_eq!(sum_macros, bundle.indexes.macros.len());
    assert_eq!(bundle.metadata.symbol_count, bundle.indexes.symbols.len());
    assert_eq!(bundle.metadata.type_count, bundle.indexes.types.len());
    assert_eq!(bundle.metadata.macro_count, bundle.indexes.macros.len());
    assert_eq!(bundle.metadata.call_edge_count, bundle.indexes.calls.len());
    assert_eq!(bundle.metadata.xref_count, bundle.indexes.xrefs.len());

    let count_tsv_rows = |name: &str| -> usize {
        fs::read_to_string(dir.join("index").join(name))
            .expect("read tsv")
            .lines()
            .skip(1)
            .filter(|l| !l.trim().is_empty())
            .count()
    };
    assert_eq!(count_tsv_rows("symbols.tsv"), bundle.metadata.symbol_count);
    assert_eq!(count_tsv_rows("types.tsv"), bundle.metadata.type_count);
    assert_eq!(count_tsv_rows("macros.tsv"), bundle.metadata.macro_count);
    assert_eq!(count_tsv_rows("calls.tsv"), bundle.metadata.call_edge_count);
    assert_eq!(count_tsv_rows("xref.tsv"), bundle.metadata.xref_count);
    assert_eq!(
        count_tsv_rows("sections.tsv"),
        bundle.metadata.section_count
    );

    // INV-3: No duplicate clean_slug across shards
    let mut slugs = BTreeSet::new();
    for sec in &bundle.indexes.sections {
        let clean = sec
            .section_id
            .split_once('-')
            .filter(|(p, _)| p.bytes().all(|b| b.is_ascii_digit()))
            .map(|(_, rest)| rest)
            .unwrap_or(sec.section_id.as_str());
        assert!(
            slugs.insert(clean.to_string()),
            "Duplicate shard clean_slug: {clean}"
        );
    }

    // INV-4: When symbol_count >= 40, no Top-15 God Node has out_degree <= 1
    if bundle.indexes.symbols.len() >= 40 {
        for gn in &bundle.indexes.god_nodes {
            assert!(
                gn.out_degree >= 2,
                "God node {} has out_degree={} (must be >= 2)",
                gn.symbol.symbol_id,
                gn.out_degree
            );
            assert_eq!(
                gn.symbol.scope,
                FileScope::FirstParty,
                "God node {} must be FirstParty",
                gn.symbol.symbol_id
            );
        }
    }
}

/// Builds the synthetic `fw_cmsis_like` repository covering Bugs #1, #2, #9, #10, #11, #12, #17.
fn create_fw_cmsis_fixture(root: &Path) {
    fs::create_dir_all(root.join("src/app")).unwrap();
    fs::create_dir_all(root.join("test/lp")).unwrap();
    fs::create_dir_all(root.join("test/lp_adv")).unwrap();
    fs::create_dir_all(root.join("test/lp_hc")).unwrap();
    fs::create_dir_all(root.join("vendor/device/inc")).unwrap();
    fs::create_dir_all(root.join("vendor/device/src")).unwrap();
    fs::create_dir_all(root.join("sub/references/example_board")).unwrap();
    fs::create_dir_all(root.join("vendor/docs/html/search")).unwrap();

    // First-party `src/app/main.h` (same basename as `vendor/device/inc/main.h`)
    fs::write(
        root.join("src/app/main.h"),
        "#ifndef APP_MAIN_H\n#define APP_MAIN_H\nvoid led_cfg_apply(int mode);\n#endif\n",
    )
    .unwrap();

    // Vendor `vendor/device/inc/main.h` (must NOT be activated when `src/app/main.c` includes `"main.h"`)
    fs::write(
        root.join("vendor/device/inc/main.h"),
        "#ifndef VENDOR_MAIN_H\n#define VENDOR_MAIN_H\nvoid unused_vendor_board_hook(void);\n#endif\n",
    )
    .unwrap();

    // CMSIS-like header with `extern "C" {`, `__IO` / `__I` / `__IOM` fields, `deadbeefh`, `SET_BIT`, `.intvecs`
    let periph_regs_h = r#"#ifndef PERIPH_REGS_H
#define PERIPH_REGS_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define __I   volatile const
#define __O   volatile
#define __IO  volatile
#define __IOM volatile

#define FLAG_MAGIC deadbeefh
#define SET_BIT(REG, BIT)     ((REG) |= (BIT))
#define CLEAR_BIT(REG, BIT)   ((REG) &= ~(BIT))
#define READ_BIT(REG, BIT)    ((REG) & (BIT))

typedef struct {
    __IO uint32_t MODER;
    __I  uint32_t IDR;
    __IOM uint32_t ODR;
} GPIO_TypeDef;

#define GPIOA_BASE 0x40020000UL
#define GPIOA      ((GPIO_TypeDef *)GPIOA_BASE)

__attribute__((section(".intvecs")))
extern const uint32_t g_pfnVectors[64];

void HAL_GPIO_Toggle(GPIO_TypeDef *port, uint32_t pin);

#ifdef __cplusplus
}
#endif
#endif
"#;
    fs::write(root.join("vendor/device/inc/periph_regs.h"), periph_regs_h).unwrap();

    // Vendor GPIO implementation with `USART1IRQHandler`, `Error_Handler`, and 22 vendor ISRs
    let mut vendor_gpio_c = String::from(
        "#include \"periph_regs.h\"\n\
         void HAL_GPIO_Toggle(GPIO_TypeDef *port, uint32_t pin) {\n\
             SET_BIT(port->ODR, pin);\n\
         }\n\
         void Error_Handler(void) { while (1) {} }\n\
         void USART1IRQHandler(void) { HAL_GPIO_Toggle(GPIOA, 1); }\n",
    );
    for i in 0..22 {
        vendor_gpio_c.push_str(&format!(
            "void TIM{i}_IRQHandler(void) {{ HAL_GPIO_Toggle(GPIOA, {i}); }}\n"
        ));
    }
    fs::write(root.join("vendor/device/src/periph_gpio.c"), vendor_gpio_c).unwrap();

    // First-party `src/app/led_cfg.c`
    fs::write(
        root.join("src/app/led_cfg.c"),
        "#include \"main.h\"\n#include \"periph_regs.h\"\n\
         void led_cfg_apply(int mode) {\n\
             GPIOA->MODER = (uint32_t)mode;\n\
             HAL_GPIO_Toggle(GPIOA, 1);\n\
         }\n",
    )
    .unwrap();

    // Large `src/app/main.c` (~1,500 lines / >36 KB) to force sub-sharding of `src/app`
    let mut app_main_c = String::from(
        "#include \"main.h\"\n#include \"periph_regs.h\"\n\
         void SysTick_Handler(void) { led_cfg_apply(1); }\n",
    );
    for i in 0..160 {
        let next_call = if i > 0 {
            format!("app_step_{}(input_val);", i - 1)
        } else {
            String::from("led_cfg_apply(0);")
        };
        app_main_c.push_str(&format!(
            "/** Step helper {i} for firmware state machine orchestration. */\n\
             int app_step_{i}(int input_val) {{\n\
                 int acc = input_val + {i};\n\
                 if (acc > 0) {{\n\
                     led_cfg_apply(acc);\n\
                     {next_call}\n\
                 }}\n\
                 return acc;\n\
             }}\n\n"
        ));
    }
    app_main_c.push_str(
        "int main(void) {\n\
             led_cfg_apply(0);\n\
             app_step_0(1);\n\
             app_step_1(2);\n\
             return 0;\n\
         }\n",
    );
    fs::write(root.join("src/app/main.c"), app_main_c).unwrap();

    // Three test files with colliding `main.c` stems under `test/`
    for (sub, fn_name) in [
        ("lp", "run_lp_suite"),
        ("lp_adv", "run_lp_adv_suite"),
        ("lp_hc", "run_lp_hc_suite"),
    ] {
        let mut test_c = format!("int {fn_name}(int x) {{ return x + 1; }}\n");
        for i in 0..60 {
            test_c.push_str(&format!(
                "int {fn_name}_case_{i}(int v) {{ return {fn_name}(v + {i}); }}\n"
            ));
        }
        fs::write(root.join("test").join(sub).join("main.c"), test_c).unwrap();
    }

    // Nested `sub/references/example_board/main.c` (vendor reference at depth 1)
    fs::write(
        root.join("sub/references/example_board/main.c"),
        "void ref_board_demo(void) {}\n",
    )
    .unwrap();

    // Generated Doxygen search asset `vendor/docs/html/search/all_3.js` (must be skipped)
    fs::write(
        root.join("vendor/docs/html/search/all_3.js"),
        "var searchData = [['foo', ['bar']]];\n",
    )
    .unwrap();
}

#[test]
fn test_fw_cmsis_fixture_invariants_and_defects() {
    let tmp = TestTempDir::new("fw_cmsis");
    let repo_dir = tmp.path().join("fw_cmsis_like");
    create_fw_cmsis_fixture(&repo_dir);

    for mode in [VendorMode::Active, VendorMode::All, VendorMode::None] {
        let out_dir = tmp.path().join(format!("out_{}", mode.as_str()));
        let mut cfg = ConvertConfig::new(repo_dir.clone(), out_dir.clone());
        cfg.vendor_mode = mode;
        let bundle = convert_repo(&cfg).expect("convert fw_cmsis_like");

        // Global invariants INV-1..INV-5 must hold for every vendor mode
        assert_global_bundle_invariants(&bundle);

        // Bug 10: Generated Doxygen `vendor/docs/html/search/all_3.js` must never be indexed
        assert!(!bundle
            .metadata
            .file_stamps
            .iter()
            .any(|s| s.rel_path.contains("all_3.js")));

        // Bug 10: `sub/references/example_board/main.c` has `references` at index 1 -> VendorSdk
        if mode != VendorMode::None {
            for s in &bundle.metadata.file_stamps {
                if s.rel_path.starts_with("sub/references/") {
                    assert_eq!(s.scope, FileScope::VendorSdk);
                }
            }
        }

        if mode == VendorMode::Active {
            // Bug 2: `GPIO_TypeDef` fields must be `MODER: uint32_t, IDR: uint32_t, ODR: uint32_t` (never `uint32_t: __IO`)
            let gpio_td = bundle
                .indexes
                .types
                .iter()
                .find(|t| t.name == "GPIO_TypeDef")
                .expect("GPIO_TypeDef retained in active mode");
            assert!(
                gpio_td.fields_summary.contains("MODER: uint32_t"),
                "Unexpected GPIO_TypeDef fields: {}",
                gpio_td.fields_summary
            );
            assert!(
                gpio_td.fields_summary.contains("IDR: uint32_t"),
                "Unexpected GPIO_TypeDef fields: {}",
                gpio_td.fields_summary
            );
            assert!(
                !gpio_td.fields_summary.contains("__IO"),
                "Qualifier macro leaked into fields_summary: {}",
                gpio_td.fields_summary
            );

            // Bug 11: `SET_BIT` and `CLEAR_BIT` must not appear in `active_mmio_registers`
            assert!(!bundle
                .indexes
                .vendor_surface
                .active_mmio_registers
                .iter()
                .any(|r| r == "SET_BIT" || r == "CLEAR_BIT" || r == "READ_BIT"));

            // Bug 11: `.intvecs` linker section must not appear in `active_vendor_symbols`
            assert!(!bundle
                .indexes
                .vendor_surface
                .active_vendor_symbols
                .iter()
                .any(|s| s.contains("intvecs")));

            // Bug 11: `#include "main.h"` in `src/app/main.c` must NOT activate `vendor/device/inc/main.h`
            assert!(!bundle
                .indexes
                .vendor_surface
                .active_vendor_headers
                .iter()
                .any(|h| h.ends_with("vendor/device/inc/main.h")));

            // Bug 9: `main` and `SysTick_Handler` must appear in `INDEX.md` Entrypoints table despite 22+ vendor ISRs
            let index_md = fs::read_to_string(out_dir.join("INDEX.md")).unwrap();
            assert!(
                index_md.contains("| `main` | `entrypoint` |"),
                "First-party `main` missing from INDEX.md Entrypoints table"
            );
            assert!(
                index_md.contains("| `SysTick_Handler` | `isr` |"),
                "First-party `SysTick_Handler` missing from INDEX.md Entrypoints table"
            );
        }

        if mode == VendorMode::All {
            // Bug 12: `Error_Handler` must be `Function`, while `USART1IRQHandler` must be `Isr`
            let err_h = bundle
                .indexes
                .symbols
                .iter()
                .find(|s| s.symbol.name == "Error_Handler")
                .expect("Error_Handler symbol");
            assert_eq!(err_h.symbol.kind, SymbolKind::Function);

            let usart_isr = bundle
                .indexes
                .symbols
                .iter()
                .find(|s| s.symbol.name == "USART1IRQHandler")
                .expect("USART1IRQHandler symbol");
            assert_eq!(usart_isr.symbol.kind, SymbolKind::Isr);

            // Bug 17: `#define FLAG_MAGIC deadbeefh` must have `hex_addr == Some("0xDEADBEEF")`
            let flag_magic = bundle
                .indexes
                .macros
                .iter()
                .find(|m| m.name == "FLAG_MAGIC")
                .expect("FLAG_MAGIC macro");
            assert_eq!(flag_magic.hex_addr.as_deref(), Some("0xDEADBEEF"));
        }
    }
}

/// Builds and tests the `rs_workspace` + `web_monorepo` + `smart_locker` fixtures (Bugs #3, #6, #7, #8, #13, #16, #18, #19, #20).
#[test]
fn test_rs_workspace_web_monorepo_and_incremental_cache_shards() {
    let tmp = TestTempDir::new("rs_and_web");

    // 1. Test `smart_locker` path isolation (Bug #3: `sym lock` must not match symbols purely by file path)
    let locker_dir = tmp.path().join("smart_locker");
    fs::create_dir_all(locker_dir.join("src")).unwrap();
    fs::write(
        locker_dir.join("src/door.c"),
        "int open_panel(int code) { return code + 1; }\n",
    )
    .unwrap();
    let locker_out = tmp.path().join("out_locker");
    let locker_cfg = ConvertConfig::new(locker_dir.clone(), locker_out.clone());
    let locker_bundle = convert_repo(&locker_cfg).unwrap();
    assert_global_bundle_invariants(&locker_bundle);

    let sym_lock =
        query_symbols(std::slice::from_ref(&locker_out), "lock", None, false, 10).unwrap();
    assert!(
        sym_lock.starts_with("No symbols matched 'lock'"),
        "sym 'lock' matched file path in smart_locker: {sym_lock}"
    );

    // 2. Test `rs_workspace` (Bugs #6, #7, #8, #12, #13)
    let rs_dir = tmp.path().join("rs_workspace");
    fs::create_dir_all(rs_dir.join("crates/core/src")).unwrap();
    fs::create_dir_all(rs_dir.join("crates/cli/src")).unwrap();

    fs::write(
        rs_dir.join("crates/core/src/model.rs"),
        r#"pub struct ScannedInfo {
    pub rel_path: String,
}
pub struct FileUnit {
    pub scanned: ScannedInfo,
}
"#,
    )
    .unwrap();

    fs::write(
        rs_dir.join("crates/core/src/lib.rs"),
        r#"pub mod model;
use crate::model::{FileUnit, ScannedInfo};

pub fn process_units(units: &[FileUnit]) -> Vec<String> {
    let mut out = Vec::with_capacity(units.len());
    for unit in units {
        if let Some(ch) = unit.scanned.rel_path.chars().next() {
            if ch.is_ascii() {
                out.push(unit.scanned.rel_path.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_unit(path: &str) -> FileUnit {
        FileUnit {
            scanned: ScannedInfo {
                rel_path: path.to_string(),
            },
        }
    }

    #[test]
    fn test_process() {
        let u = make_unit("src/lib.rs");
        let res = process_units(&[u]);
        assert_eq!(res.len(), 1);
    }
}
"#,
    )
    .unwrap();

    fs::write(
        rs_dir.join("crates/cli/src/main.rs"),
        r#"use core_crate::process_units;

fn handle_subcommand() -> usize {
    let items = process_units(&[]);
    items.len()
}

pub fn main() {
    let _ = handle_subcommand();
}
"#,
    )
    .unwrap();

    let rs_out = tmp.path().join("out_rs");
    let rs_cfg = ConvertConfig::new(rs_dir.clone(), rs_out.clone());
    let rs_bundle = convert_repo(&rs_cfg).unwrap();
    assert_global_bundle_invariants(&rs_bundle);

    // Bug 6: Inline `#[cfg(test)]` call `test_process -> make_unit` must resolve as `SameFile`
    let make_unit_edge = rs_bundle
        .indexes
        .calls
        .iter()
        .find(|c| c.callee_name == "make_unit")
        .expect("call to make_unit");
    assert_eq!(make_unit_edge.tier, ResolutionTier::SameFile);

    // Bug 8: No noisy `Some`, `with_capacity`, `chars`, `next`, `is_ascii`, `clone`, `len` in calls
    for noisy in ["Some", "with_capacity", "chars", "next", "clone", "len"] {
        assert!(
            !rs_bundle
                .indexes
                .calls
                .iter()
                .any(|c| c.callee_name == noisy),
            "Noisy Rust call {noisy} leaked into calls.tsv"
        );
    }

    // Bug 12: Private `handle_subcommand` in `ArchLayer::Cli` must be `SymbolKind::Function` (not `Entrypoint`)
    let handle_sym = rs_bundle
        .indexes
        .symbols
        .iter()
        .find(|s| s.symbol.name == "handle_subcommand")
        .expect("handle_subcommand");
    assert_eq!(handle_sym.symbol.kind, SymbolKind::Function);

    // Bug 13: `for unit in units { unit.scanned.rel_path }` must resolve `unit.scanned` to `FileUnit::scanned`
    let xref_out = query_xref(std::slice::from_ref(&rs_out), "unit.scanned", 20).unwrap();
    assert!(
        xref_out.contains("FileUnit::scanned"),
        "Expected loop variable receiver binding to FileUnit::scanned, got:\n{xref_out}"
    );

    // Bug 7: Verify per-file cache shards (`cache/manifest.json` schema `2.1.0`) and `stamp_check`
    assert!(has_bundle_cache(&rs_out));
    let manifest = load_cache_manifest(&rs_out).expect("load cache/manifest.json");
    assert_eq!(manifest.schema_version, "2.1.0");
    assert_eq!(manifest.files.len(), 3);
    for entry in manifest.files.values() {
        assert!(rs_out.join(&entry.shard).is_file());
        assert_eq!(entry.structural_digest.len(), 16);
    }

    let sc = stamp_check(&rs_dir, &rs_bundle.metadata, 4 * 1024 * 1024).expect("stamp_check");
    assert!(sc.unchanged);
    assert_eq!(sc.changed_count, 0);

    // Bug 7a: Comment-only edit preserving line count and coordinates triggers the real
    // Structural Digest No-Op Short-Circuit (`sections` empty because link/graph/shard were skipped)
    let model_path = rs_dir.join("crates/core/src/model.rs");
    let orig_model = fs::read_to_string(&model_path).unwrap();
    fs::write(
        &model_path,
        format!("{} // inline trailing comment\n", orig_model.trim_end()),
    )
    .unwrap();

    let rs_bundle_noop = convert_repo(&rs_cfg).unwrap();
    assert!(!rs_bundle_noop.cache_hit);
    assert!(
        rs_bundle_noop.sections.is_empty(),
        "Expected line-preserving comment edit to take the real short-circuit path"
    );
    assert_eq!(rs_bundle_noop.metadata.incremental_reparsed_files, 1);
    assert_eq!(rs_bundle_noop.metadata.incremental_reused_files, 2);
    assert_eq!(rs_bundle_noop.metadata.link_ms, 0);
    assert_eq!(rs_bundle_noop.metadata.graph_ms, 0);
    assert_eq!(rs_bundle_noop.metadata.shard_ms, 0);

    // Bug 7b: Appending comment lines at EOF changes line_count, so convert_repo runs the full
    // link/graph/shard/emit pipeline to keep line totals accurate and matches a --force rebuild
    fs::write(
        &model_path,
        format!("{orig_model}\n// trailing comment edit\n"),
    )
    .unwrap();

    let rs_bundle_eof = convert_repo(&rs_cfg).unwrap();
    assert!(!rs_bundle_eof.cache_hit);
    assert!(
        !rs_bundle_eof.sections.is_empty(),
        "Expected line-count-changing comment edit to run full shard/emit rebuild"
    );
    assert_eq!(rs_bundle_eof.metadata.incremental_reparsed_files, 1);
    assert_eq!(rs_bundle_eof.metadata.incremental_reused_files, 2);
    let eof_inc_hashes = collect_bundle_artifact_hashes(&rs_out);
    let mut rs_force_cfg = rs_cfg.clone();
    rs_force_cfg.force = true;
    let rs_bundle_eof_force = convert_repo(&rs_force_cfg).unwrap();
    assert_eq!(
        rs_bundle_eof.metadata.total_lines,
        rs_bundle_eof_force.metadata.total_lines
    );
    assert_eq!(eof_inc_hashes, collect_bundle_artifact_hashes(&rs_out));

    // 3. Test `web_monorepo` (Bug #19: Web / SFC layer classification)
    let web_dir = tmp.path().join("web_monorepo");
    fs::create_dir_all(web_dir.join("apps/web/src/components")).unwrap();
    fs::create_dir_all(web_dir.join("apps/web/src/pages")).unwrap();
    fs::create_dir_all(web_dir.join("apps/web/src/app")).unwrap();
    fs::create_dir_all(web_dir.join("packages/api/src")).unwrap();

    fs::write(
        web_dir.join("apps/web/src/components/Button.vue"),
        "<script setup lang=\"ts\">\nexport function renderButton(label: string): string { return label; }\n</script>\n<template><button></button></template>\n",
    )
    .unwrap();
    fs::write(
        web_dir.join("apps/web/src/pages/index.astro"),
        "---\nimport { renderButton } from '../components/Button.vue';\nexport function loadPage(): string { return renderButton('go'); }\n---\n<html></html>\n",
    )
    .unwrap();
    fs::write(
        web_dir.join("apps/web/src/app/store.ts"),
        "export function initStore(): number { return 1; }\n",
    )
    .unwrap();
    fs::write(
        web_dir.join("packages/api/src/routes.ts"),
        "export function handleGetUsers(): string { return 'ok'; }\n",
    )
    .unwrap();

    let web_out = tmp.path().join("out_web");
    let web_bundle = convert_repo(&ConvertConfig::new(web_dir.clone(), web_out.clone())).unwrap();
    assert_global_bundle_invariants(&web_bundle);

    for stamp in &web_bundle.metadata.file_stamps {
        if stamp.rel_path.starts_with("apps/web/") {
            assert_eq!(
                stamp.arch_layer,
                ArchLayer::App,
                "Expected ArchLayer::App for {}, got {:?}",
                stamp.rel_path,
                stamp.arch_layer
            );
        } else if stamp.rel_path.starts_with("packages/api/") {
            assert_eq!(stamp.arch_layer, ArchLayer::Api);
        }
    }

    // Bug 16: `workspace_status` on a nonexistent path must return `Err`
    assert!(workspace_status(&tmp.path().join("does_not_exist_at_all")).is_err());

    // Bug 18: Invalid `.chipsrc.json` must populate `InspectReport.blueprint_error` and glob suffixes in `.chipsrc.json` must work
    fs::write(web_dir.join(".chipsrc.json"), "{ invalid json ").unwrap();
    let bad_inspect = inspect_repo(&web_dir, VendorMode::Active).unwrap();
    assert!(bad_inspect.blueprint_error.is_some());

    fs::write(
        web_dir.join(".chipsrc.json"),
        r#"{"layers": {"apps/web/src/app/**": "services"}}"#,
    )
    .unwrap();
    let good_inspect = inspect_repo(&web_dir, VendorMode::Active).unwrap();
    assert!(good_inspect.blueprint_error.is_none());
    assert!(good_inspect
        .detected_layers
        .contains(&"services".to_string()));

    // Bug 16 & Bug 20: Verify `--json` query outputs parse as valid JSON and `section --show` has no double `---`
    let sec_show = query_sections(std::slice::from_ref(&rs_out), "", true, 5).unwrap();
    assert!(
        !sec_show.contains("---\n---\n"),
        "Double `---` separator found in section --show output"
    );

    for sub in [
        "sym", "callers", "callees", "type", "macro", "section", "xref", "path", "impact",
    ] {
        let json_str = query_subcommand_json(
            sub,
            std::slice::from_ref(&rs_out),
            "process_units",
            Some("make_unit"),
            None,
            5,
            10,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .unwrap_or_else(|e| panic!("Invalid JSON for {sub}: {e}"));
        assert!(parsed.is_array() || parsed.is_object());
    }
}

/// Validates unit-level invariants for `SymbolIdView`, `normalize_hex_literal`, and `classify_macro_value`.
#[test]
fn test_unit_helpers_symbol_id_view_and_hex_stoplist() {
    let v = parse_symbol_id("crates/chipsrc-core/src/parser.rs::ExtractContext::new:412");
    assert_eq!(v.file, "crates/chipsrc-core/src/parser.rs");
    assert_eq!(v.scoped, "ExtractContext::new");
    assert_eq!(v.short, "new");
    assert!(!query_targets_file("parser"));
    assert!(!query_targets_file("lock"));
    assert!(query_targets_file("src/parser.rs"));
    assert!(query_targets_file("parser.rs"));

    // Bug 17: 2..=8 hex digits + `h` without decimal digits
    assert_eq!(
        normalize_hex_literal("deadbeefh"),
        Some("0xDEADBEEF".to_string())
    );
    assert_eq!(normalize_hex_literal("FFh"), Some("0xFF".to_string()));
    assert_eq!(normalize_hex_literal("bah"), None);
    assert_eq!(normalize_hex_literal("feedh"), None);
    assert_eq!(normalize_hex_literal("deadh"), None);

    // Bug 11: `SET_BIT` and `CLEAR_BIT` must be `FunctionMacro`, not `Bitmask`
    let (kind_set, _, _) =
        classify_macro_value_with_blueprint("SET_BIT", "((REG) |= (BIT))", true, None);
    assert_eq!(kind_set, MacroKind::FunctionMacro);
    let (kind_clr, _, _) =
        classify_macro_value_with_blueprint("CLEAR_BIT", "((REG) &= ~(BIT))", true, None);
    assert_eq!(kind_clr, MacroKind::FunctionMacro);
}

/// Copies the shippable source tree for the dogfood conversion, skipping VCS metadata, build
/// output, caches, and the Python black-box harness under `qa/`.
fn copy_dogfood_product_sources(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if is_skipped_dogfood_dir(&entry.file_name()) {
                continue;
            }
            copy_dir_recursive(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn is_skipped_dogfood_dir(name: &std::ffi::OsStr) -> bool {
    const SKIPPED: &[&str] = &[
        ".git",
        "target",
        "output",
        "out",
        "qa",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    ];
    let name = name.to_string_lossy();
    SKIPPED.iter().any(|skip| name.eq_ignore_ascii_case(skip))
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if is_skipped_dogfood_dir(&entry.file_name()) {
                continue;
            }
            copy_dir_recursive(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

/// Validates the live dogfood repository (`D:\projects\chipsrc`) against all Round 2 acceptance criteria.
#[test]
fn test_dogfood_chipsrc_bundle_acceptance() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");

    let tmp = TestTempDir::new("dogfood");
    // The black-box QA harness under `qa/` is Python test infrastructure, not shippable code.
    // Its growth changes PageRank/HITS normalization slightly, which is enough to reorder the
    // tail of the per-file-diversified God Node ranking. Convert a copy of the product source
    // tree (no VCS, build output, or `qa/`) so the architectural-hub assertions stay meaningful.
    let source_root = tmp.path().join("source");
    copy_dogfood_product_sources(repo_root, &source_root).expect("copy dogfood product sources");
    let out_dir = tmp.path().join("chipsrc");
    let cfg = ConvertConfig::new(source_root, out_dir.clone());
    let bundle = convert_repo(&cfg).expect("convert dogfood repo");

    assert_global_bundle_invariants(&bundle);
    assert_eq!(bundle.sanity.score, 100);

    // Bug 4: All 7 core pipeline functions must appear in the Top-15 God Nodes
    let god_names: BTreeSet<&str> = bundle
        .indexes
        .god_nodes
        .iter()
        .map(|g| g.symbol.name.as_str())
        .collect();
    for expected in [
        "convert_repo",
        "resolve_and_link",
        "analyze_graph",
        "build_section_shards",
        "emit_bundle",
        "parse_source_str_with_blueprint",
        "scan_repository",
    ] {
        assert!(
            god_names.contains(expected),
            "Expected core orchestrator `{expected}` in Top-15 God Nodes, got: {:?}",
            god_names
        );
    }

    // Bug 5: Core Domain Types table in INDEX.md must include ConvertConfig, ChipsrcError, ConversionBundle, ParsedFileUnit, ExtractedSymbol
    let index_md = fs::read_to_string(out_dir.join("INDEX.md")).unwrap();
    for expected_type in [
        "`ConvertConfig`",
        "`ChipsrcError`",
        "`ConversionBundle`",
        "`ParsedFileUnit`",
        "`ExtractedSymbol`",
    ] {
        assert!(
            index_md.contains(expected_type),
            "Expected {expected_type} in Core Domain Types table of INDEX.md"
        );
    }
    assert!(
        !index_md.contains("| `ExtractContext` |"),
        "Private helper ExtractContext must not appear in Core Domain Types table"
    );
    assert!(
        !index_md.contains("| `Result` |"),
        "TypeAlias Result must not appear in Core Domain Types table"
    );

    // Bug 8: `external_or_macro` share on `chipsrc` core/plugin code must be < 15%.
    let core_calls: Vec<_> = bundle
        .indexes
        .calls
        .iter()
        .filter(|c| !c.file.starts_with("qa/"))
        .collect();
    let ext_calls = core_calls
        .iter()
        .filter(|c| c.tier == ResolutionTier::ExternalOrMacro)
        .count();
    let ext_ratio = ext_calls as f64 / core_calls.len().max(1) as f64;
    assert!(
        ext_ratio < 0.15,
        "Expected external_or_macro ratio < 15%, got {:.1}% ({}/{})",
        ext_ratio * 100.0,
        ext_calls,
        core_calls.len()
    );

    // Pass bundle slices directly: `std::slice::from_ref` is not a stdlib call the resolver
    // recognizes as noise, and module-qualified calls inflate the ratio above.
    let bundles = [out_dir.clone()];

    // Bug 3: `impact parser` must not match all 100+ symbols in `parser.rs`
    let impact_parser = query_impact(&bundles, "parser", 3, 50).unwrap();
    assert!(!impact_parser.contains("106 transitive callers"));

    // Verify `callers` and `callees` headers show resolved vs external/macro counts
    let callers_out = query_callers(&bundles, "resolve_and_link", false, 10).unwrap();
    assert!(callers_out.contains("resolved,"));
    let callees_out = query_callees(&bundles, "convert_repo", false, 10).unwrap();
    assert!(callees_out.contains("resolved,"));
    assert!(!callees_out.contains("external::Ok"));

    // Verify `path` intermediate hop coordinates
    let path_out = query_call_path(&bundles, "convert_repo", "resolve_and_link", 5).unwrap();
    assert!(path_out.contains("resolve_and_link"));

    // Verify `search` deduplication and `types` query
    let hits = parallel_bundle_search(&bundles, "ConvertConfig", "all", false, 20).unwrap();
    assert!(!hits.is_empty());
    let types_out = query_types(&bundles, "ConvertConfig", false, 5).unwrap();
    assert!(types_out.contains("ConvertConfig"));
    let macros_out = query_macros(&bundles, "DEFAULT_MAX_FILE_BYTES", false, 5).unwrap();
    assert!(macros_out.contains("DEFAULT_MAX_FILE_BYTES"));
}

fn collect_bundle_artifact_hashes(bundle_dir: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for sub in ["index", "sections"] {
        let dir = bundle_dir.join(sub);
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let rel = format!(
                        "{sub}/{}",
                        p.file_name().and_then(|n| n.to_str()).unwrap_or_default()
                    );
                    let bytes = fs::read(&p).expect("read artifact");
                    map.insert(rel, blake3::hash(&bytes).to_hex().to_string());
                }
            }
        }
    }
    map
}

#[test]
fn test_unified_count_source_lines_incremental_matches_force_end_to_end() {
    let tmp = TestTempDir::new("unified_lines");

    // 1. Trailing-newline, no-trailing-newline, and empty-file line-count conventions
    let conv_src = tmp.path().join("conv_src");
    let conv_out = tmp.path().join("conv_bundle");
    fs::create_dir_all(&conv_src).unwrap();
    fs::write(conv_src.join("empty.py"), b"").unwrap();
    fs::write(conv_src.join("tnl.py"), b"a = 1\na = 2\na = 3\n").unwrap();
    fs::write(conv_src.join("nonl.py"), b"b = 1\nb = 2\nb = 3").unwrap();

    let conv_bundle = convert_repo(&ConvertConfig::new(conv_src.clone(), conv_out)).unwrap();
    assert_eq!(conv_bundle.metadata.total_lines, 6);
    assert_eq!(
        inspect_repo(&conv_src, VendorMode::Active)
            .unwrap()
            .total_lines,
        6
    );
    assert_eq!(
        count_source_lines(&fs::read(conv_src.join("empty.py")).unwrap()),
        0
    );
    assert_eq!(conv_bundle.metadata.file_stamps.len(), 2);
    assert!(
        !conv_bundle
            .metadata
            .file_stamps
            .iter()
            .any(|s| s.rel_path == "empty.py"),
        "zero-byte files are skipped by the scanner and must never appear in file_stamps"
    );
    for stamp in &conv_bundle.metadata.file_stamps {
        match stamp.rel_path.as_str() {
            "tnl.py" | "nonl.py" => assert_eq!(stamp.line_count, 3, "for {}", stamp.rel_path),
            other => panic!("unexpected stamp {other}"),
        }
    }

    // 2. Multi-file edits (comment insertion, replacement, addition, deletion):
    // incremental convert vs --force convert must produce byte-identical index/* and sections/*
    // and identical total_lines / file_stamps[].line_count / inspect total_lines.
    let mx_src = tmp.path().join("mx");
    let mx_out = tmp.path().join("mx_bundle");
    fs::create_dir_all(mx_src.join("src")).unwrap();

    let ident_path = mx_src.join("src/identifiers.py");
    let helper_path = mx_src.join("src/helper.py");
    fs::write(
        &ident_path,
        "def pm_match_key(value: str) -> str:\n    return value.strip().lower()\n",
    )
    .unwrap();
    fs::write(
        &helper_path,
        "def compute_checksum(data: str) -> int:\n    return len(data)\n",
    )
    .unwrap();

    let cfg = ConvertConfig::new(mx_src.clone(), mx_out.clone());
    let b0 = convert_repo(&cfg).unwrap();
    assert_eq!(b0.metadata.total_lines, 4);

    let assert_incremental_matches_force = |expected_lines: usize, stage: &str| {
        let mut inc_cfg = cfg.clone();
        inc_cfg.force = false;
        let inc_bundle = convert_repo(&inc_cfg).unwrap();
        assert!(
            !inc_bundle.cache_hit,
            "stage {stage}: expected incremental sync, got cache hit"
        );
        let inc_hashes = collect_bundle_artifact_hashes(&mx_out);
        let inc_stamps: Vec<(String, usize)> = inc_bundle
            .metadata
            .file_stamps
            .iter()
            .map(|s| (s.rel_path.clone(), s.line_count))
            .collect();
        let inspect_lines = inspect_repo(&mx_src, VendorMode::Active)
            .unwrap()
            .total_lines;

        let mut force_cfg = cfg.clone();
        force_cfg.force = true;
        let force_bundle = convert_repo(&force_cfg).unwrap();
        let force_hashes = collect_bundle_artifact_hashes(&mx_out);
        let force_stamps: Vec<(String, usize)> = force_bundle
            .metadata
            .file_stamps
            .iter()
            .map(|s| (s.rel_path.clone(), s.line_count))
            .collect();

        assert_eq!(
            inc_bundle.metadata.total_lines, expected_lines,
            "stage {stage}: incremental total_lines"
        );
        assert_eq!(
            force_bundle.metadata.total_lines, expected_lines,
            "stage {stage}: force total_lines"
        );
        assert_eq!(
            inspect_lines, expected_lines,
            "stage {stage}: inspect total_lines"
        );
        assert_eq!(
            inc_stamps, force_stamps,
            "stage {stage}: file_stamps line_count mismatch"
        );
        assert_eq!(
            inc_hashes, force_hashes,
            "stage {stage}: index/ or sections/ bytes differed between incremental and --force"
        );
    };

    // Stage A: Prepend 1 comment line to identifiers.py and append 3 comment lines to helper.py
    let ident_v1 = fs::read_to_string(&ident_path).unwrap();
    fs::write(&ident_path, format!("# QA top comment\n{ident_v1}")).unwrap();
    let helper_v1 = fs::read_to_string(&helper_path).unwrap();
    fs::write(&helper_path, format!("{helper_v1}# c1\n# c2\n# c3\n")).unwrap();
    assert_incremental_matches_force(8, "prepend-1-append-3");

    // Stage B: Add extra.py with 7 newline-terminated lines
    let extra_path = mx_src.join("src/extra.py");
    fs::write(
        &extra_path,
        "# l1\n# l2\n# l3\ndef extra_fn(x: int) -> int:\n    return x + 1\n# l6\n# l7\n",
    )
    .unwrap();
    assert_incremental_matches_force(15, "add-7-lines");

    // Stage C: Delete extra.py
    fs::remove_file(&extra_path).unwrap();
    assert_incremental_matches_force(8, "delete-7-lines");

    // Stage D: Replace one line without changing line count, then append 2 lines;
    // verify incremental meta.total_lines agrees with inspect_repo in both states.
    let ident_v2 = fs::read_to_string(&ident_path).unwrap();
    fs::write(
        &ident_path,
        ident_v2.replace("# QA top comment\n", "# QA replaced comment\n"),
    )
    .unwrap();
    let b_replace = convert_repo(&cfg).unwrap();
    assert_eq!(b_replace.metadata.total_lines, 8);
    assert_eq!(
        inspect_repo(&mx_src, VendorMode::Active)
            .unwrap()
            .total_lines,
        b_replace.metadata.total_lines
    );

    let ident_v3 = fs::read_to_string(&ident_path).unwrap();
    fs::write(&ident_path, format!("{ident_v3}# tail 1\n# tail 2\n")).unwrap();
    let b_append = convert_repo(&cfg).unwrap();
    assert_eq!(b_append.metadata.total_lines, 10);
    assert_eq!(
        inspect_repo(&mx_src, VendorMode::Active)
            .unwrap()
            .total_lines,
        b_append.metadata.total_lines
    );
}

#[test]
fn test_duplicate_content_shards_do_not_alias_across_paths() {
    let tmp = TestTempDir::new("dup_content");
    let dup_src = tmp.path().join("dup");
    let dup_out = tmp.path().join("dup_b1");
    fs::create_dir_all(dup_src.join("alpha")).unwrap();
    fs::create_dir_all(dup_src.join("beta")).unwrap();

    let identical_py = "\
class DuplicateShape:
    value: int

def duplicate_probe(value: int) -> int:
    return value + 1
";
    let alpha_path = dup_src.join("alpha/mod.py");
    let beta_path = dup_src.join("beta/mod.py");
    fs::write(&alpha_path, identical_py).unwrap();
    fs::write(&beta_path, identical_py).unwrap();

    let cfg = ConvertConfig::new(dup_src.clone(), dup_out.clone());
    let b_cold = convert_repo(&cfg).unwrap();
    assert_global_bundle_invariants(&b_cold);

    // VAL-DUP-001: Both identical files indexed with distinct per-path cache shards
    let manifest = load_cache_manifest(&dup_out).expect("cache/manifest.json");
    let alpha_entry = manifest.files.get("alpha/mod.py").expect("alpha entry");
    let beta_entry = manifest.files.get("beta/mod.py").expect("beta entry");
    assert_eq!(alpha_entry.blake3_hash, beta_entry.blake3_hash);
    assert_ne!(
        alpha_entry.shard, beta_entry.shard,
        "Byte-identical files at different paths must have distinct shard paths"
    );
    assert!(dup_out.join(&alpha_entry.shard).is_file());
    assert!(dup_out.join(&beta_entry.shard).is_file());

    let syms_tsv = fs::read_to_string(dup_out.join("index/symbols.tsv")).unwrap();
    assert!(syms_tsv.contains("alpha/mod.py::duplicate_probe\tduplicate_probe\t"));
    assert!(syms_tsv.contains("beta/mod.py::duplicate_probe\tduplicate_probe\t"));

    let types_tsv = fs::read_to_string(dup_out.join("index/types.tsv")).unwrap();
    assert!(types_tsv.contains("alpha/mod.py::DuplicateShape\tDuplicateShape\t"));
    assert!(types_tsv.contains("beta/mod.py::DuplicateShape\tDuplicateShape\t"));

    let secs_tsv = fs::read_to_string(dup_out.join("index/sections.tsv")).unwrap();
    assert!(secs_tsv.contains("\talpha\t"));
    assert!(secs_tsv.contains("\tbeta\t"));

    // VAL-DUP-002: Editing only alpha/mod.py on incremental refresh preserves beta/mod.py
    let alpha_edited = identical_py.replace("duplicate_probe", "alpha_only_probe");
    fs::write(&alpha_path, &alpha_edited).unwrap();
    let b_edit = convert_repo(&cfg).unwrap();
    assert!(!b_edit.cache_hit);
    assert_eq!(b_edit.metadata.incremental_reparsed_files, 1);
    assert_eq!(b_edit.metadata.incremental_reused_files, 1);
    assert_global_bundle_invariants(&b_edit);

    let dup_sym_json: serde_json::Value = serde_json::from_str(
        &query_subcommand_json(
            "sym",
            std::slice::from_ref(&dup_out),
            "duplicate_probe",
            None,
            None,
            3,
            10,
        )
        .unwrap(),
    )
    .unwrap();
    let dup_rows = dup_sym_json.as_array().unwrap();
    assert_eq!(dup_rows.len(), 1, "got: {dup_rows:?}");
    assert_eq!(dup_rows[0]["file"].as_str(), Some("beta/mod.py"));

    let alpha_sym_json: serde_json::Value = serde_json::from_str(
        &query_subcommand_json(
            "sym",
            std::slice::from_ref(&dup_out),
            "alpha_only_probe",
            None,
            None,
            3,
            10,
        )
        .unwrap(),
    )
    .unwrap();
    let alpha_rows = alpha_sym_json.as_array().unwrap();
    assert_eq!(alpha_rows.len(), 1, "got: {alpha_rows:?}");
    assert_eq!(alpha_rows[0]["file"].as_str(), Some("alpha/mod.py"));

    let section_bodies: Vec<String> = fs::read_dir(dup_out.join("sections"))
        .unwrap()
        .flatten()
        .map(|e| fs::read_to_string(e.path()).unwrap())
        .collect();
    assert!(section_bodies
        .iter()
        .any(|b| b.contains("beta/mod.py") && b.contains("def duplicate_probe(")));
    assert!(section_bodies
        .iter()
        .any(|b| b.contains("alpha/mod.py") && b.contains("def alpha_only_probe(")));

    // VAL-DUP-003: Incremental refresh matches --force counts and index/* + sections/* hashes
    let inc_hashes = collect_bundle_artifact_hashes(&dup_out);
    let inc_counts = (
        b_edit.metadata.symbol_count,
        b_edit.metadata.type_count,
        b_edit.metadata.section_count,
        b_edit.metadata.total_lines,
    );
    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let b_force = convert_repo(&force_cfg).unwrap();
    let force_hashes = collect_bundle_artifact_hashes(&dup_out);
    let force_counts = (
        b_force.metadata.symbol_count,
        b_force.metadata.type_count,
        b_force.metadata.section_count,
        b_force.metadata.total_lines,
    );
    assert_eq!(inc_counts, force_counts);
    assert_eq!(inc_hashes, force_hashes);

    // VAL-DUP-004: Add gamma/mod.py and delta/mod.py identical to beta/mod.py incrementally
    fs::create_dir_all(dup_src.join("gamma")).unwrap();
    fs::create_dir_all(dup_src.join("delta")).unwrap();
    let gamma_path = dup_src.join("gamma/mod.py");
    let delta_path = dup_src.join("delta/mod.py");
    fs::write(&gamma_path, identical_py).unwrap();
    fs::write(&delta_path, identical_py).unwrap();

    let b_add = convert_repo(&cfg).unwrap();
    assert!(!b_add.cache_hit);
    assert_global_bundle_invariants(&b_add);
    let manifest_add = load_cache_manifest(&dup_out).expect("manifest after add");
    assert_eq!(manifest_add.files.len(), 4);
    let unique_shards: BTreeSet<&str> = manifest_add
        .files
        .values()
        .map(|e| e.shard.as_str())
        .collect();
    assert_eq!(unique_shards.len(), 4);
    for entry in manifest_add.files.values() {
        assert!(dup_out.join(&entry.shard).is_file());
    }

    let dup_after_add: serde_json::Value = serde_json::from_str(
        &query_subcommand_json(
            "sym",
            std::slice::from_ref(&dup_out),
            "duplicate_probe",
            None,
            None,
            3,
            10,
        )
        .unwrap(),
    )
    .unwrap();
    let files_after_add: BTreeSet<&str> = dup_after_add
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["file"].as_str())
        .collect();
    assert_eq!(
        files_after_add,
        BTreeSet::from(["beta/mod.py", "gamma/mod.py", "delta/mod.py"])
    );

    let add_inc_hashes = collect_bundle_artifact_hashes(&dup_out);
    let add_inc_counts = (
        b_add.metadata.symbol_count,
        b_add.metadata.type_count,
        b_add.metadata.section_count,
        b_add.metadata.total_lines,
    );
    let b_add_force = convert_repo(&force_cfg).unwrap();
    assert_eq!(
        add_inc_counts,
        (
            b_add_force.metadata.symbol_count,
            b_add_force.metadata.type_count,
            b_add_force.metadata.section_count,
            b_add_force.metadata.total_lines,
        )
    );
    assert_eq!(add_inc_hashes, collect_bundle_artifact_hashes(&dup_out));

    // Delete gamma/mod.py incrementally
    fs::remove_file(&gamma_path).unwrap();
    let _ = fs::remove_dir(dup_src.join("gamma"));
    let b_del = convert_repo(&cfg).unwrap();
    assert!(!b_del.cache_hit);
    assert_global_bundle_invariants(&b_del);

    let dup_after_del: serde_json::Value = serde_json::from_str(
        &query_subcommand_json(
            "sym",
            std::slice::from_ref(&dup_out),
            "duplicate_probe",
            None,
            None,
            3,
            10,
        )
        .unwrap(),
    )
    .unwrap();
    let files_after_del: BTreeSet<&str> = dup_after_del
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["file"].as_str())
        .collect();
    assert_eq!(
        files_after_del,
        BTreeSet::from(["beta/mod.py", "delta/mod.py"])
    );
    let secs_after_del = fs::read_to_string(dup_out.join("index/sections.tsv")).unwrap();
    assert!(!secs_after_del.contains("\tgamma\t"));

    let del_inc_hashes = collect_bundle_artifact_hashes(&dup_out);
    let del_inc_counts = (
        b_del.metadata.symbol_count,
        b_del.metadata.type_count,
        b_del.metadata.section_count,
        b_del.metadata.total_lines,
    );
    let b_del_force = convert_repo(&force_cfg).unwrap();
    assert_eq!(
        del_inc_counts,
        (
            b_del_force.metadata.symbol_count,
            b_del_force.metadata.type_count,
            b_del_force.metadata.section_count,
            b_del_force.metadata.total_lines,
        )
    );
    assert_eq!(del_inc_hashes, collect_bundle_artifact_hashes(&dup_out));

    // Also verify comment-only edit on one of two identical copies matches --force
    fs::write(&alpha_path, identical_py).unwrap();
    let _ = convert_repo(&force_cfg).unwrap();
    fs::write(
        &beta_path,
        format!("{identical_py}# comment in beta only\n"),
    )
    .unwrap();
    let b_comment_inc = convert_repo(&cfg).unwrap();
    assert!(!b_comment_inc.cache_hit);
    let comment_inc_hashes = collect_bundle_artifact_hashes(&dup_out);
    let comment_inc_counts = (
        b_comment_inc.metadata.symbol_count,
        b_comment_inc.metadata.type_count,
        b_comment_inc.metadata.section_count,
        b_comment_inc.metadata.total_lines,
    );
    let b_comment_force = convert_repo(&force_cfg).unwrap();
    assert_eq!(
        comment_inc_counts,
        (
            b_comment_force.metadata.symbol_count,
            b_comment_force.metadata.type_count,
            b_comment_force.metadata.section_count,
            b_comment_force.metadata.total_lines,
        )
    );
    assert_eq!(comment_inc_hashes, collect_bundle_artifact_hashes(&dup_out));
}

/// BLAKE3 digest of every packed cache shard keyed by file name.
fn cache_pack_hashes(bundle_dir: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for entry in fs::read_dir(bundle_dir.join("cache"))
        .expect("read cache dir")
        .flatten()
    {
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        if !name.starts_with("pack-") {
            continue;
        }
        let bytes = fs::read(entry.path()).expect("read pack");
        map.insert(name, blake3::hash(&bytes).to_hex().to_string());
    }
    map
}

/// A same-line-count body edit on a small repository takes the digest-noop tier and rewrites only
/// the edited file's per-file shard, removing the superseded one.
#[test]
fn test_digest_noop_edit_rewrites_only_its_shard() {
    let tmp = TestTempDir::new("digest_noop_shard");
    let repo = tmp.path().join("small");
    let out = tmp.path().join("small_out");
    fs::create_dir_all(repo.join("mod")).unwrap();
    fs::write(
        repo.join("mod/a.py"),
        "def alpha(value: int) -> int:\n    return value + 1\n",
    )
    .unwrap();
    fs::write(
        repo.join("mod/b.py"),
        "def beta(value: int) -> int:\n    return value + 2\n",
    )
    .unwrap();
    fs::write(
        repo.join("mod/c.py"),
        "def gamma(value: int) -> int:\n    return value + 3\n",
    )
    .unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    assert_eq!(cold.metadata.total_files, 3);
    let manifest_before = load_cache_manifest(&out).expect("manifest");
    let edited_shard_before = manifest_before.files["mod/b.py"].shard.clone();
    let untracked_tables = collect_bundle_artifact_hashes(&out);

    fs::write(
        repo.join("mod/b.py"),
        "def beta(value: int) -> int:\n    return value + 20\n",
    )
    .unwrap();
    let edited = convert_repo(&cfg).unwrap();
    assert_eq!(edited.metadata.incremental_tier, "digest_noop");
    assert_eq!(edited.metadata.incremental_reparsed_files, 1);
    assert_eq!(edited.metadata.incremental_reused_files, 2);

    let manifest_after = load_cache_manifest(&out).expect("manifest after edit");
    let edited_shard_after = manifest_after.files["mod/b.py"].shard.clone();
    assert_ne!(edited_shard_before, edited_shard_after);
    assert!(
        !out.join(&edited_shard_before).exists(),
        "superseded shard must be removed"
    );
    for rel_path in ["mod/a.py", "mod/c.py"] {
        assert_eq!(
            manifest_after.files[rel_path].shard,
            manifest_before.files[rel_path].shard
        );
    }
    assert_eq!(
        collect_bundle_artifact_hashes(&out),
        untracked_tables,
        "digest-noop must not change index/, sections/, or INDEX.md"
    );
    let reloaded = load_cache_shard_unit(&out, &edited_shard_after, "mod/b.py").expect("reload");
    assert_eq!(
        reloaded.scanned.blake3_hash,
        manifest_after.files["mod/b.py"].blake3_hash
    );
    assert_eq!(reloaded.symbols[0].file, "mod/b.py");
}

/// `>500`-file repositories store their per-file AST cache in deterministic 64-unit packs; an edit
/// rewrites only its own pack, and the packed layout reloads losslessly and deterministically.
#[test]
fn test_packed_cache_shards_for_large_repos() {
    let tmp = TestTempDir::new("packed_cache");
    let repo = tmp.path().join("big_repo");
    let out = tmp.path().join("big_out");
    let total = 505usize;
    let shared = "def shared_probe(value: int) -> int:\n    return value + 1\n";
    for i in 0..total {
        // Eight files per module directory keeps the coordinate-shift grouping guard satisfied.
        let module = repo.join(format!("dir{}", i / 8));
        fs::create_dir_all(&module).unwrap();
        let body = if i < 2 {
            shared.to_string()
        } else {
            format!("def probe_{i}(value: int) -> int:\n    return value + {i}\n")
        };
        fs::write(module.join(format!("f{i}.py")), body).unwrap();
    }

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    assert_eq!(cold.metadata.total_files, total);
    assert!(cold.sanity.score >= 90, "sanity {}", cold.sanity.score);
    assert!(
        chipsrc_core::scanner::bundle_artifacts_complete(&out),
        "packed bundle must be artifact-complete"
    );

    let manifest = load_cache_manifest(&out).expect("cache/manifest.json");
    assert_eq!(manifest.files.len(), total);
    let shards: BTreeSet<&str> = manifest
        .files
        .values()
        .map(|entry| entry.shard.as_str())
        .collect();
    let expected_packs = total.div_ceil(CACHE_PACK_UNITS);
    assert_eq!(
        shards.len(),
        expected_packs,
        "a 505-file repo must create only packed shards"
    );
    for shard in &shards {
        assert!(chipsrc_core::is_packed_cache_shard(shard), "{shard}");
        assert!(out.join(shard).is_file(), "{shard} must exist");
    }

    // Byte-identical files at different paths keep distinct manifest entries.
    let f0 = manifest.files.get("dir0/f0.py").expect("f0 entry");
    let f1 = manifest.files.get("dir0/f1.py").expect("f1 entry");
    assert_eq!(f0.blake3_hash, f1.blake3_hash);
    let symbols_tsv = fs::read_to_string(out.join("index/symbols.tsv")).unwrap();
    assert!(symbols_tsv.contains("dir0/f0.py::shared_probe"));
    assert!(symbols_tsv.contains("dir0/f1.py::shared_probe"));

    // A same-line-count body edit takes the digest-noop tier and rewrites exactly one pack.
    let before = cache_pack_hashes(&out);
    let edit_path = repo.join("dir0/f3.py");
    fs::write(
        &edit_path,
        "def probe_3(value: int) -> int:\n    return value + 99\n",
    )
    .unwrap();
    let edited = convert_repo(&cfg).unwrap();
    assert_eq!(edited.metadata.incremental_reparsed_files, 1);
    assert_eq!(edited.metadata.incremental_reused_files, total - 1);
    assert_eq!(edited.metadata.incremental_tier, "digest_noop");
    assert_eq!(edited.metadata.total_files, total);

    let after = cache_pack_hashes(&out);
    let removed: Vec<&String> = before
        .keys()
        .filter(|name| !after.contains_key(*name))
        .collect();
    let added: Vec<&String> = after
        .keys()
        .filter(|name| !before.contains_key(*name))
        .collect();
    assert_eq!(removed.len(), 1, "exactly one pack must be replaced");
    assert_eq!(added.len(), 1, "exactly one pack must be created");
    for (name, hash) in &before {
        if removed.contains(&name) {
            continue;
        }
        assert_eq!(
            after.get(name),
            Some(hash),
            "unrelated pack {name} must stay byte-identical"
        );
    }

    let edited_manifest = load_cache_manifest(&out).expect("manifest after edit");
    let edited_entry = edited_manifest
        .files
        .get("dir0/f3.py")
        .expect("edited entry");
    let reloaded =
        load_cache_shard_unit(&out, &edited_entry.shard, "dir0/f3.py").expect("reload edited unit");
    assert_eq!(reloaded.scanned.blake3_hash, edited_entry.blake3_hash);
    assert_eq!(reloaded.symbols[0].file, "dir0/f3.py");
    assert_eq!(reloaded.symbols[0].symbol_id, "dir0/f3.py::probe_3");

    // Tier 3 (coordinate shift) re-emits the packed cache from parsed units
    // (`CacheShardSource::Units`): prepend comment lines without touching the AST shape.
    let coord_path = repo.join("dir2/f20.py");
    let coord_body = fs::read_to_string(&coord_path).unwrap();
    fs::write(&coord_path, format!("# shift 1\n# shift 2\n{coord_body}")).unwrap();
    let shifted = convert_repo(&cfg).unwrap();
    assert_eq!(shifted.metadata.incremental_tier, "coordinate_shift");
    assert_eq!(shifted.metadata.link_ms, 0);
    assert_eq!(shifted.metadata.graph_ms, 0);
    assert!(chipsrc_core::scanner::bundle_artifacts_complete(&out));
    let shifted_manifest = load_cache_manifest(&out).expect("manifest after shift");
    assert_eq!(shifted_manifest.files.len(), total);
    for entry in shifted_manifest.files.values() {
        assert!(chipsrc_core::is_packed_cache_shard(&entry.shard));
        assert!(out.join(&entry.shard).is_file());
    }
    let shifted_unit = load_cache_shard_unit(
        &out,
        &shifted_manifest.files["dir2/f20.py"].shard,
        "dir2/f20.py",
    )
    .expect("reload shifted unit");
    assert_eq!(shifted_unit.symbols[0].start_line, 3);

    // A structural edit relinks and repacks only the edited file's pack.
    let struct_path = repo.join("dir3/f24.py");
    let structural_body = fs::read_to_string(&struct_path).unwrap();
    fs::write(
        &struct_path,
        structural_body.replace("def probe_24(", "def renamed_probe_24("),
    )
    .unwrap();
    let structural = convert_repo(&cfg).unwrap();
    assert_eq!(structural.metadata.incremental_tier, "structural");
    assert_eq!(structural.metadata.incremental_reparsed_files, 1);
    assert_eq!(structural.metadata.incremental_reused_files, total - 1);
    assert!(chipsrc_core::scanner::bundle_artifacts_complete(&out));
    let structural_manifest = load_cache_manifest(&out).expect("manifest after structural edit");
    assert_eq!(structural_manifest.files.len(), total);
    let structural_unit = load_cache_shard_unit(
        &out,
        &structural_manifest.files["dir3/f24.py"].shard,
        "dir3/f24.py",
    )
    .expect("reload structural unit");
    assert_eq!(structural_unit.symbols[0].name, "renamed_probe_24");
    assert!(fs::read_to_string(out.join("index/symbols.tsv"))
        .unwrap()
        .contains("dir3/f24.py::renamed_probe_24"));

    // Incremental tables match a full --force rebuild, and the packed layout is reproducible.
    let incremental_hashes = collect_bundle_artifact_hashes(&out);
    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let forced = convert_repo(&force_cfg).unwrap();
    assert_eq!(forced.metadata.total_files, total);
    assert_eq!(
        collect_bundle_artifact_hashes(&out),
        incremental_hashes,
        "incremental tables must match --force"
    );
    let out2 = tmp.path().join("big_out2");
    let cfg2 = ConvertConfig::new(repo.clone(), out2.clone());
    let cold2 = convert_repo(&cfg2).unwrap();
    assert_eq!(cold2.metadata.total_files, total);
    assert_eq!(
        cache_pack_hashes(&out2),
        cache_pack_hashes(&out),
        "independent builds must produce identical pack files"
    );
}

// ============================================================================
// Coordinate-shift incremental tier (Tier 3) end-to-end invariants
// ============================================================================

fn bump_file_mtime(path: &Path) {
    let modified =
        fs::metadata(path).unwrap().modified().unwrap() + std::time::Duration::from_secs(2);
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
}

/// SHA-256 of `index/*`, `sections/*`, and `INDEX.md` keyed by bundle-relative path.
fn artifact_sha_map(bundle_dir: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for sub in ["index", "sections"] {
        let dir = bundle_dir.join(sub);
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let rel = format!(
                "{sub}/{}",
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
            );
            map.insert(
                rel,
                blake3::hash(&fs::read(&path).unwrap()).to_hex().to_string(),
            );
        }
    }
    let index_md = bundle_dir.join("INDEX.md");
    map.insert(
        "INDEX.md".to_string(),
        blake3::hash(&fs::read(&index_md).unwrap())
            .to_hex()
            .to_string(),
    );
    map
}

fn symbol_coords(bundle: &ConversionBundle, name: &str) -> (usize, usize) {
    let row = bundle
        .indexes
        .symbols
        .iter()
        .find(|rs| rs.symbol.name == name)
        .unwrap_or_else(|| panic!("symbol {name} missing from bundle"));
    (row.symbol.start_line, row.symbol.end_line)
}

#[test]
fn test_coordinate_shift_tier_skips_link_and_graph_and_matches_force() {
    let tmp = TestTempDir::new("coord_shift");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(repo.join("domain")).unwrap();

    let ident = repo.join("domain/identifiers.py");
    fs::write(
        &ident,
        "def normalize_pm(value: str) -> str:\n    return value.strip().lower()\n\n\ndef pm_match_key(value: str) -> str:\n    return normalize_pm(value).casefold()\n",
    )
    .unwrap();
    fs::write(
        repo.join("domain/helpers.py"),
        "def compute_checksum(data: str) -> int:\n    return len(data)\n",
    )
    .unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    assert_eq!(cold.metadata.incremental_tier, "structural");
    assert!(
        out.join("cache/graph_state.json").is_file(),
        "structural conversion must persist cache/graph_state.json"
    );
    let (s0, e0) = symbol_coords(&cold, "pm_match_key");

    // Prepend 5 comment lines (coordinate-only shift).
    let body = fs::read_to_string(&ident).unwrap();
    let mut shifted = String::new();
    for i in 1..=5 {
        shifted.push_str(&format!("# perf shift pad {i}\n"));
    }
    shifted.push_str(&body);
    fs::write(&ident, shifted).unwrap();
    bump_file_mtime(&ident);

    let inc = convert_repo(&cfg).unwrap();
    assert!(!inc.cache_hit, "coordinate shift must not report CACHE HIT");
    assert_eq!(
        inc.metadata.incremental_tier, "coordinate_shift",
        "digest-stable coordinate shift must select Tier 3"
    );
    assert_eq!(inc.metadata.link_ms, 0, "resolve_and_link must be skipped");
    assert_eq!(inc.metadata.graph_ms, 0, "analyze_graph must be skipped");
    assert_eq!(inc.metadata.incremental_reparsed_files, 1);
    assert_eq!(inc.metadata.incremental_reused_files, 1);
    assert_eq!(symbol_coords(&inc, "pm_match_key"), (s0 + 5, e0 + 5));

    let shifted_coord = format!("identifiers.py:{}-{}", s0 + 5, e0 + 5);
    let mut section_text = String::new();
    for entry in fs::read_dir(out.join("sections")).unwrap().flatten() {
        if entry.path().extension().and_then(|e| e.to_str()) == Some("md") {
            section_text.push_str(&fs::read_to_string(entry.path()).unwrap());
        }
    }
    assert!(
        section_text.contains(&shifted_coord),
        "sections must render the shifted coordinate {shifted_coord}"
    );

    let incremental_hashes = artifact_sha_map(&out);
    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let forced = convert_repo(&force_cfg).unwrap();
    assert_eq!(forced.metadata.incremental_tier, "structural");
    assert_eq!(symbol_coords(&forced, "pm_match_key"), (s0 + 5, e0 + 5));
    assert_eq!(
        incremental_hashes,
        artifact_sha_map(&out),
        "Tier 3 index/, sections/, and INDEX.md must be byte-identical to --force"
    );
    assert!(
        out.join("cache/graph_state.json").is_file(),
        "Tier 3 must rewrite graph state for the next shift"
    );

    // A docstring-only edit keeps the digest but changes rendered documentation; it also belongs
    // to the coordinate-shift tier and must propagate.
    let current = fs::read_to_string(&ident).unwrap();
    fs::write(
        &ident,
        current.replace(
            "def pm_match_key(value: str) -> str:",
            "def pm_match_key(value: str) -> str:\n    \"\"\"QA revised match key.\"\"\"",
        ),
    )
    .unwrap();
    bump_file_mtime(&ident);

    let doc_inc = convert_repo(&cfg).unwrap();
    assert_eq!(doc_inc.metadata.incremental_tier, "coordinate_shift");
    assert_eq!(doc_inc.metadata.link_ms, 0);
    assert_eq!(doc_inc.metadata.graph_ms, 0);
    let doc_hashes = artifact_sha_map(&out);
    let doc_forced = convert_repo(&force_cfg).unwrap();
    assert_eq!(
        doc_hashes,
        artifact_sha_map(&out),
        "docstring shift must match --force"
    );
    assert_eq!(symbol_coords(&doc_forced, "pm_match_key"), (s0 + 5, e0 + 6));
}

#[test]
fn test_coordinate_shift_threshold_crossing_falls_back_to_full_path() {
    let tmp = TestTempDir::new("coord_threshold");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(repo.join("threshold")).unwrap();

    let mut content = String::new();
    for i in 0..1394 {
        content.push_str(&format!("# pad line {i}\n"));
    }
    content.push_str(
        "def qa_threshold_target(x: int) -> int:\n    \"\"\"Doc.\"\"\"\n    return x + 1\n\n",
    );
    let file = repo.join("threshold/threshold.py");
    fs::write(&file, &content).unwrap();
    assert_eq!(count_source_lines(content.as_bytes()), 1398);

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    let (s0, e0) = symbol_coords(&cold, "qa_threshold_target");

    let mut grown = String::new();
    for i in 0..100 {
        grown.push_str(&format!("# grow {i}\n"));
    }
    grown.push_str(&content);
    fs::write(&file, &grown).unwrap();
    bump_file_mtime(&file);
    assert_eq!(count_source_lines(grown.as_bytes()), 1498);

    let inc = convert_repo(&cfg).unwrap();
    assert_eq!(
        inc.metadata.incremental_tier, "structural",
        "a dirty file crossing 1,400 lines must take the full structural path"
    );
    assert_eq!(
        symbol_coords(&inc, "qa_threshold_target"),
        (s0 + 100, e0 + 100)
    );
    let incremental_hashes = artifact_sha_map(&out);

    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let forced = convert_repo(&force_cfg).unwrap();
    assert_eq!(
        symbol_coords(&forced, "qa_threshold_target"),
        (s0 + 100, e0 + 100)
    );
    assert_eq!(
        incremental_hashes,
        artifact_sha_map(&out),
        "threshold fallback must still be byte-identical to --force"
    );
}

#[test]
fn test_truncated_graph_state_falls_back_and_next_shift_self_heals() {
    let tmp = TestTempDir::new("coord_truncated_graph");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(repo.join("domain")).unwrap();
    let file = repo.join("domain/identifiers.py");
    let original = "def normalize_pm(value: str) -> str:\n    return value.strip().lower()\n\n\ndef pm_match_key(value: str) -> str:\n    return normalize_pm(value).casefold()\n";
    fs::write(&file, original).unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    let (s0, e0) = symbol_coords(&cold, "pm_match_key");

    // Truncate the persisted graph state (tolerated: disables the fast path only).
    let graph_state = out.join("cache/graph_state.json");
    fs::write(&graph_state, br#"{"schema_version":"2.1.0","symbols":["#).unwrap();
    fs::write(&file, format!("# one more\n{original}")).unwrap();
    bump_file_mtime(&file);

    let inc = convert_repo(&cfg).unwrap();
    assert_eq!(inc.metadata.incremental_tier, "structural");
    assert_eq!(symbol_coords(&inc, "pm_match_key"), (s0 + 1, e0 + 1));
    let incremental_hashes = artifact_sha_map(&out);
    assert!(
        chipsrc_core::emitter::load_graph_state(&out).is_some(),
        "full rebuild must restore a parseable graph_state.json"
    );
    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let _ = convert_repo(&force_cfg).unwrap();
    assert_eq!(incremental_hashes, artifact_sha_map(&out));

    // The restored state must enable Tier 3 again.
    let body = fs::read_to_string(&file).unwrap();
    fs::write(&file, format!("# two more\n{body}")).unwrap();
    bump_file_mtime(&file);
    let healed = convert_repo(&cfg).unwrap();
    assert_eq!(healed.metadata.incremental_tier, "coordinate_shift");
    assert_eq!(healed.metadata.link_ms, 0);
    assert_eq!(symbol_coords(&healed, "pm_match_key"), (s0 + 2, e0 + 2));
}

#[test]
fn test_truncated_meta_json_rebuilds_without_panic() {
    let tmp = TestTempDir::new("coord_truncated_meta");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::write(
        repo.join("src/app.py"),
        "def app_main() -> int:\n    return 0\n",
    )
    .unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    assert_eq!(cold.metadata.symbol_count, 1);
    let good_hashes = artifact_sha_map(&out);

    let meta_path = out.join("meta.json");
    let meta_bytes = fs::read(&meta_path).unwrap();
    fs::write(&meta_path, &meta_bytes[..128.min(meta_bytes.len())]).unwrap();
    assert!(chipsrc_core::scanner::load_meta_file(&out).is_none());
    assert!(!chipsrc_core::scanner::bundle_artifacts_complete(&out));

    let rebuilt = convert_repo(&cfg).unwrap();
    assert_eq!(rebuilt.metadata.incremental_tier, "structural");
    assert!(chipsrc_core::scanner::load_meta_file(&out).is_some());
    assert!(chipsrc_core::scanner::bundle_artifacts_complete(&out));
    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let _ = convert_repo(&force_cfg).unwrap();
    assert_eq!(good_hashes, artifact_sha_map(&out));
}

#[test]
fn test_invalid_utf8_and_unicode_sources_never_panic() {
    let tmp = TestTempDir::new("coord_unicode");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(repo.join("domain")).unwrap();

    fs::write(
        repo.join("domain/qa_invalid_utf8.py"),
        b"# raw invalid bytes below\ndef qa_invalid_bytes():\n    value = b'\xff\xfe'\n    return value\n",
    )
    .unwrap();
    let unicode_file = repo.join("domain/qa_unic_snow.py");
    let unicode_source = "# \u{2603} \u{4e2d}\u{6587} w\u{f6}rld\ndef qa_unicode_snow(value: str) -> str:\n    \"\"\"Snowman \u{2603} helper.\"\"\"\n    return value\n";
    fs::write(&unicode_file, unicode_source).unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    assert!(cold
        .indexes
        .symbols
        .iter()
        .any(|rs| rs.symbol.name == "qa_unicode_snow"));

    // A comment shift on the unicode file exercises Tier 3 with non-ASCII source.
    fs::write(&unicode_file, format!("# pad \u{2603}\n{unicode_source}")).unwrap();
    bump_file_mtime(&unicode_file);
    let shifted = convert_repo(&cfg).unwrap();
    assert_eq!(shifted.metadata.link_ms, 0);
    assert!(shifted
        .indexes
        .symbols
        .iter()
        .any(|rs| rs.symbol.name == "qa_unicode_snow" && rs.symbol.start_line == 3));

    // Unicode search (regex, literal, and BM25 `concept`) must never panic and must be
    // deterministic across repeated calls. The concept tokens are absent from the index
    // metadata (name/doc/signature fields), so the ranked pass stays empty.
    let first = chipsrc_core::query::parallel_bundle_search(
        std::slice::from_ref(&out),
        "\u{2603} \u{4e2d}\u{6587} w\u{f6}rld",
        "all",
        false,
        50,
    )
    .unwrap();
    let second = chipsrc_core::query::parallel_bundle_search(
        std::slice::from_ref(&out),
        "\u{2603} \u{4e2d}\u{6587} w\u{f6}rld",
        "all",
        false,
        50,
    )
    .unwrap();
    assert_eq!(first, second);
    let concept = chipsrc_core::query::parallel_bundle_search(
        std::slice::from_ref(&out),
        "\u{2603} \u{4e2d}\u{6587} w\u{f6}rld",
        "concept",
        false,
        50,
    )
    .unwrap();
    assert!(
        concept.is_empty(),
        "unknown search kinds must stay empty, not panic"
    );

    let syms = query_symbols(
        std::slice::from_ref(&out),
        "qa_unicode_snow",
        None,
        false,
        10,
    )
    .unwrap();
    assert!(syms.contains("qa_unicode_snow"));
}

#[test]
fn test_coordinate_shift_with_vendor_surface_compaction_matches_force() {
    let tmp = TestTempDir::new("coord_vendor");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(repo.join("src/app")).unwrap();
    fs::create_dir_all(repo.join("vendor/sdk")).unwrap();
    fs::write(
        repo.join("vendor/sdk/lib.py"),
        "def vendor_init() -> int:\n    return 1\n\n\ndef unused_vendor_entry() -> int:\n    return 2\n",
    )
    .unwrap();
    let app = repo.join("src/app/app.py");
    fs::write(
        &app,
        "from vendor.sdk.lib import vendor_init\n\n\ndef app_main() -> int:\n    return vendor_init()\n",
    )
    .unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    assert_eq!(cold.metadata.vendor_files, 1);
    assert!(
        cold.indexes
            .symbols
            .iter()
            .any(|rs| rs.symbol.name == "vendor_init"),
        "referenced vendor symbol must survive active-surface compaction"
    );
    assert!(
        !cold
            .indexes
            .symbols
            .iter()
            .any(|rs| rs.symbol.name == "unused_vendor_entry"),
        "unreferenced vendor symbol must be compacted away"
    );
    let (s0, e0) = symbol_coords(&cold, "app_main");

    fs::write(
        &app,
        "# vendor probe pad 1\n# vendor probe pad 2\n# vendor probe pad 3\nfrom vendor.sdk.lib import vendor_init\n\n\ndef app_main() -> int:\n    return vendor_init()\n",
    )
    .unwrap();
    bump_file_mtime(&app);

    let inc = convert_repo(&cfg).unwrap();
    assert_eq!(inc.metadata.incremental_tier, "coordinate_shift");
    assert_eq!(inc.metadata.link_ms, 0);
    assert_eq!(inc.metadata.graph_ms, 0);
    assert_eq!(symbol_coords(&inc, "app_main"), (s0 + 3, e0 + 3));
    assert_eq!(inc.metadata.symbol_count, cold.metadata.symbol_count);
    let incremental_hashes = artifact_sha_map(&out);

    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let _ = convert_repo(&force_cfg).unwrap();
    assert_eq!(incremental_hashes, artifact_sha_map(&out));
}

// ============================================================================
// Sync-performance scrutiny regressions (SYNC-SCRUT-003..009)
// ============================================================================

/// SYNC-SCRUT-004: moving `helper()` from `impl A::run` to `impl B::run` keeps the structural
/// digest (same short caller name) but changes the linked caller id. Tier 3 must fall back so
/// `index/calls.tsv` matches a `--force` relink.
#[test]
fn test_coordinate_shift_moved_call_between_impls_matches_force() {
    let tmp = TestTempDir::new("scrut_moved_call");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(repo.join("src")).unwrap();
    let file = repo.join("src/method.rs");
    let before = "struct A;\n\nstruct B;\n\nimpl A {\n    fn run(&self) {\n        helper();\n    }\n}\n\nimpl B {\n    fn run(&self) {\n    }\n}\n\nfn helper() -> u32 {\n    1\n}\n\nfn main() {\n    A.run();\n    B.run();\n}\n";
    let after = "struct A;\n\nstruct B;\n\nimpl A {\n    fn run(&self) {\n    }\n}\n\nimpl B {\n    fn run(&self) {\n        helper();\n    }\n}\n\nfn helper() -> u32 {\n    1\n}\n\nfn main() {\n    A.run();\n    B.run();\n}\n";
    fs::write(&file, before).unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    assert_eq!(cold.metadata.incremental_tier, "structural");
    assert!(cold
        .indexes
        .symbols
        .iter()
        .any(|rs| rs.symbol.qualified_name == "A::run"));
    assert!(cold
        .indexes
        .symbols
        .iter()
        .any(|rs| rs.symbol.qualified_name == "B::run"));

    fs::write(&file, after).unwrap();
    bump_file_mtime(&file);

    let inc = convert_repo(&cfg).unwrap();
    assert_eq!(
        inc.metadata.incremental_tier, "structural",
        "a call moved between impls must reject Tier 3"
    );
    let calls = fs::read_to_string(out.join("index/calls.tsv")).unwrap();
    let helper_row = calls
        .lines()
        .find(|line| line.contains("\thelper\t"))
        .unwrap_or_else(|| panic!("missing helper call row in:\n{calls}"));
    assert!(
        helper_row.starts_with("src/method.rs::B::run\t"),
        "stale call owner after the move: {helper_row}"
    );

    let inc_hashes = artifact_sha_map(&out);
    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let _ = convert_repo(&force_cfg).unwrap();
    assert_eq!(
        inc_hashes,
        artifact_sha_map(&out),
        "moved-call output must be byte-identical to --force"
    );
}

/// SYNC-SCRUT-005: an inline-comment change on a non-macro raw xref must refresh
/// `index/xref.tsv` (Tier 3) and match `--force`.
#[test]
fn test_coordinate_shift_refreshes_inline_xref_comment_and_matches_force() {
    let tmp = TestTempDir::new("scrut_xref_comment");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(&repo).unwrap();
    let app = repo.join("app.py");
    let before = "class Device:\n    name: str = \"\"\n\n\ndef describe(device: Device) -> str:\n    result: str = device.name  # old inline comment\n    return result\n";
    let after = "class Device:\n    name: str = \"\"\n\n\ndef describe(device: Device) -> str:\n    result: str = device.name  # revised inline comment\n    return result\n";
    fs::write(&app, before).unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    assert!(cold
        .indexes
        .xrefs
        .iter()
        .any(|x| x.context.contains("old inline")));

    fs::write(&app, after).unwrap();
    bump_file_mtime(&app);

    let inc = convert_repo(&cfg).unwrap();
    assert_eq!(
        inc.metadata.incremental_tier, "coordinate_shift",
        "a context-only xref change must stay on Tier 3"
    );
    assert_eq!(inc.metadata.link_ms, 0);
    assert_eq!(inc.metadata.graph_ms, 0);
    let xrefs = fs::read_to_string(out.join("index/xref.tsv")).unwrap();
    assert!(
        xrefs.contains("# revised inline comment"),
        "stale xref context:\n{xrefs}"
    );
    assert!(!xrefs.contains("# old inline comment"));

    let inc_hashes = artifact_sha_map(&out);
    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let _ = convert_repo(&force_cfg).unwrap();
    assert_eq!(
        inc_hashes,
        artifact_sha_map(&out),
        "xref-context refresh must be byte-identical to --force"
    );
}

/// SYNC-SCRUT-006: two macros with the same name in one file must keep distinct `macro_def`
/// contexts through a coordinate shift.
#[test]
fn test_coordinate_shift_duplicate_macro_names_match_force() {
    let tmp = TestTempDir::new("scrut_dup_macros");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(&repo).unwrap();
    let file = repo.join("dup.rs");
    let body = "const LIMIT: u32 = 10;\n\nfn first() -> u32 {\n    LIMIT\n}\n\nconst LIMIT: u32 = 20;\n\nfn second() -> u32 {\n    LIMIT\n}\n";
    fs::write(&file, body).unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let cold = convert_repo(&cfg).unwrap();
    assert_eq!(cold.metadata.macro_count, 2);

    fs::write(&file, format!("# shift pad\n{body}")).unwrap();
    bump_file_mtime(&file);

    let inc = convert_repo(&cfg).unwrap();
    assert_eq!(inc.metadata.incremental_tier, "coordinate_shift");
    let xrefs = fs::read_to_string(out.join("index/xref.tsv")).unwrap();
    let limit_rows: Vec<&str> = xrefs
        .lines()
        .filter(|line| line.starts_with("LIMIT\tmacro_def\t"))
        .collect();
    assert_eq!(limit_rows.len(), 2, "two macro_def rows expected:\n{xrefs}");
    assert_eq!(
        limit_rows[0],
        "LIMIT\tmacro_def\tconst\t10\tdup.rs\t2\t01-root\t10 (Rust const/static item)",
        "the first duplicate macro kept the wrong context:\n{xrefs}"
    );
    assert_eq!(
        limit_rows[1],
        "LIMIT\tmacro_def\tconst\t20\tdup.rs\t8\t01-root\t20 (Rust const/static item)",
        "the second duplicate macro kept the wrong context:\n{xrefs}"
    );

    let inc_hashes = artifact_sha_map(&out);
    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let _ = convert_repo(&force_cfg).unwrap();
    assert_eq!(
        inc_hashes,
        artifact_sha_map(&out),
        "duplicate-macro output must be byte-identical to --force"
    );
}

/// SYNC-SCRUT-003: `emit_bundle` prunes stale `index/*.tmp` staging files.
#[test]
fn test_convert_prunes_stale_index_tmp_files() {
    let tmp = TestTempDir::new("scrut_index_tmp");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(&repo).unwrap();
    let app = repo.join("app.py");
    fs::write(&app, "def alpha() -> int:\n    return 1\n").unwrap();
    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let _ = convert_repo(&cfg).unwrap();

    let stale_tmp = out.join("index/.xref.tsv.9999.0.tmp");
    let fresh_tmp = out.join("index/.xref.tsv.9999.1.tmp");
    fs::write(&stale_tmp, b"stale").unwrap();
    fs::write(&fresh_tmp, b"fresh").unwrap();
    fs::File::options()
        .write(true)
        .open(&stale_tmp)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(120))
        .unwrap();

    fs::write(
        &app,
        "def alpha() -> int:\n    return 1\n\n\ndef beta() -> int:\n    return 2\n",
    )
    .unwrap();
    bump_file_mtime(&app);
    let _ = convert_repo(&cfg).unwrap();

    assert!(
        !stale_tmp.exists(),
        "stale index/*.tmp files must be pruned by emit_bundle"
    );
    assert!(fresh_tmp.exists(), "fresh index/*.tmp files must be kept");
    let _ = fs::remove_file(&fresh_tmp);
}

/// SYNC-SCRUT-009: a pre-compaction schema-2.1.0 shard (long field names) loads through the serde
/// aliases, and a `--force` rebuild rewrites it in the compact format.
#[test]
fn test_legacy_schema_shard_loads_and_force_rewrites_compact_cache() {
    let tmp = TestTempDir::new("scrut_legacy_shard");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(&repo).unwrap();
    let alpha = repo.join("alpha.py");
    let beta = repo.join("beta.py");
    fs::write(&alpha, "def alpha() -> int:\n    return 1\n").unwrap();
    fs::write(&beta, "def beta() -> int:\n    return 2\n").unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let _ = convert_repo(&cfg).unwrap();

    let manifest = load_cache_manifest(&out).expect("manifest");
    let alpha_entry = manifest.files.get("alpha.py").expect("alpha entry").clone();
    let alpha_shard = out.join(&alpha_entry.shard);
    let compact: serde_json::Value =
        serde_json::from_slice(&fs::read(&alpha_shard).unwrap()).expect("compact shard json");
    let scanned = compact["scanned"].clone();
    let symbol = &compact["symbols"][0];
    let legacy_symbol = format!(
        r#"{{"name":{},"qualified_name":{},"kind":{},"visibility":{},"start_line":{},"end_line":{},"signature":{},"doc_summary":{},"enclosing_type":{},"scope":{},"arch_layer":{},"section_id":{},"file":"alpha.py","symbol_id":"alpha.py::alpha"}}"#,
        symbol["n"],
        symbol["q"],
        symbol["k"],
        symbol["v"],
        symbol["s"],
        symbol["e"],
        symbol["g"],
        symbol["d"],
        symbol["t"],
        symbol["c"],
        symbol["a"],
        symbol["i"],
    );
    let legacy = format!(
        r#"{{"scanned":{scanned},"symbols":[{legacy_symbol}],"types":[],"macros":[],"imports":[],"raw_calls":[],"raw_xrefs":[],"parse_errors":0}}"#
    );
    fs::write(&alpha_shard, legacy).unwrap();
    assert!(
        load_cache_shard_unit(&out, &alpha_entry.shard, "alpha.py").is_some(),
        "legacy field-name shard must deserialize through serde aliases"
    );

    // A structural edit to beta.py only: alpha stays clean and must be reused (1 reparsed, 1 reused).
    fs::write(&beta, "def beta(x: int) -> int:\n    return x + 2\n").unwrap();
    bump_file_mtime(&beta);
    let inc = convert_repo(&cfg).unwrap();
    assert_eq!(inc.metadata.incremental_reparsed_files, 1);
    assert_eq!(inc.metadata.incremental_reused_files, 1);

    // `--force` reparses everything and rewrites the legacy shard in the compact format.
    let mut force_cfg = cfg.clone();
    force_cfg.force = true;
    let _ = convert_repo(&force_cfg).unwrap();
    let manifest = load_cache_manifest(&out).expect("manifest after force");
    let entry = manifest
        .files
        .get("alpha.py")
        .expect("alpha entry after force");
    let rewritten = fs::read_to_string(out.join(&entry.shard)).unwrap();
    assert!(
        rewritten.contains("\"q\":\"alpha\""),
        "force rebuild must write compact field names:\n{rewritten}"
    );
    assert!(
        !rewritten.contains("\"qualified_name\""),
        "force rebuild must not keep the legacy shard format"
    );
    assert!(load_cache_shard_unit(&out, &entry.shard, "alpha.py").is_some());
}

/// SYNC-SCRUT-009: a clean shard that failed to deserialize is rewritten by the incremental sync
/// instead of being reused from the previous manifest by content hash alone.
#[test]
fn test_unreadable_clean_shard_is_rewritten_incrementally() {
    let tmp = TestTempDir::new("scrut_unreadable_shard");
    let repo = tmp.path().join("repo");
    let out = tmp.path().join("bundle");
    fs::create_dir_all(&repo).unwrap();
    let alpha = repo.join("alpha.py");
    let beta = repo.join("beta.py");
    fs::write(&alpha, "def alpha() -> int:\n    return 1\n").unwrap();
    fs::write(&beta, "def beta() -> int:\n    return 2\n").unwrap();

    let cfg = ConvertConfig::new(repo.clone(), out.clone());
    let _ = convert_repo(&cfg).unwrap();
    let manifest = load_cache_manifest(&out).expect("manifest");
    let alpha_shard = out.join(&manifest.files["alpha.py"].shard);
    fs::write(&alpha_shard, b"{not valid json").unwrap();

    fs::write(&beta, "def beta(x: int) -> int:\n    return x + 2\n").unwrap();
    bump_file_mtime(&beta);
    let inc = convert_repo(&cfg).unwrap();
    assert_eq!(
        inc.metadata.incremental_reparsed_files, 2,
        "the unreadable clean shard must be reparsed"
    );
    assert_eq!(inc.metadata.incremental_reused_files, 0);

    let manifest = load_cache_manifest(&out).expect("manifest after incremental");
    assert!(
        load_cache_shard_unit(&out, &manifest.files["alpha.py"].shard, "alpha.py").is_some(),
        "the repaired sync must rewrite the unreadable clean shard"
    );

    let again = convert_repo(&cfg).unwrap();
    assert!(again.cache_hit, "the repaired bundle must cache-hit");
}
