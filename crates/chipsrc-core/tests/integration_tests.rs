//! End-to-end integration tests for `chipsrc-core`.

use chipsrc_core::query::{
    parallel_bundle_search, query_call_path, query_callees, query_callers, query_impact,
    query_macros, query_sections, query_subcommand_json, query_symbols, query_types, query_xref,
    workspace_status,
};
use chipsrc_core::{
    auto_refresh_bundles, convert_repo, ensure_repo, inspect_repo, ArchLayer, BundleMetaFile,
    ChipsrcError, ConvertConfig, FileScope, LanguageKind, MacroKind, ResolutionTier, SymbolKind,
    VendorMode,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct TestTempDir(PathBuf);

impl TestTempDir {
    fn new(label: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("chipsrc_integ_{label}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn create_synthetic_repo(root: &Path) {
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root.join("src/app")).unwrap();
    fs::create_dir_all(root.join("src/bsp")).unwrap();
    fs::create_dir_all(root.join("src/drvs")).unwrap();
    fs::create_dir_all(root.join("vendor/cmsis")).unwrap();
    fs::create_dir_all(root.join("scripts")).unwrap();
    fs::create_dir_all(root.join("frontend")).unwrap();

    // 1. vendor/cmsis/device.h
    fs::write(
        root.join("vendor/cmsis/device.h"),
        r#"#ifndef DEVICE_H
#define DEVICE_H

#include <stdint.h>

#define VENDOR_TIM1_BASE 0x41C00000UL
#define VENDOR_TIM1_CCR1 0x41C00004UL
#define UNUSED_VENDOR_MACRO 0x41C0FFFFUL

typedef struct {
    volatile uint32_t CR1;
    volatile uint32_t CCR1;
    volatile uint32_t SR;
} TIM_TypeDef;

#define VENDOR_TIM1 ((TIM_TypeDef *) VENDOR_TIM1_BASE)

static inline void vendor_tim_enable(void) {
    VENDOR_TIM1->CR1 |= 1U;
}

static inline void vendor_unused_helper(void) {
    VENDOR_TIM1->SR = 0U;
}

#endif
"#,
    )
    .unwrap();

    // 2. src/drvs/motor_ctrl.h
    fs::write(
        root.join("src/drvs/motor_ctrl.h"),
        r#"#ifndef MOTOR_CTRL_H
#define MOTOR_CTRL_H

#include <stdint.h>

#define MOTOR_PWM_REG_ADDR 0x41C00004UL
#define MOTOR_ENABLE_MASK  (1U << 0)

typedef struct {
    uint32_t max_duty;
    uint8_t channel;
} MotorConfig_t;

void motor_init(const MotorConfig_t *cfg);
void motor_set_duty(uint32_t duty);

#endif
"#,
    )
    .unwrap();

    // 3. src/drvs/motor_ctrl.c
    fs::write(
        root.join("src/drvs/motor_ctrl.c"),
        r#"#include "motor_ctrl.h"
#include "../../vendor/cmsis/device.h"

/**
 * Initializes the hardware timer for PWM motor control.
 */
void motor_init(const MotorConfig_t *cfg) {
    vendor_tim_enable();
    motor_set_duty(cfg->max_duty);
}

/**
 * Writes the PWM duty cycle to VENDOR_TIM1->CCR1.
 */
void motor_set_duty(uint32_t duty) {
    VENDOR_TIM1->CCR1 = duty;
}

/**
 * Timer 1 Update Interrupt Service Routine.
 */
void TIM1_UP_IRQHandler(void) {
    VENDOR_TIM1->SR = 0U;
    motor_set_duty(0U);
}
"#,
    )
    .unwrap();

    // 4. src/bsp/board.c
    fs::write(
        root.join("src/bsp/board.c"),
        r#"#include "../drvs/motor_ctrl.h"

void board_init(void) {
    MotorConfig_t cfg = { .max_duty = 500, .channel = 1 };
    motor_init(&cfg);
}
"#,
    )
    .unwrap();

    // 5. src/app/main.c
    fs::write(
        root.join("src/app/main.c"),
        r#"#include "../drvs/motor_ctrl.h"

extern void board_init(void);

int main(void) {
    board_init();
    motor_set_duty(250);
    return 0;
}
"#,
    )
    .unwrap();

    // 6. scripts/tool.py
    fs::write(
        root.join("scripts/tool.py"),
        r#"DEFAULT_BAUD = 115200

class TelemetryParser:
    """Parses binary frames from the motor controller."""
    def __init__(self, baud: int = DEFAULT_BAUD):
        self.baud = baud

    def decode_frame(self, payload: bytes) -> dict:
        return {"len": len(payload), "baud": self.baud}
"#,
    )
    .unwrap();

    // 7. frontend/app.ts
    fs::write(
        root.join("frontend/app.ts"),
        r#"export interface MotorStatus {
    duty: number;
    active: boolean;
}

export function formatMotorStatus(status: MotorStatus): string {
    return `duty=${status.duty} active=${status.active}`;
}
"#,
    )
    .unwrap();
}

#[test]
fn test_full_pipeline_vendor_modes_incremental_sync_and_queries() {
    let base = TestTempDir::new("pipeline");
    let repo_dir = base.0.join("synth_fw");
    let output_root = repo_dir.join("output");
    let bundle_dir = output_root.join("synth_fw");

    create_synthetic_repo(&repo_dir);

    // 1. Test inspect_repo
    let inspect_active = inspect_repo(&repo_dir, VendorMode::Active).expect("inspect active");
    assert_eq!(inspect_active.total_files, 7);
    assert_eq!(inspect_active.first_party_files, 6);
    assert_eq!(inspect_active.vendor_files, 1);

    let inspect_none = inspect_repo(&repo_dir, VendorMode::None).expect("inspect none");
    assert_eq!(inspect_none.total_files, 6);
    assert_eq!(inspect_none.vendor_files, 0);

    // 2. Test full conversion with VendorMode::Active and single_file = true
    let mut cfg = ConvertConfig::new(repo_dir.clone(), bundle_dir.clone());
    cfg.single_file = true;
    cfg.vendor_mode = VendorMode::Active;

    let bundle = convert_repo(&cfg).expect("convert_repo active");
    assert!(!bundle.cache_hit);
    assert_eq!(bundle.metadata.total_files, 7);
    assert_eq!(bundle.metadata.incremental_reparsed_files, 7);
    assert_eq!(bundle.metadata.incremental_reused_files, 0);
    assert!(bundle.sanity.score >= 85);

    // Verify all emitted files exist (and `.claudeignore` is written inside `repo_dir`, not parent `base`)
    assert!(bundle_dir.join("INDEX.md").is_file());
    assert!(bundle_dir.join("meta.json").is_file());
    assert!(bundle_dir.join("cache").join("manifest.json").is_file());
    assert!(bundle_dir.join("synth_fw.md").is_file());
    assert!(repo_dir.join(".claudeignore").is_file());
    assert!(!base.0.join(".claudeignore").is_file());

    for tsv in [
        "sections.tsv",
        "symbols.tsv",
        "types.tsv",
        "calls.tsv",
        "macros.tsv",
        "xref.tsv",
    ] {
        assert!(
            bundle_dir.join("index").join(tsv).is_file(),
            "Missing index/{tsv}"
        );
    }

    // Verify active vendor surface identified vendor_tim_enable and VENDOR_TIM1->CCR1
    assert!(bundle
        .indexes
        .vendor_surface
        .active_vendor_symbols
        .iter()
        .any(|s| s == "vendor_tim_enable"));
    assert!(bundle
        .indexes
        .vendor_surface
        .active_mmio_registers
        .iter()
        .any(|r| r.contains("VENDOR_TIM1->CCR1")));

    // 3. Test fast-path cache hit on unchanged repo
    let cached_bundle = convert_repo(&cfg).expect("convert_repo cache hit");
    assert!(cached_bundle.cache_hit);
    assert_eq!(cached_bundle.metadata.incremental_reparsed_files, 0);
    assert_eq!(cached_bundle.metadata.incremental_reused_files, 7);

    // 4. Test all 1-turn query functions against the generated bundle
    let bundles: Vec<PathBuf> = vec![bundle_dir.clone()];

    let sym_out = query_symbols(&bundles, "motor_set_duty", None, true, 10).expect("query_symbols");
    assert!(sym_out.contains("motor_set_duty"));
    assert!(sym_out.contains("VENDOR_TIM1->CCR1 = duty;"));

    let isr_out =
        query_symbols(&bundles, "TIM1_UP_IRQHandler", Some("isr"), false, 10).expect("query isr");
    assert!(isr_out.contains("TIM1_UP_IRQHandler"));

    let callers_out = query_callers(&bundles, "motor_set_duty", true, 10).expect("query_callers");
    assert!(callers_out.contains("motor_init"));
    assert!(callers_out.contains("main"));
    assert!(callers_out.contains("TIM1_UP_IRQHandler"));

    let callees_out = query_callees(&bundles, "motor_init", true, 10).expect("query_callees");
    assert!(callees_out.contains("vendor_tim_enable"));
    assert!(callees_out.contains("motor_set_duty"));

    let types_out = query_types(&bundles, "MotorConfig_t", true, 10).expect("query_types");
    assert!(types_out.contains("MotorConfig_t"));
    assert!(types_out.contains("max_duty"));

    let ts_type_out = query_types(&bundles, "MotorStatus", false, 10).expect("query ts type");
    assert!(ts_type_out.contains("MotorStatus"));

    // Hex normalization query: 41C00004h matches 0x41C00004
    let reg_out = query_macros(&bundles, "41C00004h", true, 10).expect("query_macros hex");
    assert!(reg_out.contains("0x41C00004"));
    assert!(reg_out.contains("MOTOR_PWM_REG_ADDR") || reg_out.contains("VENDOR_TIM1_CCR1"));

    // Peripheral access query: VENDOR_TIM1_CCR1 <-> VENDOR_TIM1->CCR1
    let mmio_out =
        query_macros(&bundles, "VENDOR_TIM1->CCR1", true, 10).expect("query_macros mmio");
    assert!(mmio_out.contains("VENDOR_TIM1->CCR1") || mmio_out.contains("VENDOR_TIM1_CCR1"));

    let sec_out = query_sections(&bundles, "drvs", true, 10).expect("query_sections");
    assert!(sec_out.contains("src/drvs"));

    let xref_out = query_xref(&bundles, "VENDOR_TIM1->CCR1", 20).expect("query_xref");
    assert!(xref_out.contains("motor_set_duty"));

    let hits = parallel_bundle_search(&bundles, "decode_frame", "all", false, 20).expect("search");
    assert!(!hits.is_empty());
    assert!(hits.iter().any(|h| h.snippet.contains("decode_frame")));

    // 5. Test single-file edit + workspace_status + auto_refresh_bundles (incremental AST sync)
    let status_before = workspace_status(&output_root).expect("status before edit");
    assert_eq!(status_before.len(), 1);
    assert!(status_before[0].is_fresh);

    // Modify only src/app/main.c
    fs::write(
        repo_dir.join("src/app/main.c"),
        r#"#include "../drvs/motor_ctrl.h"

extern void board_init(void);

void emergency_brake(void) {
    motor_set_duty(0);
}

int main(void) {
    board_init();
    motor_set_duty(300);
    emergency_brake();
    return 0;
}
"#,
    )
    .unwrap();

    let status_stale = workspace_status(&output_root).expect("status after edit");
    assert!(!status_stale[0].is_fresh);
    assert_eq!(status_stale[0].changed_files_count, 1);

    let refreshed_count = auto_refresh_bundles(&bundles).expect("auto_refresh_bundles");
    assert_eq!(refreshed_count, 1);

    // Read meta.json to verify ONLY 1 file was reparsed and 6 files were reused from cache.json!
    let meta_bytes = fs::read(bundle_dir.join("meta.json")).expect("read refreshed meta.json");
    let refreshed_meta: BundleMetaFile =
        serde_json::from_slice(&meta_bytes).expect("parse refreshed meta.json");
    assert_eq!(refreshed_meta.metadata.incremental_reparsed_files, 1);
    assert_eq!(refreshed_meta.metadata.incremental_reused_files, 6);

    // Query the newly added symbol `emergency_brake`
    let brake_out =
        query_symbols(&bundles, "emergency_brake", None, true, 10).expect("query emergency_brake");
    assert!(brake_out.contains("emergency_brake"));

    // 6. Test VendorMode::All and VendorMode::None via ensure_repo
    let all_bundle = ensure_repo(&repo_dir, &output_root, false, VendorMode::All)
        .expect("ensure VendorMode::All");
    assert_eq!(all_bundle.metadata.vendor_mode, VendorMode::All);
    assert_eq!(all_bundle.metadata.total_files, 7);

    let none_bundle = ensure_repo(&repo_dir, &output_root, false, VendorMode::None)
        .expect("ensure VendorMode::None");
    assert_eq!(none_bundle.metadata.vendor_mode, VendorMode::None);
    assert_eq!(none_bundle.metadata.total_files, 6);
    assert_eq!(none_bundle.metadata.vendor_files, 0);
}

#[test]
fn test_blueprint_onboarding_overrides_cache_invalidation_and_empty_repo() {
    let base = TestTempDir::new("blueprint");
    let repo_dir = base.0.join("custom_repo");
    let bundle_dir = base.0.join("output").join("custom_repo");

    fs::create_dir_all(repo_dir.join("custom_hw/fpga_box")).unwrap();
    fs::create_dir_all(repo_dir.join("packages/telemetry")).unwrap();
    fs::create_dir_all(repo_dir.join("legacy_drop")).unwrap();

    fs::write(
        repo_dir.join("custom_hw/fpga_box/fpga_reg.c"),
        r#"#include <stdint.h>

#define FPGA_DOORBELL_REG 0xB4000010UL

CHIP_FAST_RAM void fpga_ring_doorbell(uint32_t code) {
    *(volatile uint32_t *)0xB4000010UL = code;
}

void fpga_dma_done_CustomISR(void) {
    fpga_ring_doorbell(1U);
}

void custom_boot_entry(void) {
    fpga_ring_doorbell(0U);
}
"#,
    )
    .unwrap();

    fs::write(
        repo_dir.join("packages/telemetry/index.ts"),
        r#"export function encodePacket(id: number): string {
    return `pkt:${id}`;
}
"#,
    )
    .unwrap();

    fs::write(
        repo_dir.join("legacy_drop/old.c"),
        "void ignored_legacy_fn(void) {}\n",
    )
    .unwrap();

    // 1. Inspect before `.chipsrc.json` exists -> onboarding signals must be populated
    let report_before = inspect_repo(&repo_dir, VendorMode::Active).expect("inspect before bp");
    assert!(!report_before.has_blueprint);
    assert!(
        report_before
            .unclassified_dirs
            .iter()
            .any(|d| d.contains("custom_hw/fpga_box")),
        "Expected unclassified dir in {:?}",
        report_before.unclassified_dirs
    );
    assert!(
        report_before
            .detected_workspaces
            .iter()
            .any(|w| w == "packages/telemetry"),
        "Expected workspace root in {:?}",
        report_before.detected_workspaces
    );
    assert!(
        report_before
            .candidate_c_macros
            .iter()
            .any(|m| m == "CHIP_FAST_RAM"),
        "Expected candidate C macro in {:?}",
        report_before.candidate_c_macros
    );

    // 2. Write `.chipsrc.json` blueprint
    fs::write(
        repo_dir.join(".chipsrc.json"),
        r#"{
  "scopes": {
    "custom_hw/fpga_box": "first_party"
  },
  "layers": {
    "custom_hw/fpga_box": "bsp",
    "packages/telemetry": "services"
  },
  "shards": {
    "custom_hw/fpga_box": "fpga-bsp"
  },
  "ignore_dirs": ["legacy_drop"],
  "c_qualifiers": {
    "CHIP_FAST_RAM": "static inline"
  },
  "entrypoints": ["custom_boot_entry"],
  "isr_patterns": ["_CustomISR"],
  "mmio_ranges": [
    {
      "start": "0xB0000000",
      "end": "0xBFFFFFFF",
      "description": "Custom FPGA MMIO aperture"
    }
  ]
}"#,
    )
    .unwrap();

    let report_after = inspect_repo(&repo_dir, VendorMode::Active).expect("inspect after bp");
    assert!(report_after.has_blueprint);
    assert_ne!(report_before.fingerprint, report_after.fingerprint);
    // `legacy_drop/old.c` is excluded by `ignore_dirs`
    assert_eq!(report_after.total_files, 2);

    let cfg = ConvertConfig::new(repo_dir.clone(), bundle_dir.clone());
    let bundle = convert_repo(&cfg).expect("convert with blueprint");
    assert_eq!(bundle.metadata.total_files, 2);

    // Verify custom C qualifier macro allowed clean parse (0 errors)
    assert_eq!(bundle.sanity.parse_clean_ratio, 1.0);

    // Verify custom entrypoint and ISR pattern classification
    let boot_sym = bundle
        .indexes
        .symbols
        .iter()
        .find(|rs| rs.symbol.name == "custom_boot_entry")
        .expect("custom_boot_entry symbol");
    assert_eq!(boot_sym.symbol.kind, SymbolKind::Entrypoint);
    assert_eq!(boot_sym.symbol.arch_layer, ArchLayer::Bsp);
    assert_eq!(boot_sym.symbol.scope, FileScope::FirstParty);
    assert!(boot_sym.symbol.section_id.ends_with("fpga-bsp"));

    let isr_sym = bundle
        .indexes
        .symbols
        .iter()
        .find(|rs| rs.symbol.name == "fpga_dma_done_CustomISR")
        .expect("fpga_dma_done_CustomISR symbol");
    assert_eq!(isr_sym.symbol.kind, SymbolKind::Isr);

    // Verify custom MMIO range classified `0xB4000010` as MmioAddress
    let fpga_mac = bundle
        .indexes
        .macros
        .iter()
        .find(|m| m.name == "FPGA_DOORBELL_REG")
        .expect("FPGA_DOORBELL_REG macro");
    assert_eq!(fpga_mac.kind, MacroKind::MmioAddress);
    assert!(fpga_mac.description.contains("Custom FPGA MMIO aperture"));

    // Verify `cache/manifest.json` is compact single-line JSON
    let cache_raw = fs::read_to_string(bundle_dir.join("cache").join("manifest.json"))
        .expect("read cache/manifest.json");
    assert_eq!(
        cache_raw.lines().count(),
        1,
        "cache/manifest.json must be compact JSON"
    );

    // 3. Modifying `.chipsrc.json` must invalidate the cache and re-parse
    fs::write(
        repo_dir.join(".chipsrc.json"),
        r#"{
  "layers": {
    "custom_hw/fpga_box": "drvs"
  },
  "ignore_dirs": ["legacy_drop"],
  "c_qualifiers": {
    "CHIP_FAST_RAM": "static inline"
  }
}"#,
    )
    .unwrap();

    let bundle_reindexed = convert_repo(&cfg).expect("convert after blueprint edit");
    assert!(
        !bundle_reindexed.cache_hit,
        "Blueprint change must invalidate cache"
    );
    let boot_sym_updated = bundle_reindexed
        .indexes
        .symbols
        .iter()
        .find(|rs| rs.symbol.name == "custom_boot_entry")
        .expect("custom_boot_entry symbol after update");
    assert_eq!(boot_sym_updated.symbol.arch_layer, ArchLayer::Drivers);

    // 4. Empty/fresh repository with `.chipsrc.json` must succeed on inspect_repo
    let empty_dir = base.0.join("empty_with_bp");
    fs::create_dir_all(&empty_dir).unwrap();
    fs::write(empty_dir.join(".chipsrc.json"), "{}\n").unwrap();
    let empty_report =
        inspect_repo(&empty_dir, VendorMode::Active).expect("inspect empty repo with bp");
    assert!(empty_report.has_blueprint);
    assert_eq!(empty_report.total_files, 0);
}

#[test]
fn test_local_receiver_binding_fn_ptr_dispatch_mutability_and_path_impact_queries() {
    let base = TestTempDir::new("ideas");
    let repo_dir = base.0.join("fw_ideas");
    let bundle_dir = base.0.join("output").join("fw_ideas");

    fs::create_dir_all(repo_dir.join("src/app")).unwrap();
    fs::create_dir_all(repo_dir.join("src/drvs")).unwrap();

    // Rust file testing:
    // - Idea 3: Two structs (`SpiDriver`, `I2cDriver`) both define `transfer()`.
    //   `run_bus(spi: &mut SpiDriver)` and `let dev = I2cDriver::new(); dev.transfer()` must
    //   resolve unambiguously to their respective struct methods (`SameFile`) rather than `AmbiguousName`.
    // - Idea 5: `self.tx_count += 1` (`writes_field`) vs `let n = self.tx_count` (`reads_field`).
    fs::write(
        repo_dir.join("src/drvs/bus.rs"),
        r#"pub struct SpiDriver {
    pub tx_count: u32,
}

pub struct I2cDriver {
    pub tx_count: u32,
}

impl SpiDriver {
    pub fn new() -> Self {
        Self { tx_count: 0 }
    }

    pub fn transfer(&mut self, byte: u8) -> u32 {
        self.tx_count += u32::from(byte);
        let current = self.tx_count;
        current
    }
}

impl I2cDriver {
    pub fn new() -> Self {
        Self { tx_count: 0 }
    }

    pub fn transfer(&mut self, byte: u8) -> u32 {
        u32::from(byte)
    }
}

pub fn run_spi_transaction(spi: &mut SpiDriver) -> u32 {
    spi.transfer(0x42)
}

pub fn run_i2c_transaction() -> u32 {
    let mut dev = I2cDriver::new();
    dev.transfer(0x10)
}
"#,
    )
    .unwrap();

    // C file testing:
    // - Idea 4: Function-pointer dispatch table (`.on_frame = handle_uart_frame`) and callback argument (`register_irq(uart_error_isr)`),
    //   plus precision filtering of non-function constant `BAUD_RATE_CONST`.
    // - Idea 5: MMIO register write (`UART0->DR = byte`) vs read (`uint32_t status = UART0->SR`).
    // - Idea 6: Multi-hop call chain `main -> system_startup -> register_uart_driver -> handle_uart_frame -> low_level_fifo_push`.
    fs::write(
        repo_dir.join("src/app/uart_app.c"),
        r#"#include <stdint.h>

#define UART0_BASE 0x40011000UL
typedef struct {
    volatile uint32_t SR;
    volatile uint32_t DR;
} UART_TypeDef;
#define UART0 ((UART_TypeDef *) UART0_BASE)
#define BAUD_RATE_CONST 115200U

typedef struct {
    void (*on_frame)(uint8_t);
    uint32_t baud;
} UartOps_t;

void low_level_fifo_push(uint8_t b) {
    uint32_t status = UART0->SR;
    if (status != 0U) {
        UART0->DR = (uint32_t)b;
    }
}

void handle_uart_frame(uint8_t b) {
    low_level_fifo_push(b);
}

void uart_error_IRQHandler(void) {
    low_level_fifo_push(0xFFU);
}

void install_irq_callback(uint32_t irq_num, void (*cb)(void)) {
    (void)irq_num;
    (void)cb;
}

void register_uart_driver(void) {
    UartOps_t ops = {
        .on_frame = handle_uart_frame,
        .baud = BAUD_RATE_CONST
    };
    (void)ops;
    install_irq_callback(37U, uart_error_IRQHandler);
}

void system_startup(void) {
    register_uart_driver();
}

int main(void) {
    system_startup();
    return 0;
}
"#,
    )
    .unwrap();

    let cfg = ConvertConfig::new(repo_dir.clone(), bundle_dir.clone());
    let bundle = convert_repo(&cfg).expect("convert_repo ideas");

    // Verify Idea 3: `run_spi_transaction` -> `SpiDriver::transfer` and `run_i2c_transaction` -> `I2cDriver::transfer`
    let spi_call = bundle
        .indexes
        .calls
        .iter()
        .find(|c| c.caller_name == "run_spi_transaction" && c.callee_name == "transfer")
        .expect("run_spi_transaction -> transfer call");
    assert!(
        spi_call.callee_id.ends_with("SpiDriver::transfer"),
        "Expected SpiDriver::transfer, got {}",
        spi_call.callee_id
    );
    assert_eq!(spi_call.tier, ResolutionTier::SameFile);

    let i2c_call = bundle
        .indexes
        .calls
        .iter()
        .find(|c| c.caller_name == "run_i2c_transaction" && c.callee_name == "transfer")
        .expect("run_i2c_transaction -> transfer call");
    assert!(
        i2c_call.callee_id.ends_with("I2cDriver::transfer"),
        "Expected I2cDriver::transfer, got {}",
        i2c_call.callee_id
    );
    assert_eq!(i2c_call.tier, ResolutionTier::SameFile);

    // Verify Idea 4: `register_uart_driver` has synthesized call edges and `dispatches_fn` xrefs
    // to `handle_uart_frame` and `uart_error_IRQHandler`, while `BAUD_RATE_CONST` is NOT in `fn_ptr_ref`
    assert!(
        bundle.indexes.calls.iter().any(
            |c| c.caller_name == "register_uart_driver" && c.callee_name == "handle_uart_frame"
        ),
        "Missing synthesized fn_ptr call edge to handle_uart_frame"
    );
    assert!(
        bundle
            .indexes
            .calls
            .iter()
            .any(|c| c.caller_name == "register_uart_driver"
                && c.callee_name == "uart_error_IRQHandler"),
        "Missing synthesized callback call edge to uart_error_IRQHandler"
    );
    assert!(
        bundle
            .indexes
            .xrefs
            .iter()
            .any(|x| x.symbol == "handle_uart_frame" && x.relation == "dispatches_fn"),
        "Missing dispatches_fn xref for handle_uart_frame"
    );
    assert!(
        !bundle
            .indexes
            .xrefs
            .iter()
            .any(|x| x.symbol == "BAUD_RATE_CONST" && x.category == "fn_ptr_ref"),
        "Non-function constant BAUD_RATE_CONST must be precision-filtered out of fn_ptr_ref"
    );

    // Verify Idea 5: MMIO `writes_reg` (`UART0->DR`) and `reads_reg` (`UART0->SR`),
    // plus struct field `writes_field` and `reads_field` (`SpiDriver::tx_count`)
    assert!(
        bundle
            .indexes
            .xrefs
            .iter()
            .any(|x| x.symbol == "UART0->DR" && x.relation == "writes_reg"),
        "Expected writes_reg for UART0->DR"
    );
    assert!(
        bundle
            .indexes
            .xrefs
            .iter()
            .any(|x| x.symbol == "UART0->SR" && x.relation == "reads_reg"),
        "Expected reads_reg for UART0->SR"
    );
    assert!(
        bundle
            .indexes
            .xrefs
            .iter()
            .any(|x| x.symbol == "SpiDriver::tx_count" && x.relation == "writes_field"),
        "Expected writes_field for SpiDriver::tx_count"
    );
    assert!(
        bundle
            .indexes
            .xrefs
            .iter()
            .any(|x| x.symbol == "SpiDriver::tx_count" && x.relation == "reads_field"),
        "Expected reads_field for SpiDriver::tx_count"
    );

    // Verify Idea 6: `query_call_path` and `query_impact`
    let bundles = vec![bundle_dir.clone()];
    let path_out =
        query_call_path(&bundles, "main", "low_level_fifo_push", 8).expect("query_call_path");
    assert!(
        path_out.contains("4 hops"),
        "Expected 4-hop path (main -> system_startup -> register_uart_driver -> handle_uart_frame -> low_level_fifo_push), got:\n{path_out}"
    );
    assert!(path_out.contains("register_uart_driver"));
    assert!(path_out.contains("handle_uart_frame"));

    let impact_out = query_impact(&bundles, "low_level_fifo_push", 6, 40).expect("query_impact");
    assert!(
        impact_out.contains("main"),
        "Impact should reach entrypoint main:\n{impact_out}"
    );
    assert!(
        impact_out.contains("uart_error_IRQHandler"),
        "Impact should reach ISR uart_error_IRQHandler:\n{impact_out}"
    );
}

fn set_file_mtime(path: &Path, secs: u64, nanos: u32) {
    let t = std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos);
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

#[test]
fn same_second_edit_is_detected_end_to_end() {
    let tmp = TestTempDir::new("same_second_e2e");
    let repo_dir = tmp.0.join("repo");
    let bundle_dir = tmp.0.join("bundle");
    fs::create_dir_all(repo_dir.join("src")).unwrap();

    let file_a = repo_dir.join("src/a.py");
    let file_b = repo_dir.join("src/b.py");
    let v1 = "def pm_match_key(x: int) -> int:\n    return x + 1\n";
    let v2 = "def pm_match_new(x: int) -> int:\n    return x + 1\n";
    assert_eq!(v1.len(), v2.len());

    fs::write(&file_a, v1).unwrap();
    fs::write(
        &file_b,
        "def helper_func(y: int) -> int:\n    return y * 2\n",
    )
    .unwrap();
    set_file_mtime(&file_a, 1_700_000_000, 150_000_000);

    let cfg = ConvertConfig::new(repo_dir.clone(), bundle_dir.clone());
    let b1 = convert_repo(&cfg).expect("initial convert");
    assert!(!b1.cache_hit);
    let stamp_a_1 = b1
        .metadata
        .file_stamps
        .iter()
        .find(|s| s.rel_path == "src/a.py")
        .expect("stamp for src/a.py");
    assert_eq!(stamp_a_1.mtime_secs, 1_700_000_000);
    assert_eq!(stamp_a_1.mtime_nanos, 150_000_000);

    let b1_warm = convert_repo(&cfg).expect("warm convert");
    assert!(b1_warm.cache_hit);

    // Rewrite with same length and +100ms within the same second
    fs::write(&file_a, v2).unwrap();
    set_file_mtime(&file_a, 1_700_000_000, 250_000_000);

    let status = chipsrc_core::query::workspace_status(&bundle_dir).expect("workspace_status");
    assert_eq!(status.len(), 1);
    assert!(
        !status[0].is_fresh,
        "Expected stale bundle after same-second same-size edit"
    );
    assert_eq!(status[0].changed_files_count, 1);

    let b2 = convert_repo(&cfg).expect("incremental convert after same-second edit");
    assert!(
        !b2.cache_hit,
        "Expected INCREMENTAL SYNC, not CACHE HIT, after same-second edit"
    );
    assert_eq!(b2.metadata.incremental_reparsed_files, 1);
    assert_eq!(b2.metadata.incremental_reused_files, 1);
    let stamp_a_2 = b2
        .metadata
        .file_stamps
        .iter()
        .find(|s| s.rel_path == "src/a.py")
        .expect("updated stamp for src/a.py");
    assert_eq!(stamp_a_2.mtime_secs, 1_700_000_000);
    assert_eq!(stamp_a_2.mtime_nanos, 250_000_000);
    for s in &b2.metadata.file_stamps {
        assert!(s.mtime_nanos < 1_000_000_000);
    }

    let sym_out = chipsrc_core::query::query_symbols(
        std::slice::from_ref(&bundle_dir),
        "pm_match_new",
        None,
        false,
        10,
    )
    .expect("query_symbols pm_match_new");
    assert!(
        sym_out.contains("pm_match_new"),
        "Expected pm_match_new in symbol query output:\n{sym_out}"
    );

    // Sub-case (a): Legacy 2.0.0 manifest triggers one full rebuild, then CACHE HIT
    let manifest_path = bundle_dir.join("cache/manifest.json");
    let manifest_raw = fs::read_to_string(&manifest_path).unwrap();
    fs::write(
        &manifest_path,
        manifest_raw.replace("\"2.1.0\"", "\"2.0.0\""),
    )
    .unwrap();
    let b_legacy_manifest = convert_repo(&cfg).expect("rebuild after 2.0.0 manifest");
    assert!(
        !b_legacy_manifest.cache_hit,
        "Legacy 2.0.0 manifest must not CACHE HIT"
    );
    assert_eq!(b_legacy_manifest.metadata.incremental_reparsed_files, 2);
    assert_eq!(b_legacy_manifest.metadata.incremental_reused_files, 0);
    let b_after_manifest = convert_repo(&cfg).expect("warm after 2.0.0 manifest upgrade");
    assert!(b_after_manifest.cache_hit);

    // Sub-case (b): meta.json lacking mtime_nanos triggers one full rebuild, then CACHE HIT
    let meta_path = bundle_dir.join("meta.json");
    let meta_raw = fs::read_to_string(&meta_path).unwrap();
    let meta_without_nanos: String = meta_raw
        .lines()
        .filter(|line| !line.contains("\"mtime_nanos\""))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&meta_path, meta_without_nanos).unwrap();
    let b_legacy_meta = convert_repo(&cfg).expect("rebuild after missing mtime_nanos");
    assert!(
        !b_legacy_meta.cache_hit,
        "meta.json lacking mtime_nanos must not CACHE HIT"
    );
    let b_after_meta = convert_repo(&cfg).expect("warm after mtime_nanos upgrade");
    assert!(b_after_meta.cache_hit);
}

#[test]
fn incomplete_bundle_self_heals_and_no_sync_queries_error() {
    let tmp = TestTempDir::new("incomplete_bundle_e2e");
    let repo_dir = tmp.0.join("repo");
    let out_root = tmp.0.join("out");
    create_synthetic_repo(&repo_dir);

    let b1 = ensure_repo(&repo_dir, &out_root, false, VendorMode::Active).expect("initial ensure");
    assert!(!b1.cache_hit);
    let bundle_dir = b1.output_dir.clone();
    let bundles = [bundle_dir.clone()];
    assert!(chipsrc_core::scanner::bundle_artifacts_complete(
        &bundle_dir
    ));

    let sym_tsv_path = bundle_dir.join("index/symbols.tsv");
    let saved_sym_tsv = fs::read(&sym_tsv_path).expect("read symbols.tsv");

    // 1. Delete index/symbols.tsv -> workspace_status reports is_fresh=false with reason naming symbols.tsv
    fs::remove_file(&sym_tsv_path).unwrap();
    let status = workspace_status(&bundle_dir).expect("workspace_status");
    assert_eq!(status.len(), 1);
    assert!(
        !status[0].is_fresh,
        "Expected incomplete bundle to be stale"
    );
    let reason = status[0]
        .reason
        .as_deref()
        .expect("Expected non-empty reason on incomplete bundle");
    assert!(
        reason.contains("symbols.tsv"),
        "Expected reason to name symbols.tsv, got: {reason}"
    );

    // 2. Direct query (simulating --no-sync) fails with IncompleteBundle naming symbols.tsv
    let Err(err) = query_symbols(&bundles, "motor_set_duty", None, false, 10) else {
        panic!("Expected query_symbols on missing symbols.tsv to fail");
    };
    assert!(
        err.to_string().contains("symbols.tsv"),
        "Expected error message to name symbols.tsv, got: {err}"
    );

    // 2b. callers and callees (and JSON variants) on missing symbols.tsv must also fail with IncompleteBundle naming symbols.tsv
    let Err(callers_err) = query_callers(&bundles, "motor_set_duty", false, 10) else {
        panic!("Expected query_callers on missing symbols.tsv to fail");
    };
    assert!(
        callers_err.to_string().contains("symbols.tsv"),
        "Expected callers error to name symbols.tsv, got: {callers_err}"
    );
    let Err(callees_err) = query_callees(&bundles, "motor_set_duty", false, 10) else {
        panic!("Expected query_callees on missing symbols.tsv to fail");
    };
    assert!(
        callees_err.to_string().contains("symbols.tsv"),
        "Expected callees error to name symbols.tsv, got: {callees_err}"
    );
    let Err(callers_json_err) =
        query_subcommand_json("callers", &bundles, "motor_set_duty", None, None, 3, 10)
    else {
        panic!("Expected query_subcommand_json callers on missing symbols.tsv to fail");
    };
    assert!(
        callers_json_err.to_string().contains("symbols.tsv"),
        "Expected callers JSON error to name symbols.tsv, got: {callers_json_err}"
    );

    // 3. ensure_repo repairs the missing TSV identically and next ensure_repo is CACHE HIT
    let b_repaired =
        ensure_repo(&repo_dir, &out_root, false, VendorMode::Active).expect("repair ensure");
    assert!(
        !b_repaired.cache_hit,
        "Repair run must not report CACHE HIT"
    );
    assert_eq!(
        fs::read(&sym_tsv_path).expect("restored symbols.tsv"),
        saved_sym_tsv
    );

    let b_warm = ensure_repo(&repo_dir, &out_root, false, VendorMode::Active).expect("warm ensure");
    assert!(
        b_warm.cache_hit,
        "Run following repair must be a CACHE HIT (no permanent rebuild loop)"
    );

    // 3b. Truncate index/symbols.tsv to 0 bytes -> status reports stale, queries fail, ensure regenerates, next run CACHE HIT
    fs::write(&sym_tsv_path, b"").unwrap();
    let status_zero = workspace_status(&bundle_dir).expect("workspace_status 0-byte TSV");
    assert_eq!(status_zero.len(), 1);
    assert!(
        !status_zero[0].is_fresh,
        "Expected bundle with 0-byte symbols.tsv to be stale"
    );
    assert!(
        status_zero[0]
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("symbols.tsv"),
        "Expected reason to name symbols.tsv, got: {:?}",
        status_zero[0].reason
    );
    let Err(callers_zero_err) = query_callers(&bundles, "motor_set_duty", false, 10) else {
        panic!("Expected query_callers on 0-byte symbols.tsv to fail");
    };
    assert!(callers_zero_err.to_string().contains("symbols.tsv"));

    let b_zero_repaired = ensure_repo(&repo_dir, &out_root, false, VendorMode::Active)
        .expect("repair 0-byte symbols.tsv");
    assert!(
        !b_zero_repaired.cache_hit,
        "0-byte symbols.tsv must be regenerated, not CACHE HIT"
    );
    assert_eq!(
        fs::read(&sym_tsv_path).expect("restored symbols.tsv after 0-byte"),
        saved_sym_tsv
    );
    let b_zero_warm = ensure_repo(&repo_dir, &out_root, false, VendorMode::Active)
        .expect("warm ensure after 0-byte repair");
    assert!(
        b_zero_warm.cache_hit,
        "Run following 0-byte TSV repair must be CACHE HIT"
    );

    // 4. Delete a cache/<hash>.json shard -> ensure repairs and next run is CACHE HIT
    let manifest = chipsrc_core::scanner::load_cache_manifest(&bundle_dir).expect("manifest");
    let shard_rel = manifest.files.values().next().unwrap().shard.clone();
    fs::remove_file(bundle_dir.join(&shard_rel)).unwrap();
    assert!(!chipsrc_core::scanner::bundle_artifacts_complete(
        &bundle_dir
    ));

    let b_shard_repair =
        ensure_repo(&repo_dir, &out_root, false, VendorMode::Active).expect("shard repair");
    assert!(!b_shard_repair.cache_hit);
    assert!(bundle_dir.join(&shard_rel).is_file());
    let b_shard_warm =
        ensure_repo(&repo_dir, &out_root, false, VendorMode::Active).expect("shard warm");
    assert!(b_shard_warm.cache_hit);

    // 5. Delete index/symbols.tsv -> auto_refresh_bundles repairs it before querying
    fs::remove_file(&sym_tsv_path).unwrap();
    let refreshed = auto_refresh_bundles(&bundles).expect("auto_refresh_bundles");
    assert_eq!(refreshed, 1);
    assert!(sym_tsv_path.is_file());
    let sym_out = query_symbols(&bundles, "motor_set_duty", None, false, 10)
        .expect("query after auto_refresh");
    assert!(sym_out.contains("motor_set_duty"));
}

#[test]
fn bundle_lock_and_atomic_writes_end_to_end() {
    let tmp = TestTempDir::new("lock_atomic_e2e");
    let repo_dir = tmp.0.join("repo");
    let out_root = tmp.0.join("out");
    create_synthetic_repo(&repo_dir);

    let b1 = ensure_repo(&repo_dir, &out_root, false, VendorMode::Active).expect("initial ensure");
    let bundle_dir = b1.output_dir.clone();
    let bundles = [bundle_dir.clone()];
    let lock_path = bundle_dir.join("cache/.lock");
    assert!(
        !lock_path.exists(),
        "No lock file should remain after ensure_repo"
    );

    // Edit src/app/main.c so the bundle becomes stale
    let main_c = repo_dir.join("src/app/main.c");
    let orig_main = fs::read_to_string(&main_c).unwrap();
    fs::write(
        &main_c,
        format!("{orig_main}\nvoid locked_probe_fn(void) {{ motor_set_duty(1); }}\n"),
    )
    .unwrap();
    set_file_mtime(&main_c, 1_800_000_000, 0);

    // Hold a live foreign lock on cache/.lock
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    fs::write(&lock_path, format!("999999:{now_ms}\n")).unwrap();

    // 1. auto_refresh_bundles waits <=150ms, skips refresh, leaves lock intact
    let t_auto = Instant::now();
    let refreshed = auto_refresh_bundles(&bundles).expect("auto_refresh_bundles under held lock");
    assert_eq!(
        refreshed, 0,
        "auto_refresh_bundles must skip refresh when cache/.lock is held"
    );
    assert!(t_auto.elapsed() < Duration::from_millis(1500));
    assert!(
        lock_path.is_file(),
        "Foreign cache/.lock must remain untouched"
    );

    // 2. convert_repo with auto_sync=true (used by hook post-edit) also returns BundleLocked within <=150ms
    let mut cfg = ConvertConfig::new(repo_dir.clone(), bundle_dir.clone());
    cfg.auto_sync = true;
    let hook_res = convert_repo(&cfg);
    assert!(
        matches!(hook_res, Err(ChipsrcError::BundleLocked { .. })),
        "convert_repo(auto_sync=true) must return BundleLocked when cache/.lock is held"
    );
    let status_locked = workspace_status(&bundle_dir).expect("status while locked");
    assert!(
        !status_locked[0].is_fresh,
        "Bundle must still be stale while locked"
    );

    // 3. Stale lock (>10s old) is removed and ensure_repo succeeds immediately
    set_file_mtime(&lock_path, 1_700_000_000, 0);
    let b2 = ensure_repo(&repo_dir, &out_root, false, VendorMode::Active)
        .expect("ensure_repo reclaims stale lock");
    assert!(!b2.cache_hit);
    assert!(!lock_path.exists(), "cache/.lock must be removed on Drop");

    let sym_out =
        query_symbols(&bundles, "locked_probe_fn", None, false, 10).expect("query locked_probe_fn");
    assert!(sym_out.contains("locked_probe_fn"));
}

/// SYNC-SCRUT-007: `workspace_status` parses `cache/manifest.json` once and feeds the same parsed
/// copy to both the artifact-integrity gate and the cache-presence/fallback paths.
#[test]
fn workspace_status_reuses_one_parsed_manifest() {
    let tmp = TestTempDir::new("status_manifest_once");
    let repo_dir = tmp.0.join("repo");
    let out_root = tmp.0.join("out");
    create_synthetic_repo(&repo_dir);

    let bundle =
        ensure_repo(&repo_dir, &out_root, false, VendorMode::Active).expect("initial ensure");
    let bundle_dir = bundle.output_dir.clone();
    let status = workspace_status(&bundle_dir).expect("fresh status");
    assert_eq!(status.len(), 1);
    assert!(status[0].is_fresh, "fresh bundle: {:?}", status[0].reason);
    assert_eq!(status[0].source_root, bundle.metadata.source_root);

    // The manifest is present and current, but a required TSV is missing: the artifact gate must
    // report the missing table (not a cache problem) using the pre-parsed manifest.
    let symbols_tsv = bundle_dir.join("index/symbols.tsv");
    let saved = fs::read(&symbols_tsv).expect("read symbols.tsv");
    fs::remove_file(&symbols_tsv).unwrap();
    let missing_table = workspace_status(&bundle_dir).expect("status missing table");
    assert!(!missing_table[0].is_fresh);
    let reason = missing_table[0].reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("index/symbols.tsv"),
        "expected missing symbols.tsv reason, got {reason:?}"
    );

    // With `meta.json` gone, the same parsed manifest must still supply the source root and the
    // bundle must be reported stale (reason names meta.json).
    fs::write(&symbols_tsv, saved).expect("restore symbols.tsv");
    let meta_path = bundle_dir.join("meta.json");
    // A complete bundle is fresh again after restoring the table.
    assert!(workspace_status(&bundle_dir).expect("status restored")[0].is_fresh);
    fs::remove_file(&meta_path).unwrap();
    let missing_meta = workspace_status(&bundle_dir).expect("status missing meta");
    assert_eq!(missing_meta.len(), 1);
    assert!(!missing_meta[0].is_fresh);
    assert!(
        !missing_meta[0].source_root.is_empty(),
        "source_root must be recovered from cache/manifest.json"
    );
    let reason = missing_meta[0].reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("meta.json"),
        "expected missing meta.json reason, got {reason:?}"
    );
}

/// SYNC-SCRUT-013: a leading-underscore Unicode macro name must never panic the peripheral
/// normalization path. `#define _abcé 1` trims to the five-byte `abcé`, which used to be sliced at
/// byte index 4 (inside `é`) by `strip_periph_instance_slice`.
#[test]
fn unicode_macro_name_query_never_panics() {
    let tmp = TestTempDir::new("unicode_macro");
    let repo_dir = tmp.0.join("repo");
    fs::create_dir_all(repo_dir.join("src")).expect("create src dir");
    fs::write(
        repo_dir.join("src/config.h"),
        "#ifndef CONFIG_H\n#define CONFIG_H\n\n#define _abcé 1\n#define ČEŠTINA_CONFIG 2\n\n#endif\n",
    )
    .expect("write source");
    let out_root = tmp.0.join("out");
    let bundle = ensure_repo(&repo_dir, &out_root, false, VendorMode::Active).expect("ensure_repo");
    let bundles: Vec<PathBuf> = vec![bundle.output_dir.clone()];

    for query in ["_abcé", "abcé", "ČEŠTINA_CONFIG", "ČEŠTINA"] {
        let text = query_macros(&bundles, query, false, 10)
            .unwrap_or_else(|err| panic!("text query {query:?} failed: {err}"));
        assert!(
            text.contains(query),
            "text query {query:?} must return the macro row, got: {text}"
        );

        let json = query_subcommand_json("macro", &bundles, query, None, None, 3, 10)
            .unwrap_or_else(|err| panic!("json query {query:?} failed: {err}"));
        let rows: serde_json::Value =
            serde_json::from_str(&json).unwrap_or_else(|err| panic!("json parse {query:?}: {err}"));
        let names: Vec<String> = rows
            .as_array()
            .expect("macro JSON must be an array")
            .iter()
            .filter_map(|row| row.get("name").and_then(|n| n.as_str()))
            .map(str::to_string)
            .collect();
        assert!(
            names.iter().any(|name| name.contains(query)),
            "json query {query:?} must return the macro row, got {names:?}"
        );
    }
}

/// P2.1 (VAL-NOISE-007): a synthetic multi-language probe that pins both structural call-noise
/// rules and their non-pruning boundaries through the real parsers.
///
/// Rule 1 drops unresolved receiver calls whose short name is defined by no non-Test symbol
/// (`store.flush`, `logger.info`); rule 2 drops bare Rust `PascalCase(...)` constructor calls with
/// no callable definition (`Wrapper`). Bare Python builtins, bare unqualified C calls, defined
/// receiver methods, and already-resolved calls all survive.
#[test]
fn noise_probe_rules_end_to_end() {
    let tmp = TestTempDir::new("noise_probe");
    let repo_dir = tmp.0.join("noise-probe");
    fs::create_dir_all(repo_dir.join("app")).expect("create app dir");
    fs::create_dir_all(repo_dir.join("hal")).expect("create hal dir");
    fs::create_dir_all(repo_dir.join("src")).expect("create src dir");

    fs::write(
        repo_dir.join("app/models.py"),
        "class Store:\n    def commit(self):\n        return 1\n\ndef helper(value):\n    return value\n",
    )
    .expect("write models.py");
    fs::write(
        repo_dir.join("app/uses.py"),
        "def run(store, logger):\n    store.commit()\n    store.flush()\n    logger.info(\"noise\")\n    helper(1)\n    print(\"builtin\")\n    len([1])\n",
    )
    .expect("write uses.py");
    fs::write(
        repo_dir.join("hal/board.c"),
        "extern int vendor_undef(int);\nvoid board_entry(void) { vendor_undef(3); malloc(8); }\n",
    )
    .expect("write board.c");
    fs::write(
        repo_dir.join("src/lib.rs"),
        "pub fn real_fn() -> u8 { 7 }\npub fn use_it() -> u8 { let wrapper = Wrapper(3); real_fn() }\n",
    )
    .expect("write lib.rs");

    // `hal/` is detected as a vendor-HAL directory, so `--vendor-mode all` is required to parse
    // it; the noise rules themselves are what this test pins.
    let mut cfg = ConvertConfig::new(repo_dir.clone(), tmp.0.join("out"));
    cfg.vendor_mode = VendorMode::All;
    let bundle = convert_repo(&cfg).expect("convert noise probe");

    let calls_tsv = fs::read_to_string(bundle.output_dir.join("index").join("calls.tsv"))
        .expect("read calls.tsv");
    let rows: Vec<Vec<&str>> = calls_tsv
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split('\t').collect())
        .collect();
    let find = |file: &str, callee: &str| -> Option<&Vec<&str>> {
        rows.iter().find(|row| row[4] == file && row[2] == callee)
    };

    // (1) Rust bare PascalCase constructor noise is pruned.
    assert!(
        find("src/lib.rs", "Wrapper").is_none(),
        "rule 2 must drop the bare Rust `Wrapper(3)` constructor call"
    );
    // (2) Python receiver-method noise is pruned.
    for callee in ["flush", "info"] {
        assert!(
            find("app/uses.py", callee).is_none(),
            "rule 1 must drop the undefined receiver method `{callee}`"
        );
    }
    // (3) Bare Python builtins stay as external edges.
    for callee in ["print", "len"] {
        let row = find("app/uses.py", callee)
            .unwrap_or_else(|| panic!("bare Python builtin `{callee}` must be kept"));
        assert_eq!(row[6], "external_or_macro");
    }
    // (4) Unqualified C externals stay untouched.
    for callee in ["vendor_undef", "malloc"] {
        let row = find("hal/board.c", callee)
            .unwrap_or_else(|| panic!("unqualified C external `{callee}` must be kept"));
        assert_eq!(row[6], "external_or_macro");
    }
    // (5) A receiver method whose name exists in the repository stays.
    let commit = find("app/uses.py", "commit").expect("defined receiver method `commit` kept");
    assert_eq!(commit[3], "app/models.py::Store::commit");
    // (6) Resolved calls keep resolving.
    assert_eq!(
        find("app/uses.py", "helper").expect("helper resolved")[6],
        "unique_global"
    );
    assert_eq!(
        find("src/lib.rs", "real_fn").expect("real_fn resolved")[6],
        "same_file"
    );

    // Baseline probe resolution ratio was 3 resolved / 10 edges = 0.375.
    assert!(
        bundle.sanity.call_resolution_ratio > 0.375,
        "pruning must raise call_resolution_ratio, got {}",
        bundle.sanity.call_resolution_ratio
    );
    assert!(
        !bundle
            .indexes
            .xrefs
            .iter()
            .any(|x| x.category == "call" && x.symbol == "info"),
        "pruned call must not leave an xref row behind"
    );
}

/// INT-SCRUT-009/010: the four scrutiny round-2 C++ probes keep every uppercase callable and call
/// edge through the full convert pipeline, with a clean parse.
#[test]
fn uppercase_cpp_probes_preserve_symbols_and_calls_end_to_end() {
    let base = TestTempDir::new("chipsrc_uppercase_probes");
    let probes: [(&str, &str); 4] = [
        (
            "uppercase-const",
            "class Device {\npublic:\n    void TX() const {}\n};\nvoid caller(const Device& device) { device.TX(); }\n",
        ),
        (
            "uppercase-out-of-line",
            "class IO {\npublic:\n    IO();\n    ~IO();\n};\nIO::IO() {}\nIO::~IO() {}\n",
        ),
        (
            "uppercase-conditional",
            "void TX() {}\nvoid caller(bool flag) {\n    if (flag) TX();\n    else TX();\n}\n",
        ),
        (
            "uppercase-args",
            "void TX(const char* text) {}\nvoid caller() {\n    TX(\"x;y\");\n    TX(\"a(b c)\");\n    TX(';');\n    TX(/* ; */ 1);\n}\n",
        ),
    ];

    for (name, source) in probes {
        let repo_dir = base.0.join(name);
        fs::create_dir_all(&repo_dir).expect("create probe dir");
        fs::write(repo_dir.join("test.cpp"), source).expect("write probe source");
        let bundle_dir = base.0.join(format!("{name}-bundle"));
        let cfg = ConvertConfig::new(repo_dir, bundle_dir.clone());
        let bundle = convert_repo(&cfg).unwrap_or_else(|e| panic!("convert {name}: {e}"));

        assert_eq!(
            bundle.sanity.parse_clean_ratio, 1.0,
            "{name} must parse cleanly: {:?}",
            bundle.sanity.warnings
        );

        let symbols = fs::read_to_string(bundle_dir.join("index").join("symbols.tsv"))
            .unwrap_or_else(|e| panic!("read {name} symbols.tsv: {e}"));
        let calls = fs::read_to_string(bundle_dir.join("index").join("calls.tsv"))
            .unwrap_or_else(|e| panic!("read {name} calls.tsv: {e}"));
        let call_callees: Vec<&str> = calls
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| line.split('\t').nth(2))
            .collect();

        match name {
            "uppercase-const" => {
                assert!(
                    symbols.contains("Device::TX"),
                    "Device::TX symbol missing: {symbols}"
                );
                assert!(
                    call_callees.contains(&"TX"),
                    "caller -> device.TX edge missing: {calls}"
                );
            }
            "uppercase-out-of-line" => {
                assert!(
                    symbols.contains("IO::IO") && symbols.contains("~IO"),
                    "out-of-line IO::IO / IO::~IO symbols missing: {symbols}"
                );
                assert_eq!(bundle.indexes.symbols.len(), 2, "{}", symbols);
            }
            "uppercase-conditional" => {
                assert!(
                    call_callees.iter().filter(|c| **c == "TX").count() >= 2,
                    "if/else TX call edges missing: {calls}"
                );
            }
            "uppercase-args" => {
                assert!(
                    call_callees.iter().filter(|c| **c == "TX").count() >= 4,
                    "literal/comment argument TX call edges missing: {calls}"
                );
            }
            _ => unreachable!("unexpected probe {name}"),
        }
    }
}

/// End-to-end BM25 concept search on a converted bundle: snake_case sub-token ranking, the
/// automatic multi-token fallback, `--source` gating, and nonsense-query emptiness.
#[test]
fn concept_search_ranks_sub_tokens_and_gates_fallback_on_converted_repo() {
    let base = TestTempDir::new("concept_e2e");
    let repo_dir = base.0.join("synth_concept");
    let bundle_dir = base.0.join("bundle");
    create_synthetic_repo(&repo_dir);
    let cfg = ConvertConfig::new(repo_dir, bundle_dir.clone());
    convert_repo(&cfg).expect("convert synthetic repo");
    let bundles = vec![bundle_dir];

    // `motor_set_duty` sub-tokens (motor, set, duty) must rank through the concept index even
    // though the spaced phrase never appears in the TSV rows or the sources.
    let concept = parallel_bundle_search(&bundles, "motor set duty", "concept", false, 10)
        .expect("concept search");
    assert!(
        concept
            .iter()
            .take(5)
            .any(|h| h.snippet.starts_with("motor_set_duty — ")),
        "expected motor_set_duty in the top 5: {concept:?}"
    );
    assert!(concept
        .iter()
        .all(|h| matches!(h.kind.as_str(), "symbol" | "type" | "macro")));

    let fallback = parallel_bundle_search(&bundles, "motor set duty", "all", false, 10)
        .expect("concept fallback");
    assert_eq!(
        fallback, concept,
        "zero-hit literal queries fall back to BM25"
    );

    assert!(
        parallel_bundle_search(&bundles, "motor set duty", "source", false, 10)
            .expect("source gating")
            .is_empty()
    );
    assert!(
        parallel_bundle_search(&bundles, "quuxblorp wibbleflop", "all", false, 10)
            .expect("nonsense query")
            .is_empty(),
        "nonsense multi-token queries must stay empty"
    );
}

#[test]
fn header_language_detection_ab_probes_and_incremental_parity() {
    let base = TestTempDir::new("chipsrc_header_lang");
    let c_probe = base.0.join("c-probe");
    let cpp_probe = base.0.join("cpp-probe");
    fs::create_dir_all(&c_probe).unwrap();
    fs::create_dir_all(&cpp_probe).unwrap();

    // (a) C probe: every C++ keyword lives in a comment or a string literal.
    fs::write(
        c_probe.join("plain.h"),
        r#"/* class Fake; template <typename T>; namespace demo; public:; ns::thing */
// virtual nullptr constexpr operator
static const char *s = "class Fake; namespace demo; template<typename T>";
typedef struct { int raw; } plain_sample_t;
int plain_compute(plain_sample_t *s, int x);
"#,
    )
    .unwrap();
    fs::write(
        c_probe.join("plain.c"),
        "#include \"plain.h\"\n\nint plain_compute(plain_sample_t *s, int x) {\n    return s->raw + x;\n}\n",
    )
    .unwrap();

    // (b) C++ probe: real C++ constructs in code.
    fs::write(
        cpp_probe.join("demo.h"),
        "namespace demo {\ntemplate <typename T>\nclass Box {\npublic:\n    T value;\n    T get() const;\n};\n}\n",
    )
    .unwrap();
    fs::write(cpp_probe.join("helper.py"), "def helper():\n    return 1\n").unwrap();

    let language_files = |report: &chipsrc_core::InspectReport, lang: &str| {
        report
            .languages
            .iter()
            .find(|l| l.language == lang)
            .map(|l| l.files)
            .unwrap_or(0)
    };

    // A: the C probe stays C (2 files) and never produces a cpp entry.
    let c_report = inspect_repo(&c_probe, VendorMode::Active).expect("inspect c-probe");
    assert_eq!(
        language_files(&c_report, "c"),
        2,
        "{:?}",
        c_report.languages
    );
    assert_eq!(language_files(&c_report, "cpp"), 0);

    let c_bundle_dir = base.0.join("c-bundle");
    convert_repo(&ConvertConfig::new(c_probe.clone(), c_bundle_dir.clone()))
        .expect("convert c-probe");
    let c_bundles = vec![c_bundle_dir];
    let sym_out =
        query_symbols(&c_bundles, "plain_compute", None, false, 10).expect("query plain_compute");
    assert!(
        sym_out.contains("plain_compute"),
        "plain_compute must be indexed: {sym_out}"
    );
    let type_out =
        query_types(&c_bundles, "plain_sample_t", false, 10).expect("query plain_sample_t");
    assert!(
        type_out.contains("plain_sample_t"),
        "plain_sample_t must be indexed: {type_out}"
    );

    // B: the C++ probe is reported as cpp only, and the class template is extracted.
    let cpp_report = inspect_repo(&cpp_probe, VendorMode::Active).expect("inspect cpp-probe");
    assert_eq!(
        language_files(&cpp_report, "cpp"),
        1,
        "{:?}",
        cpp_report.languages
    );
    assert_eq!(language_files(&cpp_report, "c"), 0);

    let cpp_bundle_dir = base.0.join("cpp-bundle");
    let cpp_bundle = convert_repo(&ConvertConfig::new(
        cpp_probe.clone(),
        cpp_bundle_dir.clone(),
    ))
    .expect("convert cpp-probe");
    assert_eq!(
        cpp_bundle
            .metadata
            .languages
            .iter()
            .find(|l| l.language == "cpp")
            .map(|l| l.files),
        Some(1)
    );
    assert!(cpp_bundle
        .metadata
        .languages
        .iter()
        .all(|l| l.language != "c"));
    let cpp_bundles = [cpp_bundle_dir.clone()];
    let type_out = query_types(&cpp_bundles, "Box", false, 10).expect("query Box type");
    assert!(type_out.contains("pub class `Box`"), "{type_out}");
    assert!(type_out.contains("demo.h:3"), "{type_out}");
    assert!(
        type_out.contains("demo.h::demo::Box"),
        "namespace-qualified type_id expected: {type_out}"
    );
    let qualified_type_out =
        query_types(&cpp_bundles, "demo::Box", false, 10).expect("query demo::Box type");
    assert!(
        qualified_type_out.contains("demo.h::demo::Box"),
        "namespace-qualified lookup expected: {qualified_type_out}"
    );

    // Unrelated edit -> the incremental (stat-only) path must keep the recorded header language,
    // so the language breakdown of the refreshed bundle equals the full build's.
    fs::write(cpp_probe.join("helper.py"), "def helper():\n    return 2\n").unwrap();
    let t = std::time::UNIX_EPOCH + Duration::new(1_700_000_000, 500_000_000);
    std::fs::OpenOptions::new()
        .write(true)
        .open(cpp_probe.join("helper.py"))
        .unwrap()
        .set_modified(t)
        .unwrap();
    let refreshed = convert_repo(&ConvertConfig::new(
        cpp_probe.clone(),
        cpp_bundle_dir.clone(),
    ))
    .expect("incremental convert cpp-probe");
    assert!(
        !refreshed.cache_hit,
        "editing helper.py must not be a cache hit"
    );
    assert_eq!(
        refreshed.metadata.languages, cpp_bundle.metadata.languages,
        "incremental language counts must match the full build"
    );
    let demo_stamp = refreshed
        .metadata
        .file_stamps
        .iter()
        .find(|s| s.rel_path == "demo.h")
        .expect("demo.h stamp");
    assert_eq!(demo_stamp.language, Some(LanguageKind::Cpp));
}

/// INT-SCRUT-002: an edit that flips a `.h` header's detected language (C -> C++) must never take
/// the digest-no-op (or coordinate-shift) short circuit, and the incrementally refreshed rendered
/// artifacts must equal a forced rebuild.
#[test]
fn header_language_change_matches_forced_rebuild() {
    let base = TestTempDir::new("chipsrc_header_lang_change");
    let repo = base.0.join("repo");
    fs::create_dir_all(&repo).unwrap();
    let header = repo.join("demo.h");
    fs::write(&header, "\nint compute(void) { return 1; }\n").unwrap();

    let bundle_dir = base.0.join("bundle");
    let initial = convert_repo(&ConvertConfig::new(repo.clone(), bundle_dir.clone()))
        .expect("initial convert");
    assert_eq!(
        initial
            .metadata
            .file_stamps
            .iter()
            .find(|s| s.rel_path == "demo.h")
            .and_then(|s| s.language),
        Some(LanguageKind::C)
    );

    let sections_text = |dir: &Path| -> String {
        let mut bodies: Vec<String> = fs::read_dir(dir.join("sections"))
            .expect("sections dir")
            .map(|entry| fs::read_to_string(entry.expect("section entry").path()).unwrap())
            .collect();
        bodies.sort();
        bodies.join("\n")
    };
    let c_sections = sections_text(&bundle_dir);
    assert!(c_sections.contains("`c`"), "{c_sections}");
    assert!(!c_sections.contains("`cpp`"), "{c_sections}");

    // Same line count and identical symbol coordinates: only the detected language flips.
    fs::write(
        &header,
        "namespace demo {}\nint compute(void) { return 1; }\n",
    )
    .unwrap();
    let refreshed = convert_repo(&ConvertConfig::new(repo.clone(), bundle_dir.clone()))
        .expect("incremental convert");
    assert!(!refreshed.cache_hit);
    assert_ne!(
        refreshed.metadata.incremental_tier, "digest_noop",
        "a detected-language change must not short-circuit as digest-noop"
    );
    assert_ne!(refreshed.metadata.incremental_tier, "coordinate_shift");
    assert_eq!(
        refreshed
            .metadata
            .file_stamps
            .iter()
            .find(|s| s.rel_path == "demo.h")
            .and_then(|s| s.language),
        Some(LanguageKind::Cpp)
    );

    let incremental_sections = sections_text(&bundle_dir);
    assert!(
        incremental_sections.contains("`cpp`"),
        "incrementally refreshed section must render the detected language: {incremental_sections}"
    );
    assert!(
        !incremental_sections.contains("`c`"),
        "{incremental_sections}"
    );

    let mut forced = ConvertConfig::new(repo.clone(), bundle_dir.clone());
    forced.force = true;
    convert_repo(&forced).expect("forced convert");
    assert_eq!(
        sections_text(&bundle_dir),
        incremental_sections,
        "incremental and forced section artifacts must be identical"
    );
}
