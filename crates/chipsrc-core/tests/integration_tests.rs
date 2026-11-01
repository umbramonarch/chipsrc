//! End-to-end integration tests for `chipsrc-core`.

use chipsrc_core::query::{
    parallel_bundle_search, query_call_path, query_callees, query_callers, query_impact,
    query_macros, query_sections, query_symbols, query_types, query_xref, workspace_status,
};
use chipsrc_core::{
    auto_refresh_bundles, convert_repo, ensure_repo, inspect_repo, ArchLayer, BundleMetaFile,
    ConvertConfig, FileScope, MacroKind, ResolutionTier, SymbolKind, VendorMode,
};
use std::fs;
use std::path::{Path, PathBuf};

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
    let err = query_symbols(
        std::slice::from_ref(&bundle_dir),
        "motor_set_duty",
        None,
        false,
        10,
    )
    .expect_err("Expected query_symbols on missing symbols.tsv to fail");
    assert!(
        err.to_string().contains("symbols.tsv"),
        "Expected error message to name symbols.tsv, got: {err}"
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
    let refreshed =
        auto_refresh_bundles(std::slice::from_ref(&bundle_dir)).expect("auto_refresh_bundles");
    assert_eq!(refreshed, 1);
    assert!(sym_tsv_path.is_file());
    let sym_out = query_symbols(
        std::slice::from_ref(&bundle_dir),
        "motor_set_duty",
        None,
        false,
        10,
    )
    .expect("query after auto_refresh");
    assert!(sym_out.contains("motor_set_duty"));
}
