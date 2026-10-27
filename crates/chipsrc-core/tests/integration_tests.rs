//! End-to-end integration tests for `chipsrc-core`.

use chipsrc_core::query::{
    parallel_bundle_search, query_callees, query_callers, query_macros, query_sections,
    query_symbols, query_types, query_xref, workspace_status,
};
use chipsrc_core::{
    auto_refresh_bundles, convert_repo, ensure_repo, inspect_repo, BundleMetaFile, ConvertConfig,
    VendorMode,
};
use std::fs;
use std::path::{Path, PathBuf};

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
    let base = std::env::temp_dir().join(format!("chipsrc_integ_test_{}", std::process::id()));
    let repo_dir = base.join("synth_fw");
    let output_root = base.join("output");
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

    // Verify all emitted files exist
    assert!(bundle_dir.join("INDEX.md").is_file());
    assert!(bundle_dir.join("meta.json").is_file());
    assert!(bundle_dir.join("cache.json").is_file());
    assert!(bundle_dir.join("synth_fw.md").is_file());
    assert!(base.join(".claudeignore").is_file());

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

    let _ = fs::remove_dir_all(&base);
}
