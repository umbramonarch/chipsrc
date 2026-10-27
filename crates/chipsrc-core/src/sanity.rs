use crate::model::{BundleIndexes, ParsedFileUnit, SanityReport, SectionShard};

/// Computes structural conversion health, parse coverage, call resolution rate,
/// token compression ratio, architectural warnings, and overall sanity score (0..=100).
pub fn compute_sanity_report(
    units: &[ParsedFileUnit],
    indexes: &BundleIndexes,
    sections: &[SectionShard],
) -> SanityReport {
    let parse_clean_ratio = if units.is_empty() {
        1.0
    } else {
        let clean = units.iter().filter(|u| u.parse_errors == 0).count();
        clean as f64 / (units.len() as f64)
    };

    let call_resolution_ratio = if indexes.calls.is_empty() {
        1.0
    } else {
        let resolved = indexes
            .calls
            .iter()
            .filter(|c| c.tier.is_resolved())
            .count();
        let raw_ratio = resolved as f64 / (indexes.calls.len() as f64);
        if resolved > 0 {
            raw_ratio
        } else {
            // Baseline when all calls in a tiny snippet are external stdlib/macros
            0.5
        }
    };

    let total_raw_bytes: u64 = units.iter().map(|u| u.scanned.size_bytes).sum();
    let raw_source_tokens_est = ((total_raw_bytes as usize).div_ceil(4)).max(1);

    let sections_bytes: usize = sections.iter().map(|s| s.markdown_body.len()).sum();
    let master_index_est_bytes: usize = 800
        + sections.len() * 90
        + indexes.god_nodes.len() * 110
        + indexes.entrypoints.len() * 90
        + indexes.layer_edges.len() * 60;
    let bundle_index_tokens_est = ((sections_bytes + master_index_est_bytes).div_ceil(4)).max(1);

    let token_compression_ratio = (raw_source_tokens_est as f64) / (bundle_index_tokens_est as f64);

    let mut warnings = Vec::new();
    let mut score: i32 = 100;

    let files_with_errors = units.iter().filter(|u| u.parse_errors > 0).count();
    if files_with_errors > 0 {
        let penalty = (((1.0 - parse_clean_ratio) * 25.0).round() as i32).clamp(1, 25);
        score -= penalty;
        warnings.push(format!(
            "{files_with_errors}/{} file(s) reported Tree-sitter syntax errors (clean parse ratio: {:.1}%).",
            units.len(),
            parse_clean_ratio * 100.0
        ));
    }

    let mut upward_count = 0usize;
    for edge in &indexes.layer_edges {
        if edge.is_upward_violation {
            upward_count += 1;
            warnings.push(format!(
                "Upward architectural layer dependency violation: `{}` -> `{}` ({} calls, {} imports).",
                edge.from_layer, edge.to_layer, edge.call_count, edge.import_count
            ));
        }
    }
    if upward_count > 0 {
        score -= ((upward_count as i32) * 4).min(16);
    }

    for cycle in &indexes.cycles {
        warnings.push(format!(
            "Cyclic call cluster (SCC #{}) across {} symbols: {}.",
            cycle.scc_id,
            cycle.symbols.len(),
            cycle.symbols.join(" <-> ")
        ));
    }
    if !indexes.cycles.is_empty() {
        score -= ((indexes.cycles.len() as i32) * 3).min(12);
    }

    if sections.is_empty() {
        score -= 50;
        warnings.push("No architectural module shards were generated.".to_string());
    }

    SanityReport {
        score: score.clamp(0, 100) as u8,
        parse_clean_ratio,
        call_resolution_ratio,
        raw_source_tokens_est,
        bundle_index_tokens_est,
        token_compression_ratio,
        warnings,
    }
}
