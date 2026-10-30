use crate::model::{BundleIndexes, FileScope, ParsedFileUnit, SanityReport, SectionShard};

/// Computes structural conversion health, parse coverage, call resolution rate,
/// token compression ratio, architectural warnings, and overall sanity score (0..=100).
pub fn compute_sanity_report(
    units: &[ParsedFileUnit],
    indexes: &BundleIndexes,
    sections: &[SectionShard],
) -> SanityReport {
    let primary_units: Vec<&ParsedFileUnit> = {
        let non_vendor: Vec<&ParsedFileUnit> = units
            .iter()
            .filter(|u| u.scanned.scope != FileScope::VendorSdk)
            .collect();
        if non_vendor.is_empty() {
            units.iter().collect()
        } else {
            non_vendor
        }
    };

    let parse_clean_ratio = if primary_units.is_empty() {
        1.0
    } else {
        let clean = primary_units.iter().filter(|u| u.parse_errors == 0).count();
        clean as f64 / (primary_units.len() as f64)
    };

    let call_resolution_ratio = if indexes.calls.is_empty() {
        1.0
    } else {
        let resolved = indexes
            .calls
            .iter()
            .filter(|c| c.tier.is_high_confidence())
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

    let error_files: Vec<&str> = primary_units
        .iter()
        .filter(|u| u.parse_errors > 0)
        .map(|u| u.scanned.rel_path.as_str())
        .collect();
    let files_with_errors = error_files.len();
    if files_with_errors > 0 {
        let penalty = (((1.0 - parse_clean_ratio) * 25.0).round() as i32).clamp(1, 25);
        score -= penalty;
        let sample_paths: Vec<&str> = error_files.iter().copied().take(5).collect();
        let suffix = if files_with_errors > 5 {
            format!(
                "{} (+{} more)",
                sample_paths.join(", "),
                files_with_errors - 5
            )
        } else {
            sample_paths.join(", ")
        };
        warnings.push(format!(
            "{files_with_errors}/{} file(s) reported Tree-sitter syntax errors (clean parse ratio: {:.1}%): {suffix}.",
            primary_units.len(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ArchLayer, CyclicCluster, LanguageKind, LayerDependencyEdge, ResolutionTier,
        ResolvedCallEdge, ScannedFile, SectionSummary, VendorSurfaceSummary,
    };
    use std::path::PathBuf;

    fn sample_unit(rel_path: &str, parse_errors: usize) -> ParsedFileUnit {
        ParsedFileUnit {
            scanned: ScannedFile {
                rel_path: rel_path.to_string(),
                abs_path: PathBuf::from(rel_path),
                language: LanguageKind::C,
                scope: FileScope::FirstParty,
                arch_layer: ArchLayer::Drivers,
                size_bytes: 1024,
                mtime_secs: 0,
                blake3_hash: "hash".to_string(),
                line_count: 40,
            },
            symbols: Vec::new(),
            types: Vec::new(),
            macros: Vec::new(),
            imports: Vec::new(),
            raw_calls: Vec::new(),
            raw_xrefs: Vec::new(),
            parse_errors,
        }
    }

    fn sample_shard() -> SectionShard {
        SectionShard {
            summary: SectionSummary {
                section_id: "01-drvs".to_string(),
                title: "drvs".to_string(),
                module_path: "drvs".to_string(),
                arch_layer: "drvs".to_string(),
                scope: "first_party".to_string(),
                file_count: 2,
                symbol_count: 2,
                type_count: 0,
                macro_count: 0,
                token_estimate: 50,
                md_file: "01-drvs.md".to_string(),
            },
            files: vec!["src/a.c".to_string(), "src/b.c".to_string()],
            depends_on_sections: Vec::new(),
            depended_by_sections: Vec::new(),
            markdown_body: "# 01-drvs".to_string(),
        }
    }

    #[test]
    fn test_sanity_report_penalties_and_warning_details() {
        let units = vec![sample_unit("src/a.c", 0), sample_unit("src/broken.c", 2)];
        let indexes = BundleIndexes {
            sections: Vec::new(),
            symbols: Vec::new(),
            types: Vec::new(),
            macros: Vec::new(),
            calls: vec![
                ResolvedCallEdge {
                    caller_id: "src/a.c::f".to_string(),
                    caller_name: "f".to_string(),
                    callee_name: "g".to_string(),
                    callee_id: "src/a.c::g".to_string(),
                    file: "src/a.c".to_string(),
                    line: 3,
                    tier: ResolutionTier::SameFile,
                    section_id: "01-drvs".to_string(),
                },
                ResolvedCallEdge {
                    caller_id: "src/a.c::f".to_string(),
                    caller_name: "f".to_string(),
                    callee_name: "ambig".to_string(),
                    callee_id: "src/b.c::ambig".to_string(),
                    file: "src/a.c".to_string(),
                    line: 4,
                    tier: ResolutionTier::AmbiguousName,
                    section_id: "01-drvs".to_string(),
                },
            ],
            xrefs: Vec::new(),
            god_nodes: Vec::new(),
            entrypoints: Vec::new(),
            layer_edges: vec![LayerDependencyEdge {
                from_layer: "drvs".to_string(),
                to_layer: "app".to_string(),
                call_count: 1,
                import_count: 0,
                is_upward_violation: true,
            }],
            cycles: vec![CyclicCluster {
                scc_id: 1,
                symbols: vec!["src/a.c::f".to_string(), "src/a.c::g".to_string()],
                files: vec!["src/a.c".to_string()],
            }],
            vendor_surface: VendorSurfaceSummary::default(),
        };

        let report = compute_sanity_report(&units, &indexes, &[sample_shard()]);
        // 1/2 clean files => 50%, penalty 13; 1 upward violation => -4; 1 cycle => -3 => 80
        assert_eq!(report.score, 80);
        // Only high-confidence calls count as resolved (1 of 2 = 0.5)
        assert!((report.call_resolution_ratio - 0.5).abs() < 1e-6);
        assert!(
            report.warnings.iter().any(|w| w.contains("src/broken.c")),
            "syntax error warning must list offending file paths: {:?}",
            report.warnings
        );
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("Upward architectural layer dependency violation")));
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("Cyclic call cluster")));
    }
}
