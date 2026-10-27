use crate::model::{
    ArchLayer, CyclicCluster, ExtractedSymbol, FileScope, LayerDependencyEdge, ParsedFileUnit,
    RankedSymbol, ResolvedCallEdge, SymbolKind, Visibility,
};
use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Runs deterministic 25-iteration PageRank, Tarjan's Strongly Connected Components (SCC) cycle
/// detection, entrypoint/ISR identification, God-node hub ranking, and cross-layer dependency
/// analysis (`from_layer -> to_layer` with upward violation detection).
#[allow(clippy::type_complexity)]
pub fn analyze_graph(
    symbols: Vec<ExtractedSymbol>,
    calls: &[ResolvedCallEdge],
    units: &[ParsedFileUnit],
) -> (
    Vec<RankedSymbol>,
    Vec<RankedSymbol>,
    Vec<RankedSymbol>,
    Vec<LayerDependencyEdge>,
    Vec<CyclicCluster>,
) {
    let n = symbols.len();
    if n == 0 {
        let layer_edges = compute_layer_edges(&[], calls, units);
        return (Vec::new(), Vec::new(), Vec::new(), layer_edges, Vec::new());
    }

    // 1. Assign dense integer node IDs 0..N to the sorted symbols
    let mut id_to_idx: FxHashMap<&str, u32> = FxHashMap::default();
    id_to_idx.reserve(n);
    for (i, sym) in symbols.iter().enumerate() {
        id_to_idx.entry(sym.symbol_id.as_str()).or_insert(i as u32);
    }

    // 2. Build outgoing adj and incoming rev_adj (excluding self-loops, sorted & deduplicated)
    let mut adj: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut rev_adj: Vec<Vec<u32>> = vec![Vec::new(); n];

    for call in calls {
        if !call.tier.is_resolved() {
            continue;
        }
        if let (Some(&u), Some(&v)) = (
            id_to_idx.get(call.caller_id.as_str()),
            id_to_idx.get(call.callee_id.as_str()),
        ) {
            if u != v {
                adj[u as usize].push(v);
                rev_adj[v as usize].push(u);
            }
        }
    }

    for list in &mut adj {
        list.sort_unstable();
        list.dedup();
    }
    for list in &mut rev_adj {
        list.sort_unstable();
        list.dedup();
    }

    // 3. Run 25-iteration deterministic PageRank (damping = 0.85)
    // Give 1.5x base prior weight to FileScope::FirstParty symbols over VendorSdk
    const DAMPING: f64 = 0.85;
    const ITERS: usize = 25;

    let mut prior: Vec<f64> = symbols
        .iter()
        .map(|s| match s.scope {
            FileScope::FirstParty => 1.5,
            FileScope::Test => 1.0,
            FileScope::VendorSdk => 1.0,
        })
        .collect();
    let prior_sum: f64 = prior.iter().sum();
    if prior_sum > 0.0 {
        for p in &mut prior {
            *p /= prior_sum;
        }
    }

    let mut ranks = prior.clone();
    let mut next_ranks = vec![0.0_f64; n];

    for _ in 0..ITERS {
        let mut dangling_mass = 0.0_f64;
        for (u, out_list) in adj.iter().enumerate() {
            if out_list.is_empty() {
                dangling_mass += ranks[u];
            }
        }

        for v in 0..n {
            let mut incoming_sum = 0.0_f64;
            for &u in &rev_adj[v] {
                let u_idx = u as usize;
                let deg = adj[u_idx].len() as f64;
                incoming_sum += ranks[u_idx] / deg;
            }
            next_ranks[v] =
                (1.0 - DAMPING) * prior[v] + DAMPING * (incoming_sum + dangling_mass * prior[v]);
        }

        std::mem::swap(&mut ranks, &mut next_ranks);
    }

    // 4. Run Tarjan's Strongly Connected Components (SCC) algorithm on adj
    let (cycles, node_scc_ids) = compute_tarjan_sccs(&adj, &symbols);

    // 5. Build initial RankedSymbol vector and identify Entrypoints
    let mut ranked: Vec<RankedSymbol> = symbols
        .iter()
        .enumerate()
        .map(|(i, sym)| {
            let in_degree = rev_adj[i].len();
            let out_degree = adj[i].len();
            let is_named_entry = matches!(
                sym.name.as_str(),
                "main" | "app_main" | "Reset_Handler" | "_start" | "SystemInit"
            );
            let is_entrypoint = matches!(sym.kind, SymbolKind::Entrypoint | SymbolKind::Isr)
                || (sym.scope == FileScope::FirstParty && is_named_entry)
                || (sym.scope == FileScope::FirstParty
                    && sym.visibility == Visibility::Public
                    && matches!(
                        sym.arch_layer,
                        ArchLayer::App | ArchLayer::Cli | ArchLayer::Api
                    )
                    && in_degree == 0
                    && out_degree > 0);

            RankedSymbol {
                symbol: sym.clone(),
                pagerank: ranks[i],
                in_degree,
                out_degree,
                is_god_node: false,
                is_entrypoint,
                scc_id: node_scc_ids[i],
            }
        })
        .collect();

    // 6. Identify God Nodes (Top architectural hubs)
    // Ranked by pagerank * (1.0 + (in_degree + out_degree) as f64).ln_1p()
    let mut hub_candidates: Vec<(usize, f64)> = ranked
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r.symbol.scope == FileScope::FirstParty && (r.in_degree + r.out_degree) >= 2
        })
        .map(|(idx, r)| {
            let deg = (r.in_degree + r.out_degree) as f64;
            let score = r.pagerank * (1.0 + deg).ln_1p();
            (idx, score)
        })
        .collect();

    if hub_candidates.is_empty() {
        hub_candidates = ranked
            .iter()
            .enumerate()
            .filter(|(_, r)| r.symbol.scope == FileScope::FirstParty)
            .map(|(idx, r)| {
                let deg = (r.in_degree + r.out_degree) as f64;
                let score = r.pagerank * (1.0 + deg).ln_1p();
                (idx, score)
            })
            .collect();
    }

    if hub_candidates.is_empty() {
        hub_candidates = ranked
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let deg = (r.in_degree + r.out_degree) as f64;
                let score = r.pagerank * (1.0 + deg).ln_1p();
                (idx, score)
            })
            .collect();
    }

    hub_candidates.sort_by(|(idx_a, score_a), (idx_b, score_b)| {
        score_b
            .total_cmp(score_a)
            .then_with(|| {
                let deg_a = ranked[*idx_a].in_degree + ranked[*idx_a].out_degree;
                let deg_b = ranked[*idx_b].in_degree + ranked[*idx_b].out_degree;
                deg_b.cmp(&deg_a)
            })
            .then_with(|| {
                ranked[*idx_a]
                    .symbol
                    .symbol_id
                    .cmp(&ranked[*idx_b].symbol.symbol_id)
            })
    });

    let top_hub_indices: Vec<usize> = hub_candidates
        .into_iter()
        .take(15)
        .map(|(idx, _)| idx)
        .collect();

    for &idx in &top_hub_indices {
        ranked[idx].is_god_node = true;
    }

    let god_nodes: Vec<RankedSymbol> = top_hub_indices
        .iter()
        .map(|&idx| ranked[idx].clone())
        .collect();

    let mut entrypoints: Vec<RankedSymbol> =
        ranked.iter().filter(|r| r.is_entrypoint).cloned().collect();
    entrypoints.sort_by(|a, b| {
        b.pagerank
            .total_cmp(&a.pagerank)
            .then_with(|| a.symbol.file.cmp(&b.symbol.file))
            .then_with(|| a.symbol.start_line.cmp(&b.symbol.start_line))
            .then_with(|| a.symbol.symbol_id.cmp(&b.symbol.symbol_id))
    });

    // 7. Compute cross-layer dependency edges
    let layer_edges = compute_layer_edges(&symbols, calls, units);

    (ranked, god_nodes, entrypoints, layer_edges, cycles)
}

fn compute_tarjan_sccs(
    adj: &[Vec<u32>],
    symbols: &[ExtractedSymbol],
) -> (Vec<CyclicCluster>, Vec<Option<usize>>) {
    struct TarjanState<'a> {
        adj: &'a [Vec<u32>],
        index: u32,
        indices: Vec<Option<u32>>,
        lowlink: Vec<u32>,
        on_stack: Vec<bool>,
        stack: Vec<u32>,
        raw_sccs: Vec<Vec<u32>>,
    }

    impl<'a> TarjanState<'a> {
        fn strongconnect(&mut self, v: u32) {
            let v_usize = v as usize;
            self.indices[v_usize] = Some(self.index);
            self.lowlink[v_usize] = self.index;
            self.index += 1;
            self.stack.push(v);
            self.on_stack[v_usize] = true;

            for &w in &self.adj[v_usize] {
                let w_usize = w as usize;
                if self.indices[w_usize].is_none() {
                    self.strongconnect(w);
                    self.lowlink[v_usize] = self.lowlink[v_usize].min(self.lowlink[w_usize]);
                } else if self.on_stack[w_usize] {
                    let w_idx = self.indices[w_usize].unwrap_or(0);
                    self.lowlink[v_usize] = self.lowlink[v_usize].min(w_idx);
                }
            }

            if Some(self.lowlink[v_usize]) == self.indices[v_usize] {
                let mut component = Vec::new();
                while let Some(w) = self.stack.pop() {
                    self.on_stack[w as usize] = false;
                    component.push(w);
                    if w == v {
                        break;
                    }
                }
                if component.len() >= 2 {
                    component.sort_unstable();
                    self.raw_sccs.push(component);
                }
            }
        }
    }

    let n = adj.len();
    let mut state = TarjanState {
        adj,
        index: 0,
        indices: vec![None; n],
        lowlink: vec![0; n],
        on_stack: vec![false; n],
        stack: Vec::new(),
        raw_sccs: Vec::new(),
    };

    for v in 0..(n as u32) {
        if state.indices[v as usize].is_none() {
            state.strongconnect(v);
        }
    }

    // Sort SCCs deterministically by their first node ID
    state.raw_sccs.sort();

    let mut node_scc_ids: Vec<Option<usize>> = vec![None; n];
    let mut clusters: Vec<CyclicCluster> = Vec::with_capacity(state.raw_sccs.len());

    for (cluster_idx, comp) in state.raw_sccs.into_iter().enumerate() {
        let scc_id = cluster_idx + 1;
        let mut syms = Vec::with_capacity(comp.len());
        let mut files = BTreeSet::new();

        for u in comp {
            let u_usize = u as usize;
            node_scc_ids[u_usize] = Some(scc_id);
            syms.push(symbols[u_usize].symbol_id.clone());
            files.insert(symbols[u_usize].file.clone());
        }

        clusters.push(CyclicCluster {
            scc_id,
            symbols: syms,
            files: files.into_iter().collect(),
        });
    }

    (clusters, node_scc_ids)
}

fn compute_layer_edges(
    symbols: &[ExtractedSymbol],
    calls: &[ResolvedCallEdge],
    units: &[ParsedFileUnit],
) -> Vec<LayerDependencyEdge> {
    let mut sym_layer: FxHashMap<&str, (ArchLayer, FileScope)> = FxHashMap::default();
    let mut file_layer: FxHashMap<&str, (ArchLayer, FileScope)> = FxHashMap::default();
    let mut stem_layer: FxHashMap<String, (ArchLayer, FileScope)> = FxHashMap::default();

    for sym in symbols {
        sym_layer.insert(sym.symbol_id.as_str(), (sym.arch_layer, sym.scope));
        file_layer
            .entry(sym.file.as_str())
            .or_insert((sym.arch_layer, sym.scope));
    }

    for u in units {
        file_layer.insert(
            u.scanned.rel_path.as_str(),
            (u.scanned.arch_layer, u.scanned.scope),
        );
        if let Some(stem) = Path::new(&u.scanned.rel_path)
            .file_stem()
            .and_then(|s| s.to_str())
        {
            stem_layer
                .entry(stem.to_ascii_lowercase())
                .or_insert((u.scanned.arch_layer, u.scanned.scope));
        }
    }

    let mut edge_counts: BTreeMap<(ArchLayer, ArchLayer), (usize, usize)> = BTreeMap::new();

    for call in calls {
        if !call.tier.is_resolved() {
            continue;
        }
        let from_info = sym_layer
            .get(call.caller_id.as_str())
            .or_else(|| file_layer.get(call.file.as_str()))
            .copied();
        let to_info = sym_layer.get(call.callee_id.as_str()).copied();

        if let (Some((from_l, _)), Some((to_l, _))) = (from_info, to_info) {
            if from_l != to_l {
                edge_counts.entry((from_l, to_l)).or_default().0 += 1;
            }
        }
    }

    for u in units {
        let from_l = u.scanned.arch_layer;
        for imp in &u.imports {
            let clean = imp
                .raw_path
                .trim()
                .trim_matches(|c| matches!(c, '"' | '\'' | '<' | '>'))
                .replace("::", "/")
                .replace('\\', "/");

            let matched_layer = file_layer.get(clean.as_str()).copied().or_else(|| {
                let stem = Path::new(&clean)
                    .file_stem()
                    .and_then(|s| s.to_str())?
                    .to_ascii_lowercase();
                stem_layer.get(&stem).copied()
            });

            if let Some((to_l, _)) = matched_layer {
                if from_l != to_l {
                    edge_counts.entry((from_l, to_l)).or_default().1 += 1;
                }
            }
        }
    }

    let mut edges: Vec<LayerDependencyEdge> = edge_counts
        .into_iter()
        .map(|((from_l, to_l), (call_count, import_count))| {
            let both_layered_first_party = !matches!(
                from_l,
                ArchLayer::VendorHal | ArchLayer::Tests | ArchLayer::Other
            ) && !matches!(
                to_l,
                ArchLayer::VendorHal | ArchLayer::Tests | ArchLayer::Other
            );
            let is_upward_violation = both_layered_first_party && from_l.rank() < to_l.rank();

            LayerDependencyEdge {
                from_layer: from_l.as_str().to_string(),
                to_layer: to_l.as_str().to_string(),
                call_count,
                import_count,
                is_upward_violation,
            }
        })
        .collect();

    edges.sort_by(|a, b| {
        let total_a = a.call_count + a.import_count;
        let total_b = b.call_count + b.import_count;
        total_b
            .cmp(&total_a)
            .then_with(|| a.from_layer.cmp(&b.from_layer))
            .then_with(|| a.to_layer.cmp(&b.to_layer))
    });

    edges
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ResolutionTier;

    fn make_sym(id: &str, name: &str, kind: SymbolKind, layer: ArchLayer) -> ExtractedSymbol {
        ExtractedSymbol {
            symbol_id: id.to_string(),
            name: name.to_string(),
            qualified_name: name.to_string(),
            kind,
            visibility: Visibility::Public,
            file: format!("src/{name}.c"),
            start_line: 1,
            end_line: 10,
            signature: format!("void {name}(void)"),
            doc_summary: String::new(),
            enclosing_type: None,
            scope: FileScope::FirstParty,
            arch_layer: layer,
            section_id: "src".to_string(),
        }
    }

    #[test]
    fn test_pagerank_scc_and_upward_violation() {
        let symbols = vec![
            make_sym("s::main", "main", SymbolKind::Entrypoint, ArchLayer::App),
            make_sym("s::hub", "hub", SymbolKind::Function, ArchLayer::Core),
            make_sym(
                "s::drv_a",
                "drv_a",
                SymbolKind::Function,
                ArchLayer::Drivers,
            ),
            make_sym(
                "s::drv_b",
                "drv_b",
                SymbolKind::Function,
                ArchLayer::Drivers,
            ),
        ];

        let calls = vec![
            ResolvedCallEdge {
                caller_id: "s::main".to_string(),
                caller_name: "main".to_string(),
                callee_name: "hub".to_string(),
                callee_id: "s::hub".to_string(),
                file: "src/main.c".to_string(),
                line: 5,
                tier: ResolutionTier::UniqueGlobal,
                section_id: "src".to_string(),
            },
            ResolvedCallEdge {
                caller_id: "s::hub".to_string(),
                caller_name: "hub".to_string(),
                callee_name: "drv_a".to_string(),
                callee_id: "s::drv_a".to_string(),
                file: "src/hub.c".to_string(),
                line: 6,
                tier: ResolutionTier::UniqueGlobal,
                section_id: "src".to_string(),
            },
            // Mutual recursion between drv_a and drv_b (SCC of size 2)
            ResolvedCallEdge {
                caller_id: "s::drv_a".to_string(),
                caller_name: "drv_a".to_string(),
                callee_name: "drv_b".to_string(),
                callee_id: "s::drv_b".to_string(),
                file: "src/drv_a.c".to_string(),
                line: 7,
                tier: ResolutionTier::UniqueGlobal,
                section_id: "src".to_string(),
            },
            ResolvedCallEdge {
                caller_id: "s::drv_b".to_string(),
                caller_name: "drv_b".to_string(),
                callee_name: "drv_a".to_string(),
                callee_id: "s::drv_a".to_string(),
                file: "src/drv_b.c".to_string(),
                line: 8,
                tier: ResolutionTier::UniqueGlobal,
                section_id: "src".to_string(),
            },
            // Upward layer violation: drvs -> app
            ResolvedCallEdge {
                caller_id: "s::drv_b".to_string(),
                caller_name: "drv_b".to_string(),
                callee_name: "main".to_string(),
                callee_id: "s::main".to_string(),
                file: "src/drv_b.c".to_string(),
                line: 9,
                tier: ResolutionTier::UniqueGlobal,
                section_id: "src".to_string(),
            },
        ];

        let (ranked, god_nodes, entrypoints, layer_edges, cycles) =
            analyze_graph(symbols, &calls, &[]);

        assert_eq!(ranked.len(), 4);
        assert!(!god_nodes.is_empty());
        assert_eq!(entrypoints.len(), 1);
        assert_eq!(entrypoints[0].symbol.name, "main");
        assert!(!cycles.is_empty());
        assert!(layer_edges
            .iter()
            .any(|e| e.from_layer == "drvs" && e.to_layer == "app" && e.is_upward_violation));
    }
}
