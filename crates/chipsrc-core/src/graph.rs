use crate::model::{
    ArchLayer, CyclicCluster, ExtractedSymbol, FileScope, LanguageKind, LayerDependencyEdge,
    ParsedFileUnit, RankedSymbol, ResolvedCallEdge, SymbolKind, Visibility,
};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Analyzes call graph metrics, SCC cycles, entrypoints, hub nodes, and cross-layer dependencies.
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

    let mut id_to_idx: FxHashMap<&str, u32> = FxHashMap::default();
    id_to_idx.reserve(n);
    for (i, sym) in symbols.iter().enumerate() {
        id_to_idx.entry(sym.symbol_id.as_str()).or_insert(i as u32);
    }

    let mut adj: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut rev_adj: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut deg_adj: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut deg_rev_adj: Vec<Vec<u32>> = vec![Vec::new(); n];

    for call in calls {
        if !call.tier.is_high_confidence() {
            continue;
        }
        if let (Some(&u), Some(&v)) = (
            id_to_idx.get(call.caller_id.as_str()),
            id_to_idx.get(call.callee_id.as_str()),
        ) {
            if u != v {
                let caller_scope = symbols[u as usize].scope;
                let callee_scope = symbols[v as usize].scope;
                if caller_scope == FileScope::Test && callee_scope == FileScope::FirstParty {
                    continue;
                }
                deg_adj[u as usize].push(v);
                deg_rev_adj[v as usize].push(u);

                if caller_scope != FileScope::Test {
                    adj[u as usize].push(v);
                    rev_adj[v as usize].push(u);
                }
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
    for list in &mut deg_adj {
        list.sort_unstable();
        list.dedup();
    }
    for list in &mut deg_rev_adj {
        list.sort_unstable();
        list.dedup();
    }

    const DAMPING: f64 = 0.85;
    const ITERS: usize = 25;

    let mut prior: Vec<f64> = symbols
        .iter()
        .map(|s| match s.scope {
            FileScope::FirstParty => 1.5,
            FileScope::Test => 0.1,
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

    let (hubs, authorities) = compute_hits(&adj, &rev_adj, &symbols, ITERS);

    let (cycles, node_scc_ids) = compute_tarjan_sccs(&adj, &symbols);

    let mut ranked: Vec<RankedSymbol> = symbols
        .iter()
        .enumerate()
        .map(|(i, sym)| {
            let in_degree = deg_rev_adj[i].len();
            let out_degree = deg_adj[i].len();
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

            let mut symbol = sym.clone();
            if is_entrypoint && symbol.kind == SymbolKind::Function {
                symbol.kind = SymbolKind::Entrypoint;
            }

            RankedSymbol {
                symbol,
                pagerank: ranks[i],
                hub_score: hubs[i],
                authority_score: authorities[i],
                in_degree,
                out_degree,
                is_god_node: false,
                is_entrypoint,
                scc_id: node_scc_ids[i],
            }
        })
        .collect();

    let god_node_score = |r: &RankedSymbol| -> f64 {
        let bridge = (1.0 + r.in_degree as f64).ln_1p()
            * (1.0 + r.out_degree as f64).ln_1p()
            * (r.out_degree as f64).sqrt().max(1.0);
        let vis = if r.symbol.visibility == Visibility::Public {
            1.4
        } else {
            0.85
        };
        let layer_w = match r.symbol.arch_layer {
            ArchLayer::Cli => 0.55,
            _ => 1.0,
        };
        let leaf_penalty = match r.out_degree {
            0 => 0.10,
            1 if r.in_degree >= 2 => 0.45,
            1 => 0.55,
            _ => 1.0,
        };
        (r.hub_score * r.authority_score).sqrt() * bridge * vis * layer_w * leaf_penalty
    };

    let mut hub_candidates: Vec<(usize, f64)> = ranked
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r.symbol.scope == FileScope::FirstParty
                && r.out_degree >= 2
                && (r.in_degree >= 1
                    || (r.symbol.visibility == Visibility::Public && r.out_degree >= 3))
        })
        .map(|(idx, r)| (idx, god_node_score(r)))
        .collect();

    if hub_candidates.is_empty() {
        hub_candidates = ranked
            .iter()
            .enumerate()
            .filter(|(_, r)| r.symbol.scope == FileScope::FirstParty && r.out_degree >= 2)
            .map(|(idx, r)| (idx, god_node_score(r)))
            .collect();
    }

    if ranked.len() < 40 && hub_candidates.len() < 5 {
        hub_candidates = ranked
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.symbol.scope == FileScope::FirstParty
                    && r.out_degree >= 1
                    && (r.in_degree + r.out_degree) >= 2
            })
            .map(|(idx, r)| (idx, god_node_score(r)))
            .collect();
    }

    if ranked.len() < 40 && hub_candidates.is_empty() {
        hub_candidates = ranked
            .iter()
            .enumerate()
            .filter(|(_, r)| r.symbol.scope == FileScope::FirstParty && r.out_degree >= 1)
            .map(|(idx, r)| (idx, god_node_score(r)))
            .collect();
    }

    if ranked.len() < 40 && hub_candidates.is_empty() {
        hub_candidates = ranked
            .iter()
            .enumerate()
            .filter(|(_, r)| r.symbol.scope == FileScope::FirstParty)
            .map(|(idx, r)| (idx, god_node_score(r)))
            .collect();
    }

    if hub_candidates.is_empty() {
        hub_candidates = ranked
            .iter()
            .enumerate()
            .map(|(idx, r)| (idx, god_node_score(r)))
            .collect();
    }

    hub_candidates.sort_by(|(idx_a, score_a), (idx_b, score_b)| {
        score_b.total_cmp(score_a).then_with(|| {
            ranked[*idx_a]
                .symbol
                .symbol_id
                .cmp(&ranked[*idx_b].symbol.symbol_id)
        })
    });
    {
        let mut file_counts: FxHashMap<&str, usize> = FxHashMap::default();
        for (idx, score) in &mut hub_candidates {
            let f = ranked[*idx].symbol.file.as_str();
            let count = file_counts.entry(f).or_insert(0);
            if *count >= 1 {
                *score /= 1.0 + 0.85 * (*count as f64);
            }
            *count += 1;
        }
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

    let layer_edges = compute_layer_edges(&symbols, calls, units);

    (ranked, god_nodes, entrypoints, layer_edges, cycles)
}

fn compute_hits(
    adj: &[Vec<u32>],
    rev_adj: &[Vec<u32>],
    symbols: &[ExtractedSymbol],
    iters: usize,
) -> (Vec<f64>, Vec<f64>) {
    let n = symbols.len();
    if n == 0 {
        return (Vec::new(), Vec::new());
    }

    let mut prior_hub = vec![0.0_f64; n];
    let mut prior_auth = vec![0.0_f64; n];

    for i in 0..n {
        if symbols[i].scope == FileScope::Test {
            continue;
        }
        let scope_w = if symbols[i].scope == FileScope::FirstParty {
            1.5
        } else {
            0.5
        };
        let vis_w = if symbols[i].visibility == Visibility::Public {
            2.5
        } else {
            1.0
        };
        let cross_out = adj[i]
            .iter()
            .filter(|&&v| symbols[v as usize].file != symbols[i].file)
            .count();
        let cross_in = rev_adj[i]
            .iter()
            .filter(|&&u| symbols[u as usize].file != symbols[i].file)
            .count();
        let out_deg = adj[i].len();
        let in_deg = rev_adj[i].len();

        prior_hub[i] = scope_w
            * vis_w
            * if out_deg >= 2 {
                1.0 + (out_deg as f64).ln_1p() + 2.0 * (cross_out as f64).ln_1p()
            } else {
                0.2
            };
        let auth_out_factor = if out_deg >= 2 {
            2.0
        } else if out_deg == 1 {
            0.5
        } else {
            0.15
        };
        prior_auth[i] = scope_w
            * vis_w
            * auth_out_factor
            * (1.0 + (in_deg as f64).ln_1p() + 2.5 * (cross_in as f64).ln_1p());
    }

    l2_normalize(&mut prior_hub);
    l2_normalize(&mut prior_auth);

    let mut hub = prior_hub.clone();
    let mut auth = prior_auth.clone();
    let mut next_hub = vec![0.0_f64; n];
    let mut next_auth = vec![0.0_f64; n];

    let caller_damps: Vec<f64> = (0..n)
        .map(|u| {
            let u_out = adj[u].len().max(1) as f64;
            if rev_adj[u].is_empty() || symbols[u].arch_layer == ArchLayer::Cli {
                0.35 / u_out.sqrt()
            } else {
                1.0 / u_out.sqrt()
            }
        })
        .collect();

    let edge_weight = |u: usize, v: usize| -> f64 {
        let cross_file = symbols[u].file != symbols[v].file;
        let caller_damp = caller_damps[u];
        let v_out = adj[v].len();
        if v_out == 0 {
            let v_in = rev_adj[v].len().max(1) as f64;
            return caller_damp * (0.10 / v_in);
        }
        let base = if cross_file {
            if symbols[v].visibility == Visibility::Public && v_out >= 2 {
                4.0
            } else {
                2.5
            }
        } else if v_out >= 2 {
            1.0
        } else {
            0.35
        };
        caller_damp * base
    };

    const ALPHA: f64 = 0.75;
    for _ in 0..iters {
        for v in 0..n {
            if symbols[v].scope == FileScope::Test {
                next_auth[v] = 0.0;
                continue;
            }
            let mut sum_h = 0.0_f64;
            for &u in &rev_adj[v] {
                let u_idx = u as usize;
                sum_h += edge_weight(u_idx, v) * hub[u_idx];
            }
            next_auth[v] = (1.0 - ALPHA) * prior_auth[v] + ALPHA * sum_h;
        }
        l2_normalize(&mut next_auth);
        std::mem::swap(&mut auth, &mut next_auth);

        for u in 0..n {
            if symbols[u].scope == FileScope::Test {
                next_hub[u] = 0.0;
                continue;
            }
            let mut sum_a = 0.0_f64;
            for &v in &adj[u] {
                let v_idx = v as usize;
                sum_a += edge_weight(u, v_idx) * auth[v_idx];
            }
            next_hub[u] = (1.0 - ALPHA) * prior_hub[u] + ALPHA * sum_a;
        }
        l2_normalize(&mut next_hub);
        std::mem::swap(&mut hub, &mut next_hub);
    }

    (hub, auth)
}

fn l2_normalize(vec: &mut [f64]) {
    let norm = vec.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 0.0 {
        for x in vec.iter_mut() {
            *x /= norm;
        }
    }
}

fn compute_tarjan_sccs(
    adj: &[Vec<u32>],
    symbols: &[ExtractedSymbol],
) -> (Vec<CyclicCluster>, Vec<Option<usize>>) {
    let n = adj.len();
    let mut index: u32 = 0;
    let mut indices: Vec<Option<u32>> = vec![None; n];
    let mut lowlink: Vec<u32> = vec![0; n];
    let mut on_stack: Vec<bool> = vec![false; n];
    let mut scc_stack: Vec<u32> = Vec::new();
    let mut work_stack: Vec<(u32, usize)> = Vec::new();
    let mut raw_sccs: Vec<Vec<u32>> = Vec::new();

    for start_v in 0..(n as u32) {
        if indices[start_v as usize].is_some() {
            continue;
        }

        indices[start_v as usize] = Some(index);
        lowlink[start_v as usize] = index;
        index += 1;
        scc_stack.push(start_v);
        on_stack[start_v as usize] = true;
        work_stack.push((start_v, 0));

        while let Some((v, next_edge_idx)) = work_stack.last_mut() {
            let v_usize = *v as usize;
            if *next_edge_idx < adj[v_usize].len() {
                let w = adj[v_usize][*next_edge_idx];
                *next_edge_idx += 1;
                let w_usize = w as usize;
                if indices[w_usize].is_none() {
                    indices[w_usize] = Some(index);
                    lowlink[w_usize] = index;
                    index += 1;
                    scc_stack.push(w);
                    on_stack[w_usize] = true;
                    work_stack.push((w, 0));
                } else if on_stack[w_usize] {
                    let w_idx = indices[w_usize].unwrap_or(0);
                    lowlink[v_usize] = lowlink[v_usize].min(w_idx);
                }
            } else {
                let finished_v = *v;
                let finished_usize = finished_v as usize;
                work_stack.pop();

                if let Some(&(parent_v, _)) = work_stack.last() {
                    let p_usize = parent_v as usize;
                    lowlink[p_usize] = lowlink[p_usize].min(lowlink[finished_usize]);
                }

                if Some(lowlink[finished_usize]) == indices[finished_usize] {
                    let mut component = Vec::new();
                    while let Some(w) = scc_stack.pop() {
                        on_stack[w as usize] = false;
                        component.push(w);
                        if w == finished_v {
                            break;
                        }
                    }
                    if component.len() >= 2 {
                        component.sort_unstable();
                        raw_sccs.push(component);
                    }
                }
            }
        }
    }

    raw_sccs.sort();

    let mut node_scc_ids: Vec<Option<usize>> = vec![None; n];
    let mut clusters: Vec<CyclicCluster> = Vec::with_capacity(raw_sccs.len());

    for (cluster_idx, comp) in raw_sccs.into_iter().enumerate() {
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

const GENERIC_IMPORT_STEMS: &[&str] = &[
    "main", "config", "common", "utils", "types", "index", "mod", "lib", "test",
];

fn is_generic_import_stem(stem: &str) -> bool {
    GENERIC_IMPORT_STEMS.contains(&stem)
}

fn import_module_stems(clean_path: &str) -> Vec<String> {
    let head = clean_path.split('{').next().unwrap_or(clean_path);
    let mut stems: Vec<String> = Vec::new();

    for segment in head.split(['/', ':', '\\']).rev() {
        let trimmed = segment
            .trim()
            .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.');
        if trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_ascii_lowercase();
        if matches!(lower.as_str(), "*" | "self" | "super" | "crate") {
            continue;
        }

        let stem = match lower.rsplit_once('.') {
            Some((stem, ext))
                if !stem.is_empty() && LanguageKind::from_extension(ext).is_some() =>
            {
                stem.to_string()
            }
            _ => lower.clone(),
        };
        let stem = stem
            .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .to_string();
        if !stem.is_empty() && !stems.contains(&stem) {
            stems.push(stem);
        }
    }

    stems
}

fn import_target_compatible(
    importer_language: LanguageKind,
    importer_scope: FileScope,
    target_language: LanguageKind,
    target_scope: FileScope,
) -> bool {
    importer_language.language_family() == target_language.language_family()
        || (importer_scope == FileScope::FirstParty && target_scope == FileScope::FirstParty)
}

fn compute_layer_edges(
    symbols: &[ExtractedSymbol],
    calls: &[ResolvedCallEdge],
    units: &[ParsedFileUnit],
) -> Vec<LayerDependencyEdge> {
    let mut sym_layer: FxHashMap<&str, (ArchLayer, FileScope)> = FxHashMap::default();
    let mut sym_kind: FxHashMap<&str, SymbolKind> = FxHashMap::default();
    let mut file_layer: FxHashMap<&str, (ArchLayer, FileScope)> = FxHashMap::default();
    let mut file_language: FxHashMap<&str, LanguageKind> = FxHashMap::default();
    let mut no_ext_layer: FxHashMap<String, (ArchLayer, FileScope, LanguageKind)> =
        FxHashMap::default();
    let mut stem_layer: FxHashMap<String, (ArchLayer, FileScope, LanguageKind)> =
        FxHashMap::default();
    let mut ambiguous_stems: FxHashSet<String> = FxHashSet::default();

    for sym in symbols {
        sym_layer.insert(sym.symbol_id.as_str(), (sym.arch_layer, sym.scope));
        sym_kind.insert(sym.symbol_id.as_str(), sym.kind);
        file_layer
            .entry(sym.file.as_str())
            .or_insert((sym.arch_layer, sym.scope));
    }

    for u in units {
        let rel_path = u.scanned.rel_path.as_str();
        file_layer.insert(rel_path, (u.scanned.arch_layer, u.scanned.scope));
        file_language.insert(rel_path, u.scanned.language);

        let norm_rel = rel_path.replace('\\', "/");
        let without_ext = match norm_rel.rsplit_once('.') {
            Some((prefix, ext)) if LanguageKind::from_extension(ext).is_some() => {
                prefix.to_string()
            }
            _ => norm_rel.clone(),
        };
        no_ext_layer.insert(
            without_ext,
            (u.scanned.arch_layer, u.scanned.scope, u.scanned.language),
        );

        if let Some(stem) = Path::new(rel_path).file_stem().and_then(|s| s.to_str()) {
            let key = stem.to_ascii_lowercase();
            match stem_layer.get(&key) {
                Some(existing) if existing.0 != u.scanned.arch_layer => {
                    ambiguous_stems.insert(key);
                }
                Some(_) => {}
                None => {
                    stem_layer.insert(
                        key,
                        (u.scanned.arch_layer, u.scanned.scope, u.scanned.language),
                    );
                }
            }
        }
    }

    let mut edge_counts: BTreeMap<(ArchLayer, ArchLayer), (usize, usize)> = BTreeMap::new();

    for call in calls {
        if !call.tier.is_high_confidence() {
            continue;
        }
        let is_startup_dispatch = sym_kind
            .get(call.caller_id.as_str())
            .is_some_and(|k| matches!(k, SymbolKind::Entrypoint | SymbolKind::Isr))
            && sym_layer
                .get(call.caller_id.as_str())
                .is_some_and(|(l, _)| matches!(l, ArchLayer::VendorHal | ArchLayer::Bsp));
        if is_startup_dispatch || matches!(call.caller_name.as_str(), "Reset_Handler" | "_start") {
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
        let importer_language = u.scanned.language;
        let importer_scope = u.scanned.scope;

        for imp in &u.imports {
            let clean = imp
                .raw_path
                .trim()
                .trim_matches(|c| matches!(c, '"' | '\'' | '<' | '>'))
                .replace("::", "/")
                .replace('\\', "/");

            let mut matched: Option<(ArchLayer, FileScope, Option<LanguageKind>)> = None;

            if let Some(&(layer, scope)) = file_layer.get(clean.as_str()) {
                matched = Some((layer, scope, file_language.get(clean.as_str()).copied()));
            } else if let Some(rel_target) =
                resolve_relative_path_no_ext(&u.scanned.rel_path, &clean)
            {
                if let Some(&(layer, scope, lang)) = no_ext_layer
                    .get(&rel_target)
                    .or_else(|| no_ext_layer.get(&format!("{rel_target}/index")))
                {
                    matched = Some((layer, scope, Some(lang)));
                }
            }

            if matched.is_none() && !imp.is_system {
                for key in import_module_stems(&clean) {
                    if is_generic_import_stem(&key) || ambiguous_stems.contains(&key) {
                        continue;
                    }
                    if let Some(&(layer, scope, language)) = stem_layer.get(&key) {
                        matched = Some((layer, scope, Some(language)));
                        break;
                    }
                }
            }

            let Some((to_l, to_scope, to_language)) = matched else {
                continue;
            };

            let compatible = match to_language {
                Some(language) => {
                    import_target_compatible(importer_language, importer_scope, language, to_scope)
                }
                None => true,
            };

            if compatible && from_l != to_l {
                edge_counts.entry((from_l, to_l)).or_default().1 += 1;
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

fn resolve_relative_path_no_ext(caller_file: &str, clean_import: &str) -> Option<String> {
    if !clean_import.starts_with("./") && !clean_import.starts_with("../") {
        return None;
    }
    let caller_norm = caller_file.replace('\\', "/");
    let mut stack: Vec<&str> = caller_norm.split('/').collect();
    if !stack.is_empty() {
        stack.pop();
    }
    for seg in clean_import.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    let stripped = match joined.rsplit_once('.') {
        Some((prefix, ext)) if LanguageKind::from_extension(ext).is_some() => prefix.to_string(),
        _ => joined,
    };
    Some(stripped)
}
