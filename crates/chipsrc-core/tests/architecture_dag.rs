use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

fn module_layer(module: &str) -> Option<u8> {
    match module {
        "error" | "model" => Some(0),
        "mmio" | "scanner" | "parser" => Some(1),
        "resolver" | "graph" | "sharder" | "sanity" => Some(2),
        "emitter" | "query" => Some(3),
        "lib" => Some(4),
        _ => None,
    }
}

fn strip_string_literals_in_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_str = false;
    while let Some(c) = chars.next() {
        if in_str {
            if c == '\\' {
                let _ = chars.next();
            } else if c == '"' {
                in_str = false;
                out.push('"');
            } else {
                out.push(' ');
            }
        } else if c == '"' {
            in_str = true;
            out.push('"');
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_crate_dependencies(source: &str) -> BTreeSet<String> {
    let prod_source = source.split("#[cfg(test)]").next().unwrap_or(source);
    let mut deps = BTreeSet::new();

    for raw_line in prod_source.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        let clean_line = strip_string_literals_in_line(trimmed);
        let code_part = clean_line.split("//").next().unwrap_or(&clean_line);

        for prefix in ["crate::", "super::"] {
            let mut rest = code_part;
            while let Some(pos) = rest.find(prefix) {
                let after = &rest[pos + prefix.len()..];
                let ident: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if module_layer(&ident).is_some() {
                    deps.insert(ident);
                }
                rest = after;
            }
        }

        for known in [
            "error", "model", "mmio", "scanner", "parser", "resolver", "graph", "sharder",
            "sanity", "emitter", "query",
        ] {
            let pat = format!("{known}::");
            if code_part.contains(&pat) {
                deps.insert(known.to_string());
            }
        }
    }

    deps
}

fn has_cycle(
    node: &str,
    adj: &BTreeMap<String, BTreeSet<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> bool {
    if visiting.contains(node) {
        return true;
    }
    if visited.contains(node) {
        return false;
    }
    visiting.insert(node.to_string());
    if let Some(neighbors) = adj.get(node) {
        for next in neighbors {
            if has_cycle(next, adj, visiting, visited) {
                return true;
            }
        }
    }
    visiting.remove(node);
    visited.insert(node.to_string());
    false
}

#[test]
fn test_strict_5_layer_architecture_dag() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");

    let mut adj: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for entry in fs::read_dir(&src_dir).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let module_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("file stem")
            .to_string();

        let from_layer = module_layer(&module_name)
            .unwrap_or_else(|| panic!("Unknown module '{}' in src/", module_name));

        let content = fs::read_to_string(&path).expect("read source file");
        let mut deps = parse_crate_dependencies(&content);
        deps.remove(&module_name);

        for target in &deps {
            let to_layer = module_layer(target)
                .unwrap_or_else(|| panic!("Unknown target module '{}'", target));

            assert!(
                to_layer <= from_layer,
                "Upward layer dependency violation: `{module_name}` (Layer {from_layer}) imports `{target}` (Layer {to_layer})"
            );

            if (2..4).contains(&from_layer) {
                assert!(
                    to_layer < from_layer,
                    "Same-layer sibling coupling violation in Layer {from_layer}: `{module_name}` imports `{target}`"
                );
            }
        }

        adj.insert(module_name, deps);
    }

    assert_eq!(adj.len(), 12, "Expected 12 source modules in chipsrc-core");

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for node in adj.keys() {
        assert!(
            !has_cycle(node, &adj, &mut visiting, &mut visited),
            "Circular dependency detected starting at module `{node}`"
        );
    }
}
