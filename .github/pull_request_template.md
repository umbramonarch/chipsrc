## Summary

<!-- Describe what this pull request changes and why. -->

## Related Issue

<!-- Link the related issue or task (e.g., Closes #123). -->

## Test Plan

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (for user-visible changes)

## Quality Checklist

- [ ] AST extraction heuristics remain 100% deterministic and language/vendor-neutral
- [ ] Strict Layered DAG (`Layer 0` -> `Layer 5`) is preserved with no upward dependencies
- [ ] No generated `output/` bundles are committed
