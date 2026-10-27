use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Supported programming languages for AST extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LanguageKind {
    C,
    Cpp,
    Rust,
    Python,
    TypeScript,
    Tsx,
    JavaScript,
    Jsx,
}

impl LanguageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Rust => "rust",
            Self::Python => "python",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::JavaScript => "javascript",
            Self::Jsx => "jsx",
        }
    }

    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_ascii_lowercase().as_str() {
            "c" | "h" => Some(Self::C),
            "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" | "inl" => Some(Self::Cpp),
            "rs" => Some(Self::Rust),
            "py" | "pyi" => Some(Self::Python),
            "ts" | "mts" | "cts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "js" | "mjs" | "cjs" => Some(Self::JavaScript),
            "jsx" => Some(Self::Jsx),
            _ => None,
        }
    }
}

/// Source file ownership scope to separate first-party code from large vendor SDKs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileScope {
    FirstParty,
    VendorSdk,
    Test,
}

impl FileScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstParty => "first_party",
            Self::VendorSdk => "vendor_sdk",
            Self::Test => "test",
        }
    }
}

/// Canonical architectural layer detected from repository path structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchLayer {
    App,
    Bsp,
    Drivers,
    Config,
    Libs,
    Domain,
    Services,
    Api,
    Core,
    Cli,
    VendorHal,
    Tests,
    Other,
}

impl ArchLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Bsp => "bsp",
            Self::Drivers => "drvs",
            Self::Config => "config",
            Self::Libs => "libs",
            Self::Domain => "domain",
            Self::Services => "services",
            Self::Api => "api",
            Self::Core => "core",
            Self::Cli => "cli",
            Self::VendorHal => "vendor_hal",
            Self::Tests => "tests",
            Self::Other => "other",
        }
    }

    /// Numeric layer rank (higher = higher level orchestration, lower = lower level primitive/driver)
    /// used to detect upward architectural layer dependency violations.
    pub fn rank(self) -> u8 {
        match self {
            Self::Cli | Self::Api | Self::App => 5,
            Self::Core | Self::Services => 4,
            Self::Bsp => 3,
            Self::Drivers | Self::Domain => 2,
            Self::Config | Self::Libs => 1,
            Self::VendorHal => 0,
            Self::Tests | Self::Other => 3,
        }
    }
}

/// Kind of callable or executable symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Method,
    Isr,
    Constructor,
    Entrypoint,
}

impl SymbolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Function => "fn",
            Self::Method => "method",
            Self::Isr => "isr",
            Self::Constructor => "ctor",
            Self::Entrypoint => "entrypoint",
        }
    }
}

/// Symbol or type visibility modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Private,
    Protected,
    Internal,
    Static,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "pub",
            Self::Private => "priv",
            Self::Protected => "prot",
            Self::Internal => "internal",
            Self::Static => "static",
        }
    }
}

/// Kind of data structure or type definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Struct,
    Enum,
    Union,
    Trait,
    Interface,
    Class,
    Typedef,
    TypeAlias,
}

impl TypeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Union => "union",
            Self::Trait => "trait",
            Self::Interface => "interface",
            Self::Class => "class",
            Self::Typedef => "typedef",
            Self::TypeAlias => "type_alias",
        }
    }
}

/// Kind of macro, compile-time constant, or MMIO register construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacroKind {
    ObjectMacro,
    FunctionMacro,
    Constant,
    MmioAddress,
    Bitmask,
    RegisterAccess,
    LinkerSection,
}

impl MacroKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObjectMacro => "macro",
            Self::FunctionMacro => "fn_macro",
            Self::Constant => "const",
            Self::MmioAddress => "mmio_addr",
            Self::Bitmask => "bitmask",
            Self::RegisterAccess => "reg_access",
            Self::LinkerSection => "linker_section",
        }
    }
}

/// Provenance and confidence tier for resolved cross-file call and xref edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionTier {
    SameFile,
    ImportResolved,
    UniqueGlobal,
    AmbiguousName,
    ExternalOrMacro,
}

impl ResolutionTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameFile => "same_file",
            Self::ImportResolved => "import_resolved",
            Self::UniqueGlobal => "unique_global",
            Self::AmbiguousName => "ambiguous_name",
            Self::ExternalOrMacro => "external_or_macro",
        }
    }

    pub fn is_resolved(self) -> bool {
        !matches!(self, Self::ExternalOrMacro)
    }
}

/// Vendor SDK handling mode for bundle generation.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum VendorMode {
    /// Index all vendor symbols in TSVs, but only surface vendor APIs/registers actively used by first-party code in INDEX.md and shards.
    #[default]
    Active,
    /// Include all vendor SDK files and shards in full detail.
    All,
    /// Skip vendor SDK directories completely during scanning.
    None,
}

impl VendorMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::All => "all",
            Self::None => "none",
        }
    }
}

/// Discovered source file metadata with deterministic content hash for incremental updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannedFile {
    pub rel_path: String,
    pub abs_path: PathBuf,
    pub language: LanguageKind,
    pub scope: FileScope,
    pub arch_layer: ArchLayer,
    pub size_bytes: u64,
    pub mtime_secs: u64,
    pub blake3_hash: String,
    pub line_count: usize,
}

/// Extracted function, method, constructor, entrypoint, or ISR definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedSymbol {
    pub symbol_id: String,
    pub name: String,
    pub qualified_name: String,
    pub kind: SymbolKind,
    pub visibility: Visibility,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub signature: String,
    pub doc_summary: String,
    pub enclosing_type: Option<String>,
    pub scope: FileScope,
    pub arch_layer: ArchLayer,
    pub section_id: String,
}

/// Extracted struct, enum, union, trait, interface, class, or typedef definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedType {
    pub type_id: String,
    pub name: String,
    pub kind: TypeKind,
    pub visibility: Visibility,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub fields_summary: String,
    pub doc_summary: String,
    pub scope: FileScope,
    pub arch_layer: ArchLayer,
    pub section_id: String,
}

/// Extracted `#define` macro, compile-time constant, hex MMIO address, bitmask, or hardware register access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedMacro {
    pub name: String,
    pub kind: MacroKind,
    pub value_or_args: String,
    pub hex_addr: Option<String>,
    pub file: String,
    pub line: usize,
    pub scope: FileScope,
    pub arch_layer: ArchLayer,
    pub section_id: String,
    pub description: String,
}

/// Extracted import, `use`, or `#include` directive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedImport {
    pub file: String,
    pub line: usize,
    pub raw_path: String,
    pub imported_names: Vec<String>,
    pub is_system: bool,
}

/// Unresolved syntactic call expression attributed to its enclosing function/method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCallSite {
    pub caller_file: String,
    pub caller_name: String,
    pub caller_start_line: usize,
    pub callee_name: String,
    pub receiver_or_qualifier: Option<String>,
    pub call_line: usize,
}

/// Raw cross-reference occurrence extracted from a file AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawXrefSite {
    pub file: String,
    pub line: usize,
    pub enclosing_symbol: Option<String>,
    pub target_name: String,
    pub category: String,
    pub context: String,
}

/// Complete AST extraction output for a single file, cached in `cache.json` for incremental rebuilds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedFileUnit {
    pub scanned: ScannedFile,
    pub symbols: Vec<ExtractedSymbol>,
    pub types: Vec<ExtractedType>,
    pub macros: Vec<ExtractedMacro>,
    pub imports: Vec<ExtractedImport>,
    pub raw_calls: Vec<RawCallSite>,
    pub raw_xrefs: Vec<RawXrefSite>,
    pub parse_errors: usize,
}

/// Persistent per-file AST cache stored in `output/<stem>/cache.json` so incremental code edits re-parse only changed files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IncrementalAstCache {
    pub schema_version: String,
    pub repo_root: String,
    pub vendor_mode: VendorMode,
    pub files: BTreeMap<String, ParsedFileUnit>,
}

/// Symbol enriched with deterministic PageRank, degree centrality, and SCC cycle info.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RankedSymbol {
    pub symbol: ExtractedSymbol,
    pub pagerank: f64,
    pub in_degree: usize,
    pub out_degree: usize,
    pub is_god_node: bool,
    pub is_entrypoint: bool,
    pub scc_id: Option<usize>,
}

/// Resolved caller -> callee edge emitted to `index/calls.tsv`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCallEdge {
    pub caller_id: String,
    pub caller_name: String,
    pub callee_name: String,
    pub callee_id: String,
    pub file: String,
    pub line: usize,
    pub tier: ResolutionTier,
    pub section_id: String,
}

/// Cross-reference entry emitted to `index/xref.tsv`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefEntry {
    pub symbol: String,
    pub category: String,
    pub relation: String,
    pub target: String,
    pub file: String,
    pub line: usize,
    pub section_id: String,
    pub context: String,
}

/// Architectural layer-to-layer dependency summary edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerDependencyEdge {
    pub from_layer: String,
    pub to_layer: String,
    pub call_count: usize,
    pub import_count: usize,
    pub is_upward_violation: bool,
}

/// Strongly Connected Component (SCC) cyclic dependency cluster with 2+ mutually recursive symbols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CyclicCluster {
    pub scc_id: usize,
    pub symbols: Vec<String>,
    pub files: Vec<String>,
}

/// Summary of the active vendor SDK / HAL / MMIO surface referenced by first-party code.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorSurfaceSummary {
    pub total_vendor_files: usize,
    pub total_vendor_symbols: usize,
    pub active_vendor_symbols: Vec<String>,
    pub active_mmio_registers: Vec<String>,
    pub active_vendor_headers: Vec<String>,
}

/// Metadata row for an architectural module shard (`index/sections.tsv`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionSummary {
    pub section_id: String,
    pub title: String,
    pub module_path: String,
    pub arch_layer: String,
    pub scope: String,
    pub file_count: usize,
    pub symbol_count: usize,
    pub type_count: usize,
    pub macro_count: usize,
    pub token_estimate: usize,
    pub md_file: String,
}

/// Rendered architectural module shard (`sections/<NN>-<slug>.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionShard {
    pub summary: SectionSummary,
    pub files: Vec<String>,
    pub depends_on_sections: Vec<String>,
    pub depended_by_sections: Vec<String>,
    pub markdown_body: String,
}

/// All assembled index tables and graph analyses for a repository bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BundleIndexes {
    pub sections: Vec<SectionSummary>,
    pub symbols: Vec<RankedSymbol>,
    pub types: Vec<ExtractedType>,
    pub calls: Vec<ResolvedCallEdge>,
    pub macros: Vec<ExtractedMacro>,
    pub xrefs: Vec<XrefEntry>,
    pub god_nodes: Vec<RankedSymbol>,
    pub entrypoints: Vec<RankedSymbol>,
    pub layer_edges: Vec<LayerDependencyEdge>,
    pub cycles: Vec<CyclicCluster>,
    pub vendor_surface: VendorSurfaceSummary,
}

/// Per-language file and line count breakdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageStat {
    pub language: String,
    pub files: usize,
    pub lines: usize,
    pub first_party_files: usize,
    pub vendor_files: usize,
}

/// Repository-level metadata serialized in `meta.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoMetadata {
    pub repo_name: String,
    pub source_root: String,
    pub fingerprint: String,
    pub vendor_mode: VendorMode,
    pub total_files: usize,
    pub first_party_files: usize,
    pub vendor_files: usize,
    pub test_files: usize,
    pub total_lines: usize,
    pub languages: Vec<LanguageStat>,
    pub section_count: usize,
    pub symbol_count: usize,
    pub type_count: usize,
    pub call_edge_count: usize,
    pub macro_count: usize,
    pub xref_count: usize,
    pub god_node_count: usize,
    pub entrypoint_count: usize,
    pub elapsed_ms: u64,
    pub incremental_reused_files: usize,
    pub incremental_reparsed_files: usize,
}

/// Conversion health and token-efficiency report serialized in `meta.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SanityReport {
    pub score: u8,
    pub parse_clean_ratio: f64,
    pub call_resolution_ratio: f64,
    pub raw_source_tokens_est: usize,
    pub bundle_index_tokens_est: usize,
    pub token_compression_ratio: f64,
    pub warnings: Vec<String>,
}

/// On-disk structure of `meta.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BundleMetaFile {
    pub metadata: RepoMetadata,
    pub sanity: SanityReport,
}

/// Configuration for repository conversion / indexing.
#[derive(Debug, Clone)]
pub struct ConvertConfig {
    pub repo_path: PathBuf,
    pub output_dir: PathBuf,
    pub single_file: bool,
    pub force: bool,
    pub vendor_mode: VendorMode,
    pub max_file_bytes: u64,
}

impl ConvertConfig {
    pub fn new(repo_path: PathBuf, output_dir: PathBuf) -> Self {
        Self {
            repo_path,
            output_dir,
            single_file: false,
            force: false,
            vendor_mode: VendorMode::Active,
            max_file_bytes: 4 * 1024 * 1024, // 4 MiB default per-file cap
        }
    }
}

/// Complete output of converting/indexing a repository.
#[derive(Debug, Clone)]
pub struct ConversionBundle {
    pub output_dir: PathBuf,
    pub metadata: RepoMetadata,
    pub sanity: SanityReport,
    pub sections: Vec<SectionShard>,
    pub indexes: BundleIndexes,
    pub cache_hit: bool,
    pub claudeignore_updated: bool,
}

/// Lightweight inspection report returned by `inspect_repo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectReport {
    pub repo_name: String,
    pub source_root: String,
    pub fingerprint: String,
    pub total_files: usize,
    pub first_party_files: usize,
    pub vendor_files: usize,
    pub test_files: usize,
    pub total_lines: usize,
    pub languages: Vec<LanguageStat>,
    pub detected_layers: Vec<String>,
}

/// Single search hit across TSV indexes or section shards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    pub bundle_name: String,
    pub kind: String,
    pub file: String,
    pub line: usize,
    pub snippet: String,
}

/// Status of an indexed bundle in the workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleStatusEntry {
    pub bundle_name: String,
    pub bundle_dir: PathBuf,
    pub source_root: String,
    pub is_fresh: bool,
    pub changed_files_count: usize,
    pub symbol_count: usize,
    pub section_count: usize,
}
