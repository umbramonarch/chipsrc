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
            "tsx" | "astro" | "vue" | "svelte" => Some(Self::Tsx),
            "js" | "mjs" | "cjs" => Some(Self::JavaScript),
            "jsx" => Some(Self::Jsx),
            _ => None,
        }
    }

    /// Returns the language family group ID so callers and imports only bind across
    /// compatible language ecosystems (`C/C++` = 0, `Rust` = 1, `Python` = 2, `TS/JS/SFC` = 3).
    pub fn language_family(self) -> u8 {
        match self {
            Self::C | Self::Cpp => 0,
            Self::Rust => 1,
            Self::Python => 2,
            Self::TypeScript | Self::Tsx | Self::JavaScript | Self::Jsx => 3,
        }
    }
}

/// Source file ownership scope to separate first-party code from large vendor SDKs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileScope {
    #[serde(alias = "first-party", alias = "firstparty")]
    FirstParty,
    #[serde(alias = "vendor", alias = "vendor-sdk", alias = "vendorsdk")]
    VendorSdk,
    #[serde(alias = "tests")]
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

    /// Inverse of [`FileScope::as_str`] for index-table round-trips.
    pub fn parse_label(label: &str) -> Option<Self> {
        match label.trim() {
            "first_party" => Some(Self::FirstParty),
            "vendor_sdk" => Some(Self::VendorSdk),
            "test" => Some(Self::Test),
            _ => None,
        }
    }
}

/// Canonical architectural layer detected from repository path structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchLayer {
    #[serde(alias = "application", alias = "apps")]
    App,
    #[serde(alias = "board", alias = "platform")]
    Bsp,
    #[serde(alias = "drvs", alias = "drv", alias = "driver")]
    Drivers,
    #[serde(alias = "cfg", alias = "configs")]
    Config,
    #[serde(alias = "lib", alias = "utils", alias = "common")]
    Libs,
    #[serde(alias = "models", alias = "entities")]
    Domain,
    #[serde(alias = "service")]
    Services,
    #[serde(alias = "routes", alias = "frontend", alias = "web")]
    Api,
    #[serde(alias = "engine", alias = "kernel")]
    Core,
    #[serde(alias = "bin", alias = "tools")]
    Cli,
    #[serde(alias = "vendor", alias = "hal", alias = "vendor-hal")]
    VendorHal,
    #[serde(alias = "test")]
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

    /// Inverse of [`ArchLayer::as_str`] for index-table round-trips.
    pub fn parse_label(label: &str) -> Option<Self> {
        match label.trim() {
            "app" => Some(Self::App),
            "bsp" => Some(Self::Bsp),
            "drvs" => Some(Self::Drivers),
            "config" => Some(Self::Config),
            "libs" => Some(Self::Libs),
            "domain" => Some(Self::Domain),
            "services" => Some(Self::Services),
            "api" => Some(Self::Api),
            "core" => Some(Self::Core),
            "cli" => Some(Self::Cli),
            "vendor_hal" => Some(Self::VendorHal),
            "tests" => Some(Self::Tests),
            "other" => Some(Self::Other),
            _ => None,
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

    /// Inverse of [`SymbolKind::as_str`] for index-table round-trips.
    pub fn parse_label(label: &str) -> Option<Self> {
        match label.trim() {
            "fn" => Some(Self::Function),
            "method" => Some(Self::Method),
            "isr" => Some(Self::Isr),
            "ctor" => Some(Self::Constructor),
            "entrypoint" => Some(Self::Entrypoint),
            _ => None,
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

    /// Inverse of [`Visibility::as_str`] for index-table round-trips.
    pub fn parse_label(label: &str) -> Option<Self> {
        match label.trim() {
            "pub" => Some(Self::Public),
            "priv" => Some(Self::Private),
            "prot" => Some(Self::Protected),
            "internal" => Some(Self::Internal),
            "static" => Some(Self::Static),
            _ => None,
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

    /// Inverse of [`TypeKind::as_str`] for index-table round-trips.
    pub fn parse_label(label: &str) -> Option<Self> {
        match label.trim() {
            "struct" => Some(Self::Struct),
            "enum" => Some(Self::Enum),
            "union" => Some(Self::Union),
            "trait" => Some(Self::Trait),
            "interface" => Some(Self::Interface),
            "class" => Some(Self::Class),
            "typedef" => Some(Self::Typedef),
            "type_alias" => Some(Self::TypeAlias),
            _ => None,
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

    /// Inverse of [`MacroKind::as_str`] for index-table round-trips.
    pub fn parse_label(label: &str) -> Option<Self> {
        match label.trim() {
            "macro" => Some(Self::ObjectMacro),
            "fn_macro" => Some(Self::FunctionMacro),
            "const" => Some(Self::Constant),
            "mmio_addr" => Some(Self::MmioAddress),
            "bitmask" => Some(Self::Bitmask),
            "reg_access" => Some(Self::RegisterAccess),
            "linker_section" => Some(Self::LinkerSection),
            _ => None,
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

    /// High-confidence call resolution tiers (`SameFile`, `ImportResolved`, `UniqueGlobal`)
    /// eligible for PageRank hub scoring, layer violation checks, and resolution metrics.
    pub fn is_high_confidence(self) -> bool {
        matches!(
            self,
            Self::SameFile | Self::ImportResolved | Self::UniqueGlobal
        )
    }

    /// Inverse of [`ResolutionTier::as_str`] for index-table round-trips.
    pub fn parse_label(label: &str) -> Option<Self> {
        match label.trim() {
            "same_file" => Some(Self::SameFile),
            "import_resolved" => Some(Self::ImportResolved),
            "unique_global" => Some(Self::UniqueGlobal),
            "ambiguous_name" => Some(Self::AmbiguousName),
            "external_or_macro" => Some(Self::ExternalOrMacro),
            _ => None,
        }
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
    #[serde(default)]
    pub mtime_nanos: u32,
    pub blake3_hash: String,
    pub line_count: usize,
}

/// Extracted function, method, constructor, entrypoint, or ISR definition.
///
/// Cache shards use one-letter field names (they are 30-40% of a 12k-file bundle's bytes and that
/// bundle is rewritten on every cold build) and omit the owning path: every entry in a shard
/// belongs to the shard's own file, so `file`/`symbol_id` are restored by
/// [`ParsedFileUnit::restore_per_file_fields`] on load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedSymbol {
    /// `{file}::{name}`, never serialized (reconstructed on load by
    /// [`ParsedFileUnit::restore_per_file_fields`]).
    #[serde(default, skip_serializing)]
    pub symbol_id: String,
    #[serde(rename = "n", alias = "name")]
    pub name: String,
    #[serde(rename = "q", alias = "qualified_name")]
    pub qualified_name: String,
    #[serde(rename = "k", alias = "kind")]
    pub kind: SymbolKind,
    #[serde(rename = "v", alias = "visibility")]
    pub visibility: Visibility,
    /// Owning file, never serialized (the shard's own `scanned.rel_path`).
    #[serde(default, skip_serializing)]
    pub file: String,
    #[serde(rename = "s", alias = "start_line")]
    pub start_line: usize,
    #[serde(rename = "e", alias = "end_line")]
    pub end_line: usize,
    #[serde(rename = "g", alias = "signature")]
    pub signature: String,
    #[serde(rename = "d", alias = "doc_summary")]
    pub doc_summary: String,
    #[serde(rename = "t", alias = "enclosing_type")]
    pub enclosing_type: Option<String>,
    #[serde(rename = "c", alias = "scope")]
    pub scope: FileScope,
    #[serde(rename = "a", alias = "arch_layer")]
    pub arch_layer: ArchLayer,
    #[serde(rename = "i", alias = "section_id")]
    pub section_id: String,
}

/// Extracted struct, enum, union, trait, interface, class, or typedef definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedType {
    #[serde(rename = "i", alias = "type_id")]
    pub type_id: String,
    #[serde(rename = "n", alias = "name")]
    pub name: String,
    #[serde(rename = "k", alias = "kind")]
    pub kind: TypeKind,
    #[serde(rename = "v", alias = "visibility")]
    pub visibility: Visibility,
    /// Owning file, never serialized (the shard's own `scanned.rel_path`).
    #[serde(default, skip_serializing)]
    pub file: String,
    #[serde(rename = "s", alias = "start_line")]
    pub start_line: usize,
    #[serde(rename = "e", alias = "end_line")]
    pub end_line: usize,
    #[serde(rename = "f", alias = "fields_summary")]
    pub fields_summary: String,
    #[serde(rename = "d", alias = "doc_summary")]
    pub doc_summary: String,
    #[serde(rename = "c", alias = "scope")]
    pub scope: FileScope,
    #[serde(rename = "a", alias = "arch_layer")]
    pub arch_layer: ArchLayer,
    #[serde(rename = "t", alias = "section_id")]
    pub section_id: String,
}

/// Extracted `#define` macro, compile-time constant, hex MMIO address, bitmask, or hardware register access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedMacro {
    #[serde(rename = "n", alias = "name")]
    pub name: String,
    #[serde(rename = "k", alias = "kind")]
    pub kind: MacroKind,
    #[serde(rename = "v", alias = "value_or_args")]
    pub value_or_args: String,
    #[serde(rename = "h", alias = "hex_addr")]
    pub hex_addr: Option<String>,
    /// Owning file, never serialized (the shard's own `scanned.rel_path`).
    #[serde(default, skip_serializing)]
    pub file: String,
    #[serde(rename = "l", alias = "line")]
    pub line: usize,
    #[serde(rename = "c", alias = "scope")]
    pub scope: FileScope,
    #[serde(rename = "a", alias = "arch_layer")]
    pub arch_layer: ArchLayer,
    #[serde(rename = "t", alias = "section_id")]
    pub section_id: String,
    #[serde(rename = "d", alias = "description")]
    pub description: String,
}

/// Extracted import, `use`, or `#include` directive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedImport {
    /// Owning file, never serialized (the shard's own `scanned.rel_path`).
    #[serde(default, skip_serializing)]
    pub file: String,
    #[serde(rename = "l", alias = "line")]
    pub line: usize,
    #[serde(rename = "p", alias = "raw_path")]
    pub raw_path: String,
    #[serde(rename = "i", alias = "imported_names")]
    pub imported_names: Vec<String>,
    #[serde(rename = "s", alias = "is_system")]
    pub is_system: bool,
}

/// Unresolved syntactic call expression attributed to its enclosing function/method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCallSite {
    /// Owning file, never serialized (the shard's own `scanned.rel_path`).
    #[serde(default, skip_serializing)]
    pub caller_file: String,
    #[serde(rename = "n", alias = "caller_name")]
    pub caller_name: String,
    #[serde(rename = "s", alias = "caller_start_line")]
    pub caller_start_line: usize,
    #[serde(rename = "c", alias = "callee_name")]
    pub callee_name: String,
    #[serde(rename = "r", alias = "receiver_or_qualifier")]
    pub receiver_or_qualifier: Option<String>,
    #[serde(rename = "l", alias = "call_line")]
    pub call_line: usize,
}

/// Raw cross-reference occurrence extracted from a file AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawXrefSite {
    /// Owning file, never serialized (the shard's own `scanned.rel_path`).
    #[serde(default, skip_serializing)]
    pub file: String,
    #[serde(rename = "l", alias = "line")]
    pub line: usize,
    #[serde(rename = "e", alias = "enclosing_symbol")]
    pub enclosing_symbol: Option<String>,
    #[serde(rename = "n", alias = "target_name")]
    pub target_name: String,
    #[serde(rename = "c", alias = "category")]
    pub category: String,
    #[serde(rename = "x", alias = "context")]
    pub context: String,
}

/// Complete AST extraction output for a single file, cached in `cache/` for incremental rebuilds.
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

impl ParsedFileUnit {
    /// Re-attaches the per-file fields that [`crate::emitter::prepare_cache_shard`] omits from a
    /// cache shard: every entry belongs to `self.scanned.rel_path`, so the paths are stored once
    /// (as the unit's `scanned.rel_path`) instead of once per symbol/type/macro/call/xref.
    ///
    /// Idempotent, and a no-op for units that already carry the values (in-memory parses and
    /// shards written before this compaction).
    pub fn restore_per_file_fields(&mut self) {
        let rel_path = self.scanned.rel_path.as_str();
        if rel_path.is_empty() {
            return;
        }
        for s in &mut self.symbols {
            if s.file.is_empty() {
                s.file = rel_path.to_string();
            }
            if s.symbol_id.is_empty() {
                s.symbol_id = format!("{}::{}", s.file, s.qualified_name);
            }
        }
        for t in &mut self.types {
            if t.file.is_empty() {
                t.file = rel_path.to_string();
            }
        }
        for m in &mut self.macros {
            if m.file.is_empty() {
                m.file = rel_path.to_string();
            }
        }
        for imp in &mut self.imports {
            if imp.file.is_empty() {
                imp.file = rel_path.to_string();
            }
        }
        for c in &mut self.raw_calls {
            if c.caller_file.is_empty() {
                c.caller_file = rel_path.to_string();
            }
        }
        for x in &mut self.raw_xrefs {
            if x.file.is_empty() {
                x.file = rel_path.to_string();
            }
        }
    }

    /// Computes a deterministic 16-character BLAKE3 structural digest over extracted symbols,
    /// types, macros, imports, raw calls, and raw xrefs while excluding line numbers and doc
    /// comments so comment-only or line-shift edits can short-circuit full graph relinking.
    ///
    /// The detected language participates in the digest: a `.h` header whose content flips
    /// between C and C++ changes which declarations the grammar sees and which language labels
    /// the rendered artifacts carry, so it must never take a digest-no-op short circuit.
    pub fn structural_digest(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(self.scanned.language.as_str().as_bytes());
        h.update(b"|");
        h.update(self.scanned.scope.as_str().as_bytes());
        h.update(b"|");
        h.update(self.scanned.arch_layer.as_str().as_bytes());
        h.update(b"\n");
        for s in &self.symbols {
            h.update(b"S:");
            h.update(s.name.as_bytes());
            h.update(b"|");
            h.update(s.kind.as_str().as_bytes());
            h.update(b"|");
            h.update(s.visibility.as_str().as_bytes());
            h.update(b"|");
            h.update(s.signature.as_bytes());
            h.update(b"|");
            if let Some(ref et) = s.enclosing_type {
                h.update(et.as_bytes());
            }
            h.update(b"|");
            h.update(s.scope.as_str().as_bytes());
            h.update(b"\n");
        }
        for t in &self.types {
            h.update(b"T:");
            h.update(t.name.as_bytes());
            h.update(b"|");
            h.update(t.kind.as_str().as_bytes());
            h.update(b"|");
            h.update(t.visibility.as_str().as_bytes());
            h.update(b"|");
            h.update(t.fields_summary.as_bytes());
            h.update(b"\n");
        }
        for m in &self.macros {
            h.update(b"M:");
            h.update(m.name.as_bytes());
            h.update(b"|");
            h.update(m.kind.as_str().as_bytes());
            h.update(b"|");
            h.update(m.value_or_args.as_bytes());
            h.update(b"\n");
        }
        for imp in &self.imports {
            h.update(b"I:");
            h.update(imp.raw_path.as_bytes());
            h.update(b"|");
            for name in &imp.imported_names {
                h.update(name.as_bytes());
                h.update(b",");
            }
            h.update(b"\n");
        }
        for c in &self.raw_calls {
            h.update(b"C:");
            h.update(c.caller_name.as_bytes());
            h.update(b"|");
            h.update(c.callee_name.as_bytes());
            h.update(b"|");
            if let Some(ref q) = c.receiver_or_qualifier {
                h.update(q.as_bytes());
            }
            h.update(b"\n");
        }
        for x in &self.raw_xrefs {
            h.update(b"X:");
            h.update(x.target_name.as_bytes());
            h.update(b"|");
            h.update(x.category.as_bytes());
            h.update(b"|");
            if let Some(ref es) = x.enclosing_symbol {
                h.update(es.as_bytes());
            }
            h.update(b"\n");
        }
        h.finalize().to_hex()[..16].to_string()
    }
}

/// Entry in `cache/manifest.json` pointing to a per-file AST shard (`cache/<shard_key>.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheShardEntry {
    pub blake3_hash: String,
    pub shard: String,
    #[serde(default)]
    pub structural_digest: String,
}

impl CacheShardEntry {
    /// Computes a deterministic 16-hex-character BLAKE3 shard key from `rel_path` and `blake3_hash`
    /// so byte-identical files at different paths never alias to the same shard file.
    pub fn shard_key(rel_path: &str, blake3_hash: &str) -> String {
        let mut h = blake3::Hasher::new();
        h.update(rel_path.as_bytes());
        h.update(b"\0");
        h.update(blake3_hash.as_bytes());
        h.finalize().to_hex()[..16].to_string()
    }

    /// Formats the relative bundle shard path (`cache/<shard_key>.json`) for `(rel_path, blake3_hash)`.
    pub fn shard_rel_path(rel_path: &str, blake3_hash: &str) -> String {
        format!("cache/{}.json", Self::shard_key(rel_path, blake3_hash))
    }
}

/// Number of per-file cache units grouped into one packed shard on large repositories.
///
/// 256 units keeps the pack count low (STM32CubeF4: 12,471 units -> 49 packs of ~5-7 MB instead of
/// 195 packs of ~1.3 MB), which halves the small-file creation cost on the cold path without
/// exceeding the ~8 MiB budget of a single sequential write.
pub const CACHE_PACK_UNITS: usize = 256;

/// Repositories with more source files than this store their per-file AST cache as packed shards
/// (`cache/pack-<16hex>.json`, [`CACHE_PACK_UNITS`] units each) instead of one small file per
/// source file. Creating 12k tiny files costs minutes on a rotational disk; 49 packs do not.
pub const CACHE_PACK_FILE_THRESHOLD: usize = 500;

/// File-name prefix of a packed cache shard.
pub const CACHE_PACK_PREFIX: &str = "pack-";

/// Returns `true` when `shard` (a bundle-relative path or bare file name) names a packed shard.
pub fn is_packed_cache_shard(shard: &str) -> bool {
    shard
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name| name.starts_with(CACHE_PACK_PREFIX))
}

/// Computes the deterministic file name of the packed shard holding the given
/// `(rel_path, blake3_hash)` pairs: `pack-<16hex>.json`, where `<16hex>` is BLAKE3 over the pairs
/// sorted by `rel_path`.
pub fn cache_pack_file_name<'a, I>(pairs: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut sorted: Vec<(&str, &str)> = pairs.into_iter().collect();
    sorted.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    for (rel_path, blake3_hash) in sorted {
        hasher.update(rel_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(blake3_hash.as_bytes());
        hasher.update(b"\n");
    }
    format!(
        "{CACHE_PACK_PREFIX}{}.json",
        &hasher.finalize().to_hex()[..16]
    )
}

/// Computes the deterministic packed shard file name for a chunk of parsed units.
pub fn cache_pack_shard_name(units: &[&ParsedFileUnit]) -> String {
    cache_pack_file_name(units.iter().map(|unit| {
        (
            unit.scanned.rel_path.as_str(),
            unit.scanned.blake3_hash.as_str(),
        )
    }))
}

/// Per-file cache manifest stored at `output/<stem>/cache/manifest.json` (schema `2.1.0`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheManifest {
    pub schema_version: String,
    pub repo_root: String,
    pub vendor_mode: VendorMode,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub blueprint_hash: String,
    pub files: BTreeMap<String, CacheShardEntry>,
}

/// Persistent per-file AST cache stored in `output/<stem>/cache/` so incremental code edits re-parse only changed files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IncrementalAstCache {
    pub schema_version: String,
    pub repo_root: String,
    pub vendor_mode: VendorMode,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub blueprint_hash: String,
    pub files: BTreeMap<String, ParsedFileUnit>,
}

/// Custom MMIO hex address range defined in `.chipsrc.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MmioAddressRange {
    pub start: String,
    pub end: String,
    #[serde(alias = "description")]
    pub name: String,
}

fn deserialize_c_qualifiers<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum QualifiersRepr {
        List(Vec<String>),
        Map(BTreeMap<String, String>),
    }

    match Option::<QualifiersRepr>::deserialize(deserializer)? {
        Some(QualifiersRepr::List(v)) => Ok(v),
        Some(QualifiersRepr::Map(m)) => Ok(m.into_keys().collect()),
        None => Ok(Vec::new()),
    }
}

/// Agent-once repository onboarding blueprint (`.chipsrc.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RepoBlueprint {
    /// Path prefix -> FileScope ("first_party" | "vendor_sdk" | "test")
    pub scopes: BTreeMap<String, FileScope>,
    /// Path prefix -> ArchLayer ("app", "bsp", "drvs", "config", "libs", "domain", "services", "api", "core", "cli", "vendor_hal", "tests")
    pub layers: BTreeMap<String, ArchLayer>,
    /// Path prefix -> custom module shard slug/path (e.g. "packages/ui" -> "packages-ui")
    pub shards: BTreeMap<String, String>,
    /// Additional directories or glob prefixes to ignore
    pub ignore_dirs: Vec<String>,
    /// Additional C/C++ storage/attribute qualifier macros to strip before declarators
    #[serde(deserialize_with = "deserialize_c_qualifiers")]
    pub c_qualifiers: Vec<String>,
    /// Additional function names or attributes to classify as entrypoints
    pub entrypoints: Vec<String>,
    /// Additional function names or attributes to classify as hardware ISRs
    pub isr_patterns: Vec<String>,
    /// Custom MMIO hex address ranges (e.g. RISC-V `0x10000000`..`0x1FFFFFFF`)
    pub mmio_ranges: Vec<MmioAddressRange>,
}

/// Symbol enriched with deterministic PageRank, HITS hub/authority scores, degree centrality, and SCC cycle info.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RankedSymbol {
    pub symbol: ExtractedSymbol,
    pub pagerank: f64,
    #[serde(default)]
    pub hub_score: f64,
    #[serde(default)]
    pub authority_score: f64,
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

/// Identity of a linked symbol inside `cache/graph_state.json`.
///
/// `start_line` is the coordinate the symbol had when the graph was linked; it disambiguates
/// duplicate `symbol_id`s (e.g. two same-named definitions in one file) and lets the
/// coordinate-shift tier re-attach graph metrics after line numbers move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphSymbolRef {
    pub symbol_id: String,
    pub start_line: usize,
}

/// Per-symbol graph annotations that cannot be re-derived from the AST alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SymbolGraphState {
    pub symbol_id: String,
    pub start_line: usize,
    pub pagerank: f64,
    #[serde(default)]
    pub hub_score: f64,
    #[serde(default)]
    pub authority_score: f64,
    pub in_degree: usize,
    pub out_degree: usize,
    #[serde(default)]
    pub is_god_node: bool,
    #[serde(default)]
    pub is_entrypoint: bool,
    #[serde(default)]
    pub scc_id: Option<usize>,
}

/// Reconstructible linked-graph state persisted at `cache/graph_state.json` next to the
/// per-file AST manifest. Holds only the analysis results that cannot be cheaply recomputed
/// from source (PageRank/HITS/degree/SCC annotations, god nodes, entrypoints, layer edges,
/// cycles, vendor surface); the entity tables themselves live in `index/*.tsv`.
///
/// Schema-versioned with `CACHE_SCHEMA_VERSION`; a missing, truncated, or version-mismatched
/// file simply disables the coordinate-shift tier (the caller falls back to a full rebuild).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GraphStateFile {
    pub schema_version: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub vendor_mode: VendorMode,
    #[serde(default)]
    pub symbols: Vec<SymbolGraphState>,
    #[serde(default)]
    pub god_nodes: Vec<GraphSymbolRef>,
    #[serde(default)]
    pub entrypoints: Vec<GraphSymbolRef>,
    #[serde(default)]
    pub layer_edges: Vec<LayerDependencyEdge>,
    #[serde(default)]
    pub cycles: Vec<CyclicCluster>,
    #[serde(default)]
    pub vendor_surface: VendorSurfaceSummary,
}

/// Name of the persisted linked-graph state file inside a bundle's `cache/` directory.
pub const GRAPH_STATE_FILE: &str = "graph_state.json";

/// Per-language file and line count breakdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageStat {
    pub language: String,
    pub files: usize,
    pub lines: usize,
    pub first_party_files: usize,
    pub vendor_files: usize,
}

/// Lightweight per-file freshness stamp stored in `meta.json` so `status` and
/// `auto_refresh_bundles` can detect modified files without deserializing `cache.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStamp {
    pub rel_path: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub mtime_secs: u64,
    #[serde(default)]
    pub mtime_nanos: u32,
    #[serde(default)]
    pub line_count: usize,
    pub blake3_hash: String,
    pub scope: FileScope,
    pub arch_layer: ArchLayer,
    /// Language chosen when the file content was last read (content-based `.h` C/C++
    /// disambiguation). Stat-only warm walks reuse it so incremental and `--force` builds report
    /// identical language counts. Absent in bundles written before header detection existed;
    /// callers fall back to the path extension in that case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<LanguageKind>,
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
    #[serde(default)]
    pub scan_ms: u64,
    #[serde(default)]
    pub parse_ms: u64,
    #[serde(default)]
    pub link_ms: u64,
    #[serde(default)]
    pub graph_ms: u64,
    #[serde(default)]
    pub shard_ms: u64,
    #[serde(default)]
    pub emit_ms: u64,
    /// Synchronization tier that produced this bundle: `cache_hit`, `digest_noop`,
    /// `coordinate_shift`, or `structural` (full link + graph).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub incremental_tier: String,
    pub incremental_reused_files: usize,
    pub incremental_reparsed_files: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_stamps: Vec<FileStamp>,
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

/// Default maximum source file size (4 MiB) indexed by `chipsrc`.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Current schema version for `cache/manifest.json` (`IncrementalAstCache`).
pub const CACHE_SCHEMA_VERSION: &str = "2.1.0";

/// Configuration for repository conversion / indexing.
#[derive(Debug, Clone)]
pub struct ConvertConfig {
    pub repo_path: PathBuf,
    pub output_dir: PathBuf,
    pub single_file: bool,
    pub force: bool,
    pub auto_sync: bool,
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
            auto_sync: false,
            vendor_mode: VendorMode::Active,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
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
    #[serde(default)]
    pub has_blueprint: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blueprint_error: Option<String>,
    #[serde(default)]
    pub unclassified_dirs: Vec<String>,
    #[serde(default)]
    pub detected_workspaces: Vec<String>,
    #[serde(default)]
    pub candidate_c_macros: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
