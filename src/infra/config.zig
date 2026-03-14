const std = @import("std");
const guardrails_mod = @import("../ai/guardrails.zig");
const body_policy = @import("../net/body_policy.zig");
const UnsupportedBodyBehavior = body_policy.UnsupportedBodyBehavior;
const runtime_model = @import("../net/runtime_model.zig");
const RuntimeModel = runtime_model.RuntimeModel;
const GuardrailMode = guardrails_mod.Mode;

pub const LogLevel = enum {
    debug,
    info,
    warn,
    error_,

    pub fn parse(s: []const u8) !LogLevel {
        if (std.mem.eql(u8, s, "debug")) return .debug;
        if (std.mem.eql(u8, s, "info")) return .info;
        if (std.mem.eql(u8, s, "warn")) return .warn;
        if (std.mem.eql(u8, s, "error")) return .error_;
        return error.InvalidLogLevel;
    }
};

pub const VaultBackend = enum {
    memory,
    file,
    external,

    pub fn parse(s: []const u8) !VaultBackend {
        if (std.mem.eql(u8, s, "memory")) return .memory;
        if (std.mem.eql(u8, s, "file")) return .file;
        if (std.mem.eql(u8, s, "external")) return .external;
        return error.InvalidVaultBackend;
    }

    pub fn asStr(self: VaultBackend) []const u8 {
        return switch (self) {
            .memory => "memory",
            .file => "file",
            .external => "external",
        };
    }
};

pub const Profile = enum {
    hipaa_safe_harbor,
    healthcare_lite,
    llm_basic,
    custom,

    pub fn parse(s: []const u8) !Profile {
        if (std.mem.eql(u8, s, "hipaa-safe-harbor")) return .hipaa_safe_harbor;
        if (std.mem.eql(u8, s, "healthcare-lite")) return .healthcare_lite;
        if (std.mem.eql(u8, s, "llm-basic")) return .llm_basic;
        if (std.mem.eql(u8, s, "custom")) return .custom;
        return error.InvalidProfile;
    }

    pub fn asStr(self: Profile) []const u8 {
        return switch (self) {
            .hipaa_safe_harbor => "hipaa-safe-harbor",
            .healthcare_lite => "healthcare-lite",
            .llm_basic => "llm-basic",
            .custom => "custom",
        };
    }

    pub fn apply(self: Profile, config: *Config) void {
        switch (self) {
            .hipaa_safe_harbor => {
                config.enable_email = true;
                config.enable_phone = true;
                config.enable_ip = true;
                config.enable_healthcare = true;
                config.enable_dates = true;
                config.enable_addresses = true;
                config.enable_fax = true;
                config.enable_accounts = true;
                config.enable_licenses = true;
                config.enable_urls = true;
                config.enable_vehicle_ids = true;
                config.enable_context_rules = true;
            },
            .healthcare_lite => {
                config.enable_email = true;
                config.enable_phone = true;
                config.enable_healthcare = true;
                config.enable_dates = true;
            },
            .llm_basic => {
                config.enable_email = true;
                config.enable_credit_card = true;
                config.enable_ip = true;
            },
            .custom => {
                // Do nothing; relies entirely on individual flags
            },
        }
    }
};

pub const ConfigSource = enum {
    default,
    env_var,
    cli_flag,

    pub fn asStr(self: ConfigSource) []const u8 {
        return switch (self) {
            .default => "default",
            .env_var => "env var",
            .cli_flag => "CLI flag",
        };
    }
};

pub const Config = struct {
    /// Centralised version string — referenced by /healthz and future endpoints.
    pub const version = "0.1.0";
    listen_host: []const u8 = "127.0.0.1",
    listen_host_src: ConfigSource = .default,
    listen_port: u16 = 8081,
    listen_port_src: ConfigSource = .default,
    target_host: []const u8 = "httpbin.org",
    target_host_src: ConfigSource = .default,
    target_port: u16 = 80,
    target_port_src: ConfigSource = .default,
    entity_file: ?[]const u8 = null,
    entity_file_src: ConfigSource = .default,
    fuzzy_threshold: f32 = 0.80,
    fuzzy_threshold_src: ConfigSource = .default,
    max_connections: u32 = 128,
    max_connections_src: ConfigSource = .default,
    runtime_model: RuntimeModel = .thread_per_connection,
    runtime_model_src: ConfigSource = .default,
    runtime_worker_threads: usize = 0,
    runtime_worker_threads_src: ConfigSource = .default,
    log_level: LogLevel = .info,
    log_level_src: ConfigSource = .default,
    watch_interval_ms: u64 = 1000,
    watch_interval_ms_src: ConfigSource = .default,
    admin_api: bool = false,
    admin_api_src: ConfigSource = .default,
    admin_token: ?[]const u8 = null,
    admin_token_src: ConfigSource = .default,
    admin_listen_address: ?[]const u8 = null,
    admin_listen_address_src: ConfigSource = .default,
    admin_allowlist: ?[]const u8 = null,
    admin_allowlist_src: ConfigSource = .default,
    admin_read_only: bool = false,
    admin_read_only_src: ConfigSource = .default,
    admin_mutation_rate_limit_per_minute: u32 = 60,
    admin_mutation_rate_limit_per_minute_src: ConfigSource = .default,
    entity_file_sync: bool = false,
    entity_file_sync_src: ConfigSource = .default,
    tls_cert: ?[]const u8 = null,
    tls_cert_src: ConfigSource = .default,
    tls_key: ?[]const u8 = null,
    tls_key_src: ConfigSource = .default,
    target_tls: bool = false,
    target_tls_src: ConfigSource = .default,
    ca_file: ?[]const u8 = null,
    ca_file_src: ConfigSource = .default,
    tls_no_system_ca: bool = false,
    tls_no_system_ca_src: ConfigSource = .default,
    max_body_size: usize = 10 * 1024 * 1024,
    max_body_size_src: ConfigSource = .default,
    upstream_connect_timeout_ms: u64 = 5_000,
    upstream_connect_timeout_ms_src: ConfigSource = .default,
    upstream_read_timeout_ms: u64 = 30_000,
    upstream_read_timeout_ms_src: ConfigSource = .default,
    upstream_request_timeout_ms: u64 = 60_000,
    upstream_request_timeout_ms_src: ConfigSource = .default,
    shutdown_drain_timeout_ms: u64 = 30_000,
    shutdown_drain_timeout_ms_src: ConfigSource = .default,
    log_file: ?[]const u8 = null,
    log_file_src: ConfigSource = .default,
    audit_log: bool = false,
    audit_log_src: ConfigSource = .default,
    unsupported_request_body_behavior: UnsupportedBodyBehavior = .reject,
    unsupported_request_body_behavior_src: ConfigSource = .default,
    unsupported_response_body_behavior: UnsupportedBodyBehavior = .bypass,
    unsupported_response_body_behavior_src: ConfigSource = .default,
    // --- Pattern library flags (Phase 5 / Epic 7) ---
    enable_email: bool = false,
    enable_email_src: ConfigSource = .default,
    enable_phone: bool = false,
    enable_phone_src: ConfigSource = .default,
    enable_credit_card: bool = false,
    enable_credit_card_src: ConfigSource = .default,
    enable_ip: bool = false,
    enable_ip_src: ConfigSource = .default,
    enable_healthcare: bool = false,
    enable_healthcare_src: ConfigSource = .default,
    enable_iban: bool = false,
    enable_iban_src: ConfigSource = .default,
    enable_uk_nino: bool = false,
    enable_uk_nino_src: ConfigSource = .default,
    enable_passport: bool = false,
    enable_passport_src: ConfigSource = .default,
    enable_intl_phone: bool = false,
    enable_intl_phone_src: ConfigSource = .default,
    // --- Phase 1 / V4 Pattern library flags ---
    enable_dates: bool = false,
    enable_dates_src: ConfigSource = .default,
    enable_addresses: bool = false,
    enable_addresses_src: ConfigSource = .default,
    enable_fax: bool = false,
    enable_fax_src: ConfigSource = .default,
    enable_accounts: bool = false,
    enable_accounts_src: ConfigSource = .default,
    enable_licenses: bool = false,
    enable_licenses_src: ConfigSource = .default,
    enable_urls: bool = false,
    enable_urls_src: ConfigSource = .default,
    enable_vehicle_ids: bool = false,
    enable_vehicle_ids_src: ConfigSource = .default,
    // --- Phase 3 / V4 Context Rules ---
    enable_context_rules: bool = false,
    enable_context_rules_src: ConfigSource = .default,
    context_confidence_threshold: f32 = 0.70,
    context_confidence_threshold_src: ConfigSource = .default,
    // --- Detection Profiles ---
    profile: Profile = .custom,
    profile_src: ConfigSource = .default,
    // --- Schema-aware redaction flags (Phase 5 / Epic 8) ---
    schema_file: ?[]const u8 = null,
    schema_file_src: ConfigSource = .default,
    /// Owned action string when overridden by env/CLI; null = "SCAN" default.
    schema_default: ?[]u8 = null,
    schema_default_src: ConfigSource = .default,
    hash_key: ?[]const u8 = null,
    hash_key_src: ConfigSource = .default,
    hash_key_file: ?[]const u8 = null,
    hash_key_file_src: ConfigSource = .default,
    // --- Report-only mode (Phase 2 / NMV3-007) ---
    report_only: bool = false,
    report_only_src: ConfigSource = .default,
    // --- Persistent Token Vault (Phase 2 / NMV4-007) ---
    vault_backend: VaultBackend = .memory,
    vault_backend_src: ConfigSource = .default,
    vault_file_path: ?[]const u8 = null,
    vault_file_path_src: ConfigSource = .default,
    // --- Phase 5: AI guardrails and semantic caching ---
    enable_guardrails: bool = false,
    enable_guardrails_src: ConfigSource = .default,
    guardrail_mode: GuardrailMode = .alert,
    guardrail_mode_src: ConfigSource = .default,
    enable_semantic_cache: bool = false,
    enable_semantic_cache_src: ConfigSource = .default,
    semantic_cache_ttl_ms: u64 = 300_000,
    semantic_cache_ttl_ms_src: ConfigSource = .default,
    semantic_cache_max_entries: usize = 256,
    semantic_cache_max_entries_src: ConfigSource = .default,
    semantic_cache_tenant_header: []const u8 = "X-NanoMask-Tenant",
    semantic_cache_tenant_header_src: ConfigSource = .default,
    // --- Phase 3: Enterprise Control Plane (NMV3-011, NMV3-012, NMV3-013) ---
    admin_api_key_file: ?[]const u8 = null,
    admin_api_key_file_src: ConfigSource = .default,
    audit_buffer_size: u32 = 1000,
    audit_buffer_size_src: ConfigSource = .default,
    otel_service_name: ?[]const u8 = null,
    otel_service_name_src: ConfigSource = .default,
    syslog_address: ?[]const u8 = null,
    syslog_address_src: ConfigSource = .default,
    hash_key_exec: ?[]const u8 = null,
    hash_key_exec_src: ConfigSource = .default,
    mtls_ca: ?[]const u8 = null,
    mtls_ca_src: ConfigSource = .default,
    mtls_cert: ?[]const u8 = null,
    mtls_cert_src: ConfigSource = .default,
    mtls_key: ?[]const u8 = null,
    mtls_key_src: ConfigSource = .default,

    /// When true, perform a health check probe against the listener and exit.
    /// Wildcard binds probe loopback so container HEALTHCHECK still works.
    healthcheck: bool = false,

    /// When true, validate all configuration (files, flags, consistency)
    /// and print a summary without starting the server.
    validate_config: bool = false,

    allocator: std.mem.Allocator,

    pub const ParseError = error{
        HelpRequested,
        MissingValue,
        InvalidListenHost,
        InvalidPort,
        InvalidThreshold,
        InvalidLogLevel,
        InvalidMaxConnections,
        InvalidRuntimeModel,
        InvalidRuntimeWorkerThreads,
        InvalidWatchInterval,
        EntityFileNotFound,
        InvalidAdminFlag,
        InvalidAdminListenAddress,
        InvalidAdminAllowlist,
        InvalidAdminRateLimit,
        MissingTlsPair,
        TlsCertNotFound,
        TlsKeyNotFound,
        CaFileNotFound,
        InvalidTargetTlsFlag,
        InvalidNoSystemCaFlag,
        InvalidMaxBodySize,
        InvalidTimeout,
        MissingAdminToken,
        InvalidAuditLogFlag,
        InvalidUnsupportedBodyBehavior,
        InvalidPatternFlag,
        InvalidGuardrailMode,
        InvalidSemanticCacheConfig,
        InvalidSchemaDefault,
        SchemaFileNotFound,
        InvalidHashKey,
        HashKeyFileNotFound,
        InvalidReportOnlyFlag,
        InvalidApiKeyFile,
        InvalidAuditBufferSize,
        InvalidMtlsConfig,
        InvalidMtlsPemFormat,
        InvalidVaultBackend,
        MissingVaultFilePath,
        VaultFileNotFound,
        InvalidContextConfidenceThreshold,
        InvalidProfile,
        UnknownFlag,
        OutOfMemory,
    };

    pub fn deinit(self: *Config) void {
        if (self.listen_host_src == .env_var) {
            self.allocator.free(self.listen_host);
        }
        if (self.target_host_src == .env_var) {
            self.allocator.free(self.target_host);
        }
        if (self.entity_file != null and self.entity_file_src == .env_var) {
            self.allocator.free(self.entity_file.?);
        }
        if (self.admin_token != null and self.admin_token_src == .env_var) {
            self.allocator.free(self.admin_token.?);
        }
        if (self.admin_listen_address != null and self.admin_listen_address_src == .env_var) {
            self.allocator.free(self.admin_listen_address.?);
        }
        if (self.admin_allowlist != null and self.admin_allowlist_src == .env_var) {
            self.allocator.free(self.admin_allowlist.?);
        }
        if (self.tls_cert != null and self.tls_cert_src == .env_var) {
            self.allocator.free(self.tls_cert.?);
        }
        if (self.tls_key != null and self.tls_key_src == .env_var) {
            self.allocator.free(self.tls_key.?);
        }
        if (self.ca_file != null and self.ca_file_src == .env_var) {
            self.allocator.free(self.ca_file.?);
        }
        if (self.log_file != null and self.log_file_src == .env_var) {
            self.allocator.free(self.log_file.?);
        }
        if (self.schema_file != null and self.schema_file_src == .env_var) {
            self.allocator.free(self.schema_file.?);
        }
        if (self.hash_key != null and self.hash_key_src == .env_var) {
            self.allocator.free(self.hash_key.?);
        }
        if (self.hash_key_file != null and self.hash_key_file_src == .env_var) {
            self.allocator.free(self.hash_key_file.?);
        }
        if (self.vault_file_path != null and self.vault_file_path_src == .env_var) {
            self.allocator.free(self.vault_file_path.?);
        }
        if (self.schema_default) |sd| {
            self.allocator.free(sd);
        }
        // Only free when the value was heap-allocated from an env var.
        // cli_flag assignments borrow directly from the argv slice (server lifetime)
        // so no deinit is needed for that source.
        if (self.semantic_cache_tenant_header_src == .env_var) {
            self.allocator.free(self.semantic_cache_tenant_header);
        }
        if (self.admin_api_key_file != null and self.admin_api_key_file_src == .env_var) {
            self.allocator.free(self.admin_api_key_file.?);
        }
        if (self.otel_service_name != null and self.otel_service_name_src == .env_var) {
            self.allocator.free(self.otel_service_name.?);
        }
        if (self.syslog_address != null and self.syslog_address_src == .env_var) {
            self.allocator.free(self.syslog_address.?);
        }
        if (self.hash_key_exec != null and self.hash_key_exec_src == .env_var) {
            self.allocator.free(self.hash_key_exec.?);
        }
        if (self.mtls_ca != null and self.mtls_ca_src == .env_var) {
            self.allocator.free(self.mtls_ca.?);
        }
        if (self.mtls_cert != null and self.mtls_cert_src == .env_var) {
            self.allocator.free(self.mtls_cert.?);
        }
        if (self.mtls_key != null and self.mtls_key_src == .env_var) {
            self.allocator.free(self.mtls_key.?);
        }
    }

    pub const help_text =
        \\Usage: nanomask [options]
        \\
        \\Core proxy:
        \\  --listen-host <ip>                  Host/IP to bind on (default: 127.0.0.1)
        \\  --listen-port <u16>                 Port to listen on (default: 8081)
        \\  --target-host <string>              Upstream target host (default: httpbin.org)
        \\  --target-port <u16>                 Upstream target port (default: 80)
        \\  --target-tls                        Enable TLS for upstream connections (default: disabled)
        \\  --max-connections <u32>             Maximum concurrent connections (default: 128)
        \\  --runtime-model <mode>              Connection scheduler: thread-per-connection or worker-pool (default: thread-per-connection)
        \\  --runtime-worker-threads <n>        Worker threads for worker-pool mode (0 = auto, default: 0)
        \\  --max-body-size <bytes>             Maximum request body size in bytes (default: 10485760)
        \\  --entity-file <path>                Path to file containing entity aliases (default: none)
        \\  --watch-interval <ms>               Entity file poll interval in ms (default: 1000)
        \\  --fuzzy-threshold <f32>             Threshold for fuzzy matching (0.0 - 1.0) (default: 0.8)
        \\
        \\Safety and operations:
        \\  --log-level <level>                 Logging level: debug, info, warn, error (default: info)
        \\  --log-file <path>                   Write structured JSON logs to file (default: stderr)
        \\  --audit-log                         Enable per-redaction audit events in log output
        \\  --tls-cert <path>                   PEM certificate file for TLS (requires --tls-key)
        \\  --tls-key <path>                    PEM private key file for TLS (requires --tls-cert)
        \\  --ca-file <path>                    Custom CA bundle PEM for upstream TLS verification
        \\  --tls-no-system-ca                  Suppress system CA loading (use with --ca-file for self-signed certs)
        \\  --upstream-connect-timeout-ms <ms>  Upstream TCP connect timeout in ms (0 disables, default: 5000)
        \\  --upstream-read-timeout-ms <ms>     Upstream response read timeout in ms (0 disables, default: 30000)
        \\  --upstream-request-timeout-ms <ms>  Overall upstream request timeout in ms (0 disables, default: 60000)
        \\  --shutdown-drain-timeout-ms <ms>    Graceful shutdown drain window in ms (0 disables waiting, default: 30000)
        \\  --unsupported-request-body-behavior <mode>   Unsupported request body handling: bypass or reject (default: reject)
        \\  --unsupported-response-body-behavior <mode>  Unsupported response body handling: bypass or reject (default: bypass)
        \\
        \\Admin and utilities:
        \\  --admin-api                         Enable /_admin/entities REST endpoints (default: disabled)
        \\  --admin-token <secret>              Require Bearer token for admin endpoints (mandatory with --admin-api)
        \\  --admin-listen-address <ip:port>    Bind admin routes on a dedicated listener instead of the public proxy listener
        \\  --admin-allowlist <csv>             Comma-separated client IP allowlist for admin routes (exact IPs only)
        \\  --admin-read-only                   Allow admin visibility but reject runtime entity mutations
        \\  --admin-mutation-rate-limit <n>     Maximum entity mutations per minute (0 disables, default: 60)
        \\  --entity-file-sync                  Write API entity changes back to entity file
        \\  --admin-api-key-file <path>         Bootstrap API keys from JSON file for RBAC (Phase 3)
        \\  --report-only                       Detect PII without modifying payloads (evaluation mode, default: disabled)
        \\  --enable-guardrails                 Enable baseline AI guardrail checks on request bodies
        \\  --guardrail-mode <mode>             Guardrail action: alert or block (default: alert)
        \\  --enable-semantic-cache             Cache de-identified prompt-response pairs in memory
        \\  --semantic-cache-ttl-ms <ms>        Semantic cache entry TTL in ms (default: 300000)
        \\  --semantic-cache-max-entries <n>    Maximum semantic cache entries; eviction is O(n) per store — keep ≤4096 (default: 256)
        \\  --semantic-cache-tenant-header <h>  Header used for cache tenant isolation (default: X-NanoMask-Tenant)
        \\  --healthcheck                       Probe /healthz on the local listener and exit
        \\  --validate-config                   Validate configuration and print summary without starting the server
        \\  --help                              Print this help message and exit
        \\
        \\Optional detection features:
        \\  --enable-email                      Redact email addresses (default: disabled)
        \\  --enable-phone                      Redact phone numbers (default: disabled)
        \\  --enable-credit-card                Redact credit card numbers with Luhn validation (default: disabled)
        \\  --enable-ip                         Redact IPv4/IPv6 addresses (default: disabled)
        \\  --enable-healthcare                 Redact healthcare IDs: MRN, ICD-10, Insurance (default: disabled)
        \\  --enable-iban                       Redact EU IBAN values (default: disabled)
        \\  --enable-uk-nino                    Redact UK National Insurance numbers (default: disabled)
        \\  --enable-passport                   Redact passport numbers when label-qualified (default: disabled)
        \\  --enable-intl-phone                 Redact common non-US international phone numbers (default: disabled)
        \\  --enable-dates                      Redact dates and aggregate ages > 89 (default: disabled)
        \\  --enable-addresses                  Redact US street addresses, ZIPs, city/states (default: disabled)
        \\  --enable-fax                        Redact fax numbers (default: disabled)
        \\  --enable-accounts                   Redact banking and financial account numbers (default: disabled)
        \\  --enable-licenses                   Redact US driver's licenses, DEA, and NPI numbers (default: disabled)
        \\  --enable-urls                       Redact HTTP/HTTPS URLs (default: disabled)
        \\  --enable-vehicle-ids                Redact VINs and heuristic license plates (default: disabled)
        \\  --enable-context-rules              Redact contextual patterns like Name after 'Patient:' (Stage 4) (default: disabled)
        \\  --context-confidence-threshold <f>  Threshold for context rules (0.0 - 1.0) (default: 0.70)
        \\  --profile <name>                    Enable a detection profile preset (hipaa-safe-harbor, healthcare-lite, llm-basic, custom)
        \\  --list-profiles                     List available detection profiles and exit
        \\  --schema-file <path>                NanoMask schema file using field.path = ACTION rules
        \\  --schema-default <action>           Default action for unlisted keys: REDACT, KEEP, SCAN (default: SCAN)
        \\  --hash-key <hex>                    64-char hex HMAC key for HASH-mode pseudonymization
        \\  --hash-key-file <path>              File containing the 64-char hex HMAC key
        \\  --hash-key-exec <command>           Shell command that outputs the HMAC key on stdout (Phase 3)
        \\                                      WARNING: command is executed as a shell; only use with trusted config sources
        \\  --vault-backend <type>              Backend for HASH-mode persistence: memory, file, external (default: memory)
        \\  --vault-file-path <path>            File path for encrypted local storage (required with --vault-backend file)
        \\
        \\Enterprise observability (Phase 3):
        \\  --audit-buffer-size <n>              In-memory audit ring buffer size (default: 1000)
        \\  --otel-service-name <name>          Add OTel-compatible fields to structured logs
        \\  --syslog-address <host:port>        Duplicate log lines to UDP syslog target (RFC 5424)
        \\
        \\Mutual TLS (Phase 3):
        \\  --mtls-ca <path>                    Client CA bundle PEM for mutual TLS verification
        \\  --mtls-cert <path>                  Client certificate PEM for mTLS
        \\  --mtls-key <path>                   Client private key PEM for mTLS
        \\
    ;

    const known_flags = [_][]const u8{
        "--listen-host",
        "--listen-port",
        "--target-host",
        "--target-port",
        "--target-tls",
        "--max-connections",
        "--runtime-model",
        "--runtime-worker-threads",
        "--max-body-size",
        "--entity-file",
        "--watch-interval",
        "--fuzzy-threshold",
        "--log-level",
        "--log-file",
        "--audit-log",
        "--tls-cert",
        "--tls-key",
        "--ca-file",
        "--tls-no-system-ca",
        "--upstream-connect-timeout-ms",
        "--upstream-read-timeout-ms",
        "--upstream-request-timeout-ms",
        "--shutdown-drain-timeout-ms",
        "--unsupported-request-body-behavior",
        "--unsupported-response-body-behavior",
        "--admin-api",
        "--admin-token",
        "--admin-listen-address",
        "--admin-allowlist",
        "--admin-read-only",
        "--admin-mutation-rate-limit",
        "--entity-file-sync",
        "--admin-api-key-file",
        "--report-only",
        "--enable-guardrails",
        "--guardrail-mode",
        "--enable-semantic-cache",
        "--semantic-cache-ttl-ms",
        "--semantic-cache-max-entries",
        "--semantic-cache-tenant-header",
        "--healthcheck",
        "--validate-config",
        "--help",
        "--enable-email",
        "--enable-phone",
        "--enable-credit-card",
        "--enable-ip",
        "--enable-healthcare",
        "--enable-iban",
        "--enable-uk-nino",
        "--enable-passport",
        "--enable-intl-phone",
        "--enable-dates",
        "--enable-addresses",
        "--enable-fax",
        "--enable-accounts",
        "--enable-licenses",
        "--enable-urls",
        "--enable-vehicle-ids",
        "--enable-context-rules",
        "--context-confidence-threshold",
        "--profile",
        "--list-profiles",
        "--schema-file",
        "--schema-default",
        "--hash-key",
        "--hash-key-file",
        "--hash-key-exec",
        "--vault-backend",
        "--vault-file-path",
        "--audit-buffer-size",
        "--otel-service-name",
        "--syslog-address",
        "--mtls-ca",
        "--mtls-cert",
        "--mtls-key",
    };

    pub fn printProfiles() void {
        const text =
            \\Available Detection Profiles:
            \\
            \\  hipaa-safe-harbor
            \\    Enables all HIPAA Safe Harbor identifiers: email, phone, IP, healthcare IDs (MRN, etc.),
            \\    dates/ages, addresses, fax, accounts, licenses, URLs, vehicle IDs, and context rules.
            \\
            \\  healthcare-lite
            \\    A faster, lower false-positive profile: email, phone, healthcare IDs, and dates/ages.
            \\    (Excludes context rules, addresses, licenses, etc.)
            \\
            \\  llm-basic
            \\    Fastest baseline protection: email, credit card, IP.
            \\
            \\  custom
            \\    No preset active. Requires individual --enable-* flags. (Default)
            \\
        ;
        std.debug.print("{s}", .{text});
    }

    pub fn printHelp() void {
        std.debug.print("{s}", .{help_text});
    }

    fn levenshteinDistance(a: []const u8, b: []const u8) usize {
        if (a.len == 0) return b.len;
        if (b.len == 0) return a.len;

        var prev: [128]usize = undefined;
        var curr: [128]usize = undefined;
        std.debug.assert(b.len + 1 <= prev.len);

        for (0..b.len + 1) |j| {
            prev[j] = j;
        }

        for (a, 0..) |a_byte, i| {
            curr[0] = i + 1;
            for (b, 0..) |b_byte, j| {
                const substitution_cost: usize = if (a_byte == b_byte) 0 else 1;
                const deletion = prev[j + 1] + 1;
                const insertion = curr[j] + 1;
                const substitution = prev[j] + substitution_cost;
                curr[j + 1] = @min(@min(deletion, insertion), substitution);
            }
            std.mem.copyForwards(usize, prev[0 .. b.len + 1], curr[0 .. b.len + 1]);
        }

        return prev[b.len];
    }

    fn suggestFlag(flag: []const u8) ?[]const u8 {
        if (!std.mem.startsWith(u8, flag, "--")) return null;
        // levenshteinDistance uses a fixed 128-element stack buffer indexed by
        // b.len + 1. Guard here so we never exceed it regardless of input.
        if (flag.len >= 128) return null;

        var best_flag: ?[]const u8 = null;
        var best_distance: usize = std.math.maxInt(usize);

        for (known_flags) |candidate| {
            const distance = levenshteinDistance(flag, candidate);
            if (distance < best_distance) {
                best_distance = distance;
                best_flag = candidate;
            }
        }

        if (best_flag) |candidate| {
            const max_distance: usize = if (flag.len <= 16) 3 else 4;
            if (best_distance <= max_distance) return candidate;
        }
        return null;
    }

    fn needsBracketedHost(host: []const u8) bool {
        return std.mem.indexOfScalar(u8, host, ':') != null and
            !(host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']');
    }

    fn validateListenHostValue(value: []const u8, label: []const u8) ParseError!void {
        _ = std.net.Address.parseIp(value, 0) catch {
            std.debug.print("error: {s} must be a valid IPv4 or IPv6 address, got '{s}'\n", .{ label, value });
            return error.InvalidListenHost;
        };
    }

    fn validateAdminListenAddressValue(value: []const u8, label: []const u8) ParseError!void {
        _ = std.net.Address.parseIpAndPort(value) catch {
            std.debug.print("error: {s} must be a valid IP:port or [IPv6]:port address, got '{s}'\n", .{ label, value });
            return error.InvalidAdminListenAddress;
        };
    }

    fn validateAdminAllowlistValue(value: []const u8, label: []const u8) ParseError!void {
        var it = std.mem.splitScalar(u8, value, ',');
        var saw_entry = false;
        while (it.next()) |entry| {
            const trimmed = std.mem.trim(u8, entry, " \t");
            if (trimmed.len == 0) continue;
            saw_entry = true;
            _ = std.net.Address.parseIp(trimmed, 0) catch {
                std.debug.print("error: {s} must contain comma-separated IPv4 or IPv6 addresses, got '{s}'\n", .{ label, trimmed });
                return error.InvalidAdminAllowlist;
            };
        }
        if (!saw_entry) {
            std.debug.print("error: {s} must contain at least one IP address\n", .{label});
            return error.InvalidAdminAllowlist;
        }
    }

    pub fn healthcheckHost(self: Config) []const u8 {
        if (std.mem.eql(u8, self.listen_host, "0.0.0.0")) return "127.0.0.1";
        if (std.mem.eql(u8, self.listen_host, "::")) return "::1";
        return self.listen_host;
    }

    pub fn formatListenAddress(self: Config, buffer: []u8) ![]const u8 {
        if (needsBracketedHost(self.listen_host)) {
            return std.fmt.bufPrint(buffer, "[{s}]:{d}", .{ self.listen_host, self.listen_port });
        }
        return std.fmt.bufPrint(buffer, "{s}:{d}", .{ self.listen_host, self.listen_port });
    }

    pub fn formatHealthcheckUrl(self: Config, buffer: []u8) ![]const u8 {
        const host = self.healthcheckHost();
        if (needsBracketedHost(host)) {
            return std.fmt.bufPrint(buffer, "http://[{s}]:{d}/healthz", .{ host, self.listen_port });
        }
        return std.fmt.bufPrint(buffer, "http://{s}:{d}/healthz", .{ host, self.listen_port });
    }

    fn applyEnvVar(config: *Config, name: []const u8, value: []const u8, allocator: std.mem.Allocator) !void {
        if (std.mem.eql(u8, name, "NANOMASK_LISTEN_HOST")) {
            try validateListenHostValue(value, "NANOMASK_LISTEN_HOST");
            config.listen_host = try allocator.dupe(u8, value);
            config.listen_host_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_LISTEN_PORT")) {
            config.listen_port = std.fmt.parseInt(u16, value, 10) catch {
                std.debug.print("error: NANOMASK_LISTEN_PORT must be 1-65535, got '{s}'\n", .{value});
                return error.InvalidPort;
            };
            if (config.listen_port == 0) return error.InvalidPort;
            config.listen_port_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_TARGET_HOST")) {
            config.target_host = try allocator.dupe(u8, value);
            config.target_host_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_TARGET_PORT")) {
            config.target_port = std.fmt.parseInt(u16, value, 10) catch {
                std.debug.print("error: NANOMASK_TARGET_PORT must be 1-65535, got '{s}'\n", .{value});
                return error.InvalidPort;
            };
            if (config.target_port == 0) return error.InvalidPort;
            config.target_port_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENTITY_FILE")) {
            config.entity_file = try allocator.dupe(u8, value);
            config.entity_file_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open entity file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.EntityFileNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_FUZZY_THRESHOLD")) {
            config.fuzzy_threshold = std.fmt.parseFloat(f32, value) catch {
                std.debug.print("error: NANOMASK_FUZZY_THRESHOLD must be a float between 0.0 and 1.0, got '{s}'\n", .{value});
                return error.InvalidThreshold;
            };
            if (config.fuzzy_threshold < 0.0 or config.fuzzy_threshold > 1.0) return error.InvalidThreshold;
            config.fuzzy_threshold_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_MAX_CONNECTIONS")) {
            config.max_connections = std.fmt.parseInt(u32, value, 10) catch {
                std.debug.print("error: NANOMASK_MAX_CONNECTIONS must be an integer, got '{s}'\n", .{value});
                return error.InvalidMaxConnections;
            };
            if (config.max_connections == 0) return error.InvalidMaxConnections;
            config.max_connections_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_RUNTIME_MODEL")) {
            config.runtime_model = try parseRuntimeModelValue(value, "NANOMASK_RUNTIME_MODEL");
            config.runtime_model_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_RUNTIME_WORKER_THREADS")) {
            config.runtime_worker_threads = try parseRuntimeWorkerThreadsValue(value, "NANOMASK_RUNTIME_WORKER_THREADS");
            config.runtime_worker_threads_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_LOG_LEVEL")) {
            config.log_level = LogLevel.parse(value) catch {
                std.debug.print("error: NANOMASK_LOG_LEVEL must be debug, info, warn, error, got '{s}'\n", .{value});
                return error.InvalidLogLevel;
            };
            config.log_level_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_WATCH_INTERVAL")) {
            config.watch_interval_ms = std.fmt.parseInt(u64, value, 10) catch {
                std.debug.print("error: NANOMASK_WATCH_INTERVAL must be a positive integer (ms), got '{s}'\n", .{value});
                return error.InvalidWatchInterval;
            };
            if (config.watch_interval_ms == 0) return error.InvalidWatchInterval;
            config.watch_interval_ms_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ADMIN_API")) {
            config.admin_api = parseBoolEnv(value) orelse {
                std.debug.print("error: NANOMASK_ADMIN_API must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidAdminFlag;
            };
            config.admin_api_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ADMIN_TOKEN")) {
            config.admin_token = try allocator.dupe(u8, value);
            config.admin_token_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ADMIN_LISTEN_ADDRESS")) {
            try validateAdminListenAddressValue(value, "NANOMASK_ADMIN_LISTEN_ADDRESS");
            config.admin_listen_address = try allocator.dupe(u8, value);
            config.admin_listen_address_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ADMIN_ALLOWLIST")) {
            try validateAdminAllowlistValue(value, "NANOMASK_ADMIN_ALLOWLIST");
            config.admin_allowlist = try allocator.dupe(u8, value);
            config.admin_allowlist_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ADMIN_READ_ONLY")) {
            config.admin_read_only = parseBoolEnv(value) orelse {
                std.debug.print("error: NANOMASK_ADMIN_READ_ONLY must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidAdminFlag;
            };
            config.admin_read_only_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ADMIN_MUTATION_RATE_LIMIT")) {
            config.admin_mutation_rate_limit_per_minute = std.fmt.parseInt(u32, value, 10) catch {
                std.debug.print("error: NANOMASK_ADMIN_MUTATION_RATE_LIMIT must be a non-negative integer, got '{s}'\n", .{value});
                return error.InvalidAdminRateLimit;
            };
            config.admin_mutation_rate_limit_per_minute_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENTITY_FILE_SYNC")) {
            config.entity_file_sync = parseBoolEnv(value) orelse {
                std.debug.print("error: NANOMASK_ENTITY_FILE_SYNC must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidAdminFlag;
            };
            config.entity_file_sync_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_TLS_CERT")) {
            config.tls_cert = try allocator.dupe(u8, value);
            config.tls_cert_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open TLS cert file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.TlsCertNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_TLS_KEY")) {
            config.tls_key = try allocator.dupe(u8, value);
            config.tls_key_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open TLS key file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.TlsKeyNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_TARGET_TLS")) {
            config.target_tls = parseBoolEnv(value) orelse {
                std.debug.print("error: NANOMASK_TARGET_TLS must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidTargetTlsFlag;
            };
            config.target_tls_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_CA_FILE")) {
            config.ca_file = try allocator.dupe(u8, value);
            config.ca_file_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open CA file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.CaFileNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_TLS_NO_SYSTEM_CA")) {
            config.tls_no_system_ca = parseBoolEnv(value) orelse {
                std.debug.print("error: NANOMASK_TLS_NO_SYSTEM_CA must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidNoSystemCaFlag;
            };
            config.tls_no_system_ca_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_MAX_BODY_SIZE")) {
            config.max_body_size = std.fmt.parseInt(usize, value, 10) catch {
                std.debug.print("error: NANOMASK_MAX_BODY_SIZE must be a positive integer, got '{s}'\n", .{value});
                return error.InvalidMaxBodySize;
            };
            if (config.max_body_size == 0) return error.InvalidMaxBodySize;
            config.max_body_size_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_UPSTREAM_CONNECT_TIMEOUT_MS")) {
            config.upstream_connect_timeout_ms = try parseTimeoutValue(value, "NANOMASK_UPSTREAM_CONNECT_TIMEOUT_MS");
            config.upstream_connect_timeout_ms_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_UPSTREAM_READ_TIMEOUT_MS")) {
            config.upstream_read_timeout_ms = try parseTimeoutValue(value, "NANOMASK_UPSTREAM_READ_TIMEOUT_MS");
            config.upstream_read_timeout_ms_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_UPSTREAM_REQUEST_TIMEOUT_MS")) {
            config.upstream_request_timeout_ms = try parseTimeoutValue(value, "NANOMASK_UPSTREAM_REQUEST_TIMEOUT_MS");
            config.upstream_request_timeout_ms_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_SHUTDOWN_DRAIN_TIMEOUT_MS")) {
            config.shutdown_drain_timeout_ms = try parseTimeoutValue(value, "NANOMASK_SHUTDOWN_DRAIN_TIMEOUT_MS");
            config.shutdown_drain_timeout_ms_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_UNSUPPORTED_REQUEST_BODY_BEHAVIOR")) {
            config.unsupported_request_body_behavior = try parseUnsupportedBodyBehaviorValue(value, "NANOMASK_UNSUPPORTED_REQUEST_BODY_BEHAVIOR");
            config.unsupported_request_body_behavior_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_UNSUPPORTED_RESPONSE_BODY_BEHAVIOR")) {
            config.unsupported_response_body_behavior = try parseUnsupportedBodyBehaviorValue(value, "NANOMASK_UNSUPPORTED_RESPONSE_BODY_BEHAVIOR");
            config.unsupported_response_body_behavior_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_LOG_FILE")) {
            config.log_file = try allocator.dupe(u8, value);
            config.log_file_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_AUDIT_LOG")) {
            config.audit_log = parseBoolEnv(value) orelse {
                std.debug.print("error: NANOMASK_AUDIT_LOG must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidAuditLogFlag;
            };
            config.audit_log_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_EMAIL")) {
            config.enable_email = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_email_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_PHONE")) {
            config.enable_phone = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_phone_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_CREDIT_CARD")) {
            config.enable_credit_card = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_credit_card_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_IP")) {
            config.enable_ip = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_ip_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_HEALTHCARE")) {
            config.enable_healthcare = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_healthcare_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_IBAN")) {
            config.enable_iban = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_iban_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_UK_NINO")) {
            config.enable_uk_nino = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_uk_nino_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_PASSPORT")) {
            config.enable_passport = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_passport_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_INTL_PHONE")) {
            config.enable_intl_phone = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_intl_phone_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_DATES")) {
            config.enable_dates = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_dates_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_ADDRESSES")) {
            config.enable_addresses = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_addresses_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_FAX")) {
            config.enable_fax = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_fax_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_ACCOUNTS")) {
            config.enable_accounts = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_accounts_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_LICENSES")) {
            config.enable_licenses = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_licenses_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_URLS")) {
            config.enable_urls = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_urls_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_VEHICLE_IDS")) {
            config.enable_vehicle_ids = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_vehicle_ids_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_CONTEXT_RULES")) {
            config.enable_context_rules = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_context_rules_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_CONTEXT_CONFIDENCE_THRESHOLD")) {
            config.context_confidence_threshold = std.fmt.parseFloat(f32, value) catch {
                std.debug.print("error: NANOMASK_CONTEXT_CONFIDENCE_THRESHOLD must be a float between 0.0 and 1.0, got '{s}'\n", .{value});
                return error.InvalidContextConfidenceThreshold;
            };
            if (config.context_confidence_threshold < 0.0 or config.context_confidence_threshold > 1.0) return error.InvalidContextConfidenceThreshold;
            config.context_confidence_threshold_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_PROFILE")) {
            config.profile = Profile.parse(value) catch {
                std.debug.print("error: NANOMASK_PROFILE must be hipaa-safe-harbor, healthcare-lite, llm-basic, or custom, got '{s}'\n", .{value});
                return error.InvalidProfile;
            };
            config.profile_src = .env_var;
            config.profile.apply(config);
        } else if (std.mem.eql(u8, name, "NANOMASK_SCHEMA_FILE")) {
            config.schema_file = try allocator.dupe(u8, value);
            config.schema_file_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open schema file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.SchemaFileNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_SCHEMA_DEFAULT")) {
            if (std.mem.eql(u8, value, "REDACT") or std.mem.eql(u8, value, "KEEP") or std.mem.eql(u8, value, "SCAN")) {
                config.schema_default = try allocator.dupe(u8, value);
                config.schema_default_src = .env_var;
            } else {
                std.debug.print("error: NANOMASK_SCHEMA_DEFAULT must be REDACT, KEEP, or SCAN, got '{s}'\n", .{value});
                return error.InvalidSchemaDefault;
            }
            // Note: schema_default is now ?[]u8; duped value is freed in deinit()
        } else if (std.mem.eql(u8, name, "NANOMASK_HASH_KEY")) {
            // Validate 64 hex chars at parse time (same as CLI --hash-key)
            if (value.len != 64) {
                std.debug.print("error: NANOMASK_HASH_KEY must be exactly 64 hex characters, got {d}\n", .{value.len});
                return error.InvalidHashKey;
            }
            for (value) |ch| {
                switch (ch) {
                    '0'...'9', 'a'...'f', 'A'...'F' => {},
                    else => {
                        std.debug.print("error: NANOMASK_HASH_KEY contains non-hex character\n", .{});
                        return error.InvalidHashKey;
                    },
                }
            }
            config.hash_key = try allocator.dupe(u8, value);
            config.hash_key_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_HASH_KEY_FILE")) {
            config.hash_key_file = try allocator.dupe(u8, value);
            config.hash_key_file_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open hash key file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.HashKeyFileNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_REPORT_ONLY")) {
            config.report_only = parseBoolEnv(value) orelse {
                std.debug.print("error: NANOMASK_REPORT_ONLY must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidReportOnlyFlag;
            };
            config.report_only_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_GUARDRAILS")) {
            config.enable_guardrails = parseBoolEnv(value) orelse {
                std.debug.print("error: NANOMASK_ENABLE_GUARDRAILS must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidPatternFlag;
            };
            config.enable_guardrails_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_GUARDRAIL_MODE")) {
            config.guardrail_mode = GuardrailMode.parse(value) catch {
                std.debug.print("error: NANOMASK_GUARDRAIL_MODE must be alert or block, got '{s}'\n", .{value});
                return error.InvalidGuardrailMode;
            };
            config.guardrail_mode_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_SEMANTIC_CACHE")) {
            config.enable_semantic_cache = parseBoolEnv(value) orelse {
                std.debug.print("error: NANOMASK_ENABLE_SEMANTIC_CACHE must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidSemanticCacheConfig;
            };
            config.enable_semantic_cache_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_SEMANTIC_CACHE_TTL_MS")) {
            config.semantic_cache_ttl_ms = try parseTimeoutValue(value, "NANOMASK_SEMANTIC_CACHE_TTL_MS");
            config.semantic_cache_ttl_ms_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_SEMANTIC_CACHE_MAX_ENTRIES")) {
            config.semantic_cache_max_entries = std.fmt.parseInt(usize, value, 10) catch {
                std.debug.print("error: NANOMASK_SEMANTIC_CACHE_MAX_ENTRIES must be a positive integer, got '{s}'\n", .{value});
                return error.InvalidSemanticCacheConfig;
            };
            if (config.semantic_cache_max_entries == 0) return error.InvalidSemanticCacheConfig;
            config.semantic_cache_max_entries_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_SEMANTIC_CACHE_TENANT_HEADER")) {
            config.semantic_cache_tenant_header = try allocator.dupe(u8, value);
            config.semantic_cache_tenant_header_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ADMIN_API_KEY_FILE")) {
            config.admin_api_key_file = try allocator.dupe(u8, value);
            config.admin_api_key_file_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open API key file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.InvalidApiKeyFile;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_AUDIT_BUFFER_SIZE")) {
            config.audit_buffer_size = std.fmt.parseInt(u32, value, 10) catch {
                std.debug.print("error: NANOMASK_AUDIT_BUFFER_SIZE must be a positive integer, got '{s}'\n", .{value});
                return error.InvalidAuditBufferSize;
            };
            if (config.audit_buffer_size == 0) return error.InvalidAuditBufferSize;
            config.audit_buffer_size_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_OTEL_SERVICE_NAME")) {
            config.otel_service_name = try allocator.dupe(u8, value);
            config.otel_service_name_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_SYSLOG_ADDRESS")) {
            config.syslog_address = try allocator.dupe(u8, value);
            config.syslog_address_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_HASH_KEY_EXEC")) {
            config.hash_key_exec = try allocator.dupe(u8, value);
            config.hash_key_exec_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_VAULT_BACKEND")) {
            config.vault_backend = VaultBackend.parse(value) catch {
                std.debug.print("error: NANOMASK_VAULT_BACKEND must be memory, file, or external, got '{s}'\n", .{value});
                return error.InvalidVaultBackend;
            };
            config.vault_backend_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_VAULT_FILE_PATH")) {
            config.vault_file_path = try allocator.dupe(u8, value);
            config.vault_file_path_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_MTLS_CA")) {
            try checkPemFile(value, "mTLS CA");
            config.mtls_ca = try allocator.dupe(u8, value);
            config.mtls_ca_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_MTLS_CERT")) {
            try checkPemFile(value, "mTLS cert");
            config.mtls_cert = try allocator.dupe(u8, value);
            config.mtls_cert_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_MTLS_KEY")) {
            try checkPemFile(value, "mTLS key");
            config.mtls_key = try allocator.dupe(u8, value);
            config.mtls_key_src = .env_var;
        }
    }

    fn parseBoolEnv(value: []const u8) ?bool {
        if (std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1")) return true;
        if (std.mem.eql(u8, value, "false") or std.mem.eql(u8, value, "0")) return false;
        return null;
    }

    fn parseUnsupportedBodyBehaviorValue(
        value: []const u8,
        label: []const u8,
    ) ParseError!UnsupportedBodyBehavior {
        return UnsupportedBodyBehavior.parse(value) catch {
            std.debug.print("error: {s} must be 'bypass' or 'reject', got '{s}'\n", .{ label, value });
            return error.InvalidUnsupportedBodyBehavior;
        };
    }

    fn parseRuntimeModelValue(
        value: []const u8,
        label: []const u8,
    ) ParseError!RuntimeModel {
        return RuntimeModel.parse(value) catch {
            std.debug.print(
                "error: {s} must be 'thread-per-connection' or 'worker-pool', got '{s}'\n",
                .{ label, value },
            );
            return error.InvalidRuntimeModel;
        };
    }

    fn parseRuntimeWorkerThreadsValue(
        value: []const u8,
        label: []const u8,
    ) ParseError!usize {
        return std.fmt.parseInt(usize, value, 10) catch {
            std.debug.print("error: {s} must be a non-negative integer, got '{s}'\n", .{ label, value });
            return error.InvalidRuntimeWorkerThreads;
        };
    }

    fn parseTimeoutValue(value: []const u8, label: []const u8) ParseError!u64 {
        return std.fmt.parseInt(u64, value, 10) catch {
            std.debug.print("error: {s} must be a non-negative integer in milliseconds, got '{s}'\n", .{ label, value });
            return error.InvalidTimeout;
        };
    }

    /// Parses configuration from a slice of argument strings. Errors out via writer if not headless.
    pub fn parse(allocator: std.mem.Allocator, args: []const []const u8) !Config {
        var config = Config{ .allocator = allocator };

        var env = try std.process.getEnvMap(allocator);
        defer env.deinit();

        const env_keys = [_][]const u8{
            "NANOMASK_LISTEN_HOST",
            "NANOMASK_LISTEN_PORT",
            "NANOMASK_TARGET_HOST",
            "NANOMASK_TARGET_PORT",
            "NANOMASK_ENTITY_FILE",
            "NANOMASK_FUZZY_THRESHOLD",
            "NANOMASK_MAX_CONNECTIONS",
            "NANOMASK_RUNTIME_MODEL",
            "NANOMASK_RUNTIME_WORKER_THREADS",
            "NANOMASK_LOG_LEVEL",
            "NANOMASK_WATCH_INTERVAL",
            "NANOMASK_ADMIN_API",
            "NANOMASK_ADMIN_TOKEN",
            "NANOMASK_ADMIN_LISTEN_ADDRESS",
            "NANOMASK_ADMIN_ALLOWLIST",
            "NANOMASK_ADMIN_READ_ONLY",
            "NANOMASK_ADMIN_MUTATION_RATE_LIMIT",
            "NANOMASK_ENTITY_FILE_SYNC",
            "NANOMASK_TLS_CERT",
            "NANOMASK_TLS_KEY",
            "NANOMASK_TARGET_TLS",
            "NANOMASK_CA_FILE",
            "NANOMASK_TLS_NO_SYSTEM_CA",
            "NANOMASK_MAX_BODY_SIZE",
            "NANOMASK_UPSTREAM_CONNECT_TIMEOUT_MS",
            "NANOMASK_UPSTREAM_READ_TIMEOUT_MS",
            "NANOMASK_UPSTREAM_REQUEST_TIMEOUT_MS",
            "NANOMASK_SHUTDOWN_DRAIN_TIMEOUT_MS",
            "NANOMASK_UNSUPPORTED_REQUEST_BODY_BEHAVIOR",
            "NANOMASK_UNSUPPORTED_RESPONSE_BODY_BEHAVIOR",
            "NANOMASK_LOG_FILE",
            "NANOMASK_AUDIT_LOG",
            "NANOMASK_ENABLE_EMAIL",
            "NANOMASK_ENABLE_PHONE",
            "NANOMASK_ENABLE_CREDIT_CARD",
            "NANOMASK_ENABLE_IP",
            "NANOMASK_ENABLE_HEALTHCARE",
            "NANOMASK_ENABLE_IBAN",
            "NANOMASK_ENABLE_UK_NINO",
            "NANOMASK_ENABLE_PASSPORT",
            "NANOMASK_ENABLE_INTL_PHONE",
            "NANOMASK_ENABLE_DATES",
            "NANOMASK_ENABLE_ADDRESSES",
            "NANOMASK_ENABLE_FAX",
            "NANOMASK_ENABLE_ACCOUNTS",
            "NANOMASK_ENABLE_LICENSES",
            "NANOMASK_ENABLE_URLS",
            "NANOMASK_ENABLE_VEHICLE_IDS",
            "NANOMASK_ENABLE_CONTEXT_RULES",
            "NANOMASK_CONTEXT_CONFIDENCE_THRESHOLD",
            "NANOMASK_PROFILE",
            "NANOMASK_SCHEMA_FILE",
            "NANOMASK_SCHEMA_DEFAULT",
            "NANOMASK_HASH_KEY",
            "NANOMASK_HASH_KEY_FILE",
            "NANOMASK_REPORT_ONLY",
            "NANOMASK_ENABLE_GUARDRAILS",
            "NANOMASK_GUARDRAIL_MODE",
            "NANOMASK_ENABLE_SEMANTIC_CACHE",
            "NANOMASK_SEMANTIC_CACHE_TTL_MS",
            "NANOMASK_SEMANTIC_CACHE_MAX_ENTRIES",
            "NANOMASK_SEMANTIC_CACHE_TENANT_HEADER",
            "NANOMASK_ADMIN_API_KEY_FILE",
            "NANOMASK_AUDIT_BUFFER_SIZE",
            "NANOMASK_OTEL_SERVICE_NAME",
            "NANOMASK_SYSLOG_ADDRESS",
            "NANOMASK_HASH_KEY_EXEC",
            "NANOMASK_MTLS_CA",
            "NANOMASK_MTLS_CERT",
            "NANOMASK_MTLS_KEY",
        };

        for (env_keys) |key| {
            if (env.get(key)) |val| {
                try applyEnvVar(&config, key, val, allocator);
            }
        }

        var i: usize = 1; // skip executable (args[0])

        while (i < args.len) : (i += 1) {
            const arg = args[i];

            if (std.mem.eql(u8, arg, "--help")) {
                printHelp();
                return error.HelpRequested;
            } else if (std.mem.eql(u8, arg, "--listen-host")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --listen-host\n", .{});
                    return error.MissingValue;
                }
                try validateListenHostValue(args[i], "--listen-host");
                if (config.listen_host_src == .env_var) allocator.free(config.listen_host);
                config.listen_host = args[i];
                config.listen_host_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--listen-port")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --listen-port\n", .{});
                    return error.MissingValue;
                }
                config.listen_port = std.fmt.parseInt(u16, args[i], 10) catch {
                    std.debug.print("error: --listen-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                };
                if (config.listen_port == 0) {
                    std.debug.print("error: --listen-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                }
                config.listen_port_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--target-host")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --target-host\n", .{});
                    return error.MissingValue;
                }
                if (config.target_host_src == .env_var) allocator.free(config.target_host);
                config.target_host = args[i];
                config.target_host_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--target-port")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --target-port\n", .{});
                    return error.MissingValue;
                }
                config.target_port = std.fmt.parseInt(u16, args[i], 10) catch {
                    std.debug.print("error: --target-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                };
                if (config.target_port == 0) {
                    std.debug.print("error: --target-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                }
                config.target_port_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--entity-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --entity-file\n", .{});
                    return error.MissingValue;
                }
                if (config.entity_file != null and config.entity_file_src == .env_var) {
                    allocator.free(config.entity_file.?);
                }
                config.entity_file = args[i];
                config.entity_file_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open entity file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.EntityFileNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--fuzzy-threshold")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --fuzzy-threshold\n", .{});
                    return error.MissingValue;
                }
                config.fuzzy_threshold = std.fmt.parseFloat(f32, args[i]) catch {
                    std.debug.print("error: --fuzzy-threshold must be a float between 0.0 and 1.0, got '{s}'\n", .{args[i]});
                    return error.InvalidThreshold;
                };
                if (config.fuzzy_threshold < 0.0 or config.fuzzy_threshold > 1.0) {
                    std.debug.print("error: --fuzzy-threshold must be between 0.0 and 1.0, got '{s}'\n", .{args[i]});
                    return error.InvalidThreshold;
                }
                config.fuzzy_threshold_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--max-connections")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --max-connections\n", .{});
                    return error.MissingValue;
                }
                config.max_connections = std.fmt.parseInt(u32, args[i], 10) catch {
                    std.debug.print("error: --max-connections must be an integer, got '{s}'\n", .{args[i]});
                    return error.InvalidMaxConnections;
                };
                if (config.max_connections == 0) {
                    std.debug.print("error: --max-connections must be > 0\n", .{});
                    return error.InvalidMaxConnections;
                }
                config.max_connections_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--runtime-model")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --runtime-model\n", .{});
                    return error.MissingValue;
                }
                config.runtime_model = try parseRuntimeModelValue(args[i], "--runtime-model");
                config.runtime_model_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--runtime-worker-threads")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --runtime-worker-threads\n", .{});
                    return error.MissingValue;
                }
                config.runtime_worker_threads = try parseRuntimeWorkerThreadsValue(args[i], "--runtime-worker-threads");
                config.runtime_worker_threads_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--log-level")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --log-level\n", .{});
                    return error.MissingValue;
                }
                config.log_level = LogLevel.parse(args[i]) catch {
                    std.debug.print("error: --log-level must be debug, info, warn, error, got '{s}'\n", .{args[i]});
                    return error.InvalidLogLevel;
                };
                config.log_level_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--watch-interval")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --watch-interval\n", .{});
                    return error.MissingValue;
                }
                config.watch_interval_ms = std.fmt.parseInt(u64, args[i], 10) catch {
                    std.debug.print("error: --watch-interval must be a positive integer (ms), got '{s}'\n", .{args[i]});
                    return error.InvalidWatchInterval;
                };
                if (config.watch_interval_ms == 0) {
                    std.debug.print("error: --watch-interval must be > 0\n", .{});
                    return error.InvalidWatchInterval;
                }
                config.watch_interval_ms_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--admin-api")) {
                config.admin_api = true;
                config.admin_api_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--admin-token")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --admin-token\n", .{});
                    return error.MissingValue;
                }
                if (config.admin_token != null and config.admin_token_src == .env_var) {
                    allocator.free(config.admin_token.?);
                }
                config.admin_token = args[i];
                config.admin_token_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--admin-listen-address")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --admin-listen-address\n", .{});
                    return error.MissingValue;
                }
                try validateAdminListenAddressValue(args[i], "--admin-listen-address");
                if (config.admin_listen_address != null and config.admin_listen_address_src == .env_var) {
                    allocator.free(config.admin_listen_address.?);
                }
                config.admin_listen_address = args[i];
                config.admin_listen_address_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--admin-allowlist")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --admin-allowlist\n", .{});
                    return error.MissingValue;
                }
                try validateAdminAllowlistValue(args[i], "--admin-allowlist");
                if (config.admin_allowlist != null and config.admin_allowlist_src == .env_var) {
                    allocator.free(config.admin_allowlist.?);
                }
                config.admin_allowlist = args[i];
                config.admin_allowlist_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--admin-read-only")) {
                config.admin_read_only = true;
                config.admin_read_only_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--admin-mutation-rate-limit")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --admin-mutation-rate-limit\n", .{});
                    return error.MissingValue;
                }
                config.admin_mutation_rate_limit_per_minute = std.fmt.parseInt(u32, args[i], 10) catch {
                    std.debug.print("error: --admin-mutation-rate-limit must be a non-negative integer, got '{s}'\n", .{args[i]});
                    return error.InvalidAdminRateLimit;
                };
                config.admin_mutation_rate_limit_per_minute_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--entity-file-sync")) {
                config.entity_file_sync = true;
                config.entity_file_sync_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--tls-cert")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --tls-cert\n", .{});
                    return error.MissingValue;
                }
                if (config.tls_cert != null and config.tls_cert_src == .env_var) {
                    allocator.free(config.tls_cert.?);
                }
                config.tls_cert = args[i];
                config.tls_cert_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open TLS cert file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.TlsCertNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--tls-key")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --tls-key\n", .{});
                    return error.MissingValue;
                }
                if (config.tls_key != null and config.tls_key_src == .env_var) {
                    allocator.free(config.tls_key.?);
                }
                config.tls_key = args[i];
                config.tls_key_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open TLS key file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.TlsKeyNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--target-tls")) {
                config.target_tls = true;
                config.target_tls_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--ca-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --ca-file\n", .{});
                    return error.MissingValue;
                }
                if (config.ca_file != null and config.ca_file_src == .env_var) {
                    allocator.free(config.ca_file.?);
                }
                config.ca_file = args[i];
                config.ca_file_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open CA file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.CaFileNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--tls-no-system-ca")) {
                config.tls_no_system_ca = true;
                config.tls_no_system_ca_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--max-body-size")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --max-body-size\n", .{});
                    return error.MissingValue;
                }
                config.max_body_size = std.fmt.parseInt(usize, args[i], 10) catch {
                    std.debug.print("error: --max-body-size must be a positive integer, got '{s}'\n", .{args[i]});
                    return error.InvalidMaxBodySize;
                };
                if (config.max_body_size == 0) {
                    std.debug.print("error: --max-body-size must be > 0\n", .{});
                    return error.InvalidMaxBodySize;
                }
                config.max_body_size_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--upstream-connect-timeout-ms")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --upstream-connect-timeout-ms\n", .{});
                    return error.MissingValue;
                }
                config.upstream_connect_timeout_ms = try parseTimeoutValue(args[i], "--upstream-connect-timeout-ms");
                config.upstream_connect_timeout_ms_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--upstream-read-timeout-ms")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --upstream-read-timeout-ms\n", .{});
                    return error.MissingValue;
                }
                config.upstream_read_timeout_ms = try parseTimeoutValue(args[i], "--upstream-read-timeout-ms");
                config.upstream_read_timeout_ms_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--upstream-request-timeout-ms")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --upstream-request-timeout-ms\n", .{});
                    return error.MissingValue;
                }
                config.upstream_request_timeout_ms = try parseTimeoutValue(args[i], "--upstream-request-timeout-ms");
                config.upstream_request_timeout_ms_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--shutdown-drain-timeout-ms")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --shutdown-drain-timeout-ms\n", .{});
                    return error.MissingValue;
                }
                config.shutdown_drain_timeout_ms = try parseTimeoutValue(args[i], "--shutdown-drain-timeout-ms");
                config.shutdown_drain_timeout_ms_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--unsupported-request-body-behavior")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --unsupported-request-body-behavior\n", .{});
                    return error.MissingValue;
                }
                config.unsupported_request_body_behavior = try parseUnsupportedBodyBehaviorValue(args[i], "--unsupported-request-body-behavior");
                config.unsupported_request_body_behavior_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--unsupported-response-body-behavior")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --unsupported-response-body-behavior\n", .{});
                    return error.MissingValue;
                }
                config.unsupported_response_body_behavior = try parseUnsupportedBodyBehaviorValue(args[i], "--unsupported-response-body-behavior");
                config.unsupported_response_body_behavior_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--log-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --log-file\n", .{});
                    return error.MissingValue;
                }
                if (config.log_file != null and config.log_file_src == .env_var) {
                    allocator.free(config.log_file.?);
                }
                config.log_file = args[i];
                config.log_file_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--audit-log")) {
                config.audit_log = true;
                config.audit_log_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-email")) {
                config.enable_email = true;
                config.enable_email_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-phone")) {
                config.enable_phone = true;
                config.enable_phone_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-credit-card")) {
                config.enable_credit_card = true;
                config.enable_credit_card_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-ip")) {
                config.enable_ip = true;
                config.enable_ip_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-healthcare")) {
                config.enable_healthcare = true;
                config.enable_healthcare_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-iban")) {
                config.enable_iban = true;
                config.enable_iban_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-uk-nino")) {
                config.enable_uk_nino = true;
                config.enable_uk_nino_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-passport")) {
                config.enable_passport = true;
                config.enable_passport_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-intl-phone")) {
                config.enable_intl_phone = true;
                config.enable_intl_phone_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-context-rules")) {
                config.enable_context_rules = true;
                config.enable_context_rules_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--context-confidence-threshold")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --context-confidence-threshold\n", .{});
                    return error.MissingValue;
                }
                config.context_confidence_threshold = std.fmt.parseFloat(f32, args[i]) catch {
                    std.debug.print("error: --context-confidence-threshold must be a float between 0.0 and 1.0, got '{s}'\n", .{args[i]});
                    return error.InvalidContextConfidenceThreshold;
                };
                if (config.context_confidence_threshold < 0.0 or config.context_confidence_threshold > 1.0) {
                    std.debug.print("error: --context-confidence-threshold must be between 0.0 and 1.0, got '{s}'\n", .{args[i]});
                    return error.InvalidContextConfidenceThreshold;
                }
                config.context_confidence_threshold_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--profile")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --profile\n", .{});
                    return error.MissingValue;
                }
                config.profile = Profile.parse(args[i]) catch {
                    std.debug.print("error: --profile must be hipaa-safe-harbor, healthcare-lite, llm-basic, or custom, got '{s}'\n", .{args[i]});
                    return error.InvalidProfile;
                };
                config.profile_src = .cli_flag;
                // Immediately apply profile defaults. Later individual flags in args will correctly override these.
                config.profile.apply(&config);
            } else if (std.mem.eql(u8, arg, "--list-profiles")) {
                printProfiles();
                std.posix.exit(0);
            } else if (std.mem.eql(u8, arg, "--schema-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --schema-file\n", .{});
                    return error.MissingValue;
                }
                if (config.schema_file != null and config.schema_file_src == .env_var) {
                    allocator.free(config.schema_file.?);
                }
                config.schema_file = args[i];
                config.schema_file_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open schema file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.SchemaFileNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--schema-default")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --schema-default\n", .{});
                    return error.MissingValue;
                }
                if (std.mem.eql(u8, args[i], "REDACT") or std.mem.eql(u8, args[i], "KEEP") or std.mem.eql(u8, args[i], "SCAN")) {
                    // Free previous duped value if being overridden
                    if (config.schema_default) |prev| allocator.free(prev);
                    config.schema_default = try allocator.dupe(u8, args[i]);
                    config.schema_default_src = .cli_flag;
                } else {
                    std.debug.print("error: --schema-default must be REDACT, KEEP, or SCAN, got '{s}'\n", .{args[i]});
                    return error.InvalidSchemaDefault;
                }
            } else if (std.mem.eql(u8, arg, "--hash-key")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --hash-key\n", .{});
                    return error.MissingValue;
                }
                // Validate 64 hex chars at parse time for fail-fast behavior
                if (args[i].len != 64) {
                    std.debug.print("error: --hash-key must be exactly 64 hex characters (32 bytes), got {d} chars\n", .{args[i].len});
                    return error.InvalidHashKey;
                }
                for (args[i]) |ch| {
                    switch (ch) {
                        '0'...'9', 'a'...'f', 'A'...'F' => {},
                        else => {
                            std.debug.print("error: --hash-key contains non-hex character '{c}'\n", .{ch});
                            return error.InvalidHashKey;
                        },
                    }
                }
                if (config.hash_key != null and config.hash_key_src == .env_var) {
                    allocator.free(config.hash_key.?);
                }
                config.hash_key = args[i];
                config.hash_key_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--hash-key-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --hash-key-file\n", .{});
                    return error.MissingValue;
                }
                if (config.hash_key_file != null and config.hash_key_file_src == .env_var) {
                    allocator.free(config.hash_key_file.?);
                }
                config.hash_key_file = args[i];
                config.hash_key_file_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open hash key file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.HashKeyFileNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--vault-backend")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --vault-backend\n", .{});
                    return error.MissingValue;
                }
                config.vault_backend = VaultBackend.parse(args[i]) catch {
                    std.debug.print("error: --vault-backend must be memory, file, or external, got '{s}'\n", .{args[i]});
                    return error.InvalidVaultBackend;
                };
                config.vault_backend_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--vault-file-path")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --vault-file-path\n", .{});
                    return error.MissingValue;
                }
                if (config.vault_file_path != null and config.vault_file_path_src == .env_var) {
                    allocator.free(config.vault_file_path.?);
                }
                config.vault_file_path = args[i];
                config.vault_file_path_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--report-only")) {
                config.report_only = true;
                config.report_only_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-guardrails")) {
                config.enable_guardrails = true;
                config.enable_guardrails_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--guardrail-mode")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --guardrail-mode\n", .{});
                    return error.MissingValue;
                }
                config.guardrail_mode = GuardrailMode.parse(args[i]) catch {
                    std.debug.print("error: --guardrail-mode must be alert or block, got '{s}'\n", .{args[i]});
                    return error.InvalidGuardrailMode;
                };
                config.guardrail_mode_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-semantic-cache")) {
                config.enable_semantic_cache = true;
                config.enable_semantic_cache_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--semantic-cache-ttl-ms")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --semantic-cache-ttl-ms\n", .{});
                    return error.MissingValue;
                }
                config.semantic_cache_ttl_ms = try parseTimeoutValue(args[i], "--semantic-cache-ttl-ms");
                config.semantic_cache_ttl_ms_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--semantic-cache-max-entries")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --semantic-cache-max-entries\n", .{});
                    return error.MissingValue;
                }
                config.semantic_cache_max_entries = std.fmt.parseInt(usize, args[i], 10) catch {
                    std.debug.print("error: --semantic-cache-max-entries must be a positive integer, got '{s}'\n", .{args[i]});
                    return error.InvalidSemanticCacheConfig;
                };
                if (config.semantic_cache_max_entries == 0) {
                    std.debug.print("error: --semantic-cache-max-entries must be > 0\n", .{});
                    return error.InvalidSemanticCacheConfig;
                }
                config.semantic_cache_max_entries_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--semantic-cache-tenant-header")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --semantic-cache-tenant-header\n", .{});
                    return error.MissingValue;
                }
                if (config.semantic_cache_tenant_header_src == .env_var) {
                    allocator.free(config.semantic_cache_tenant_header);
                }
                config.semantic_cache_tenant_header = args[i];
                config.semantic_cache_tenant_header_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--admin-api-key-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --admin-api-key-file\n", .{});
                    return error.MissingValue;
                }
                if (config.admin_api_key_file != null and config.admin_api_key_file_src == .env_var) {
                    allocator.free(config.admin_api_key_file.?);
                }
                config.admin_api_key_file = args[i];
                config.admin_api_key_file_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open API key file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.InvalidApiKeyFile;
                }
            } else if (std.mem.eql(u8, arg, "--audit-buffer-size")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --audit-buffer-size\n", .{});
                    return error.MissingValue;
                }
                config.audit_buffer_size = std.fmt.parseInt(u32, args[i], 10) catch {
                    std.debug.print("error: --audit-buffer-size must be a positive integer, got '{s}'\n", .{args[i]});
                    return error.InvalidAuditBufferSize;
                };
                if (config.audit_buffer_size == 0) {
                    std.debug.print("error: --audit-buffer-size must be > 0\n", .{});
                    return error.InvalidAuditBufferSize;
                }
                config.audit_buffer_size_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--otel-service-name")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --otel-service-name\n", .{});
                    return error.MissingValue;
                }
                if (config.otel_service_name != null and config.otel_service_name_src == .env_var) {
                    allocator.free(config.otel_service_name.?);
                }
                config.otel_service_name = args[i];
                config.otel_service_name_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--syslog-address")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --syslog-address\n", .{});
                    return error.MissingValue;
                }
                if (config.syslog_address != null and config.syslog_address_src == .env_var) {
                    allocator.free(config.syslog_address.?);
                }
                config.syslog_address = args[i];
                config.syslog_address_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--hash-key-exec")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --hash-key-exec\n", .{});
                    return error.MissingValue;
                }
                if (config.hash_key_exec != null and config.hash_key_exec_src == .env_var) {
                    allocator.free(config.hash_key_exec.?);
                }
                config.hash_key_exec = args[i];
                config.hash_key_exec_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--mtls-ca")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --mtls-ca\n", .{});
                    return error.MissingValue;
                }
                if (config.mtls_ca != null and config.mtls_ca_src == .env_var) {
                    allocator.free(config.mtls_ca.?);
                }
                try checkPemFile(args[i], "mTLS CA");
                config.mtls_ca = args[i];
                config.mtls_ca_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--mtls-cert")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --mtls-cert\n", .{});
                    return error.MissingValue;
                }
                if (config.mtls_cert != null and config.mtls_cert_src == .env_var) {
                    allocator.free(config.mtls_cert.?);
                }
                try checkPemFile(args[i], "mTLS cert");
                config.mtls_cert = args[i];
                config.mtls_cert_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--mtls-key")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --mtls-key\n", .{});
                    return error.MissingValue;
                }
                if (config.mtls_key != null and config.mtls_key_src == .env_var) {
                    allocator.free(config.mtls_key.?);
                }
                try checkPemFile(args[i], "mTLS key");
                config.mtls_key = args[i];
                config.mtls_key_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--healthcheck")) {
                config.healthcheck = true;
            } else if (std.mem.eql(u8, arg, "--validate-config")) {
                config.validate_config = true;
            } else {
                std.debug.print("error: unknown flag '{s}'\n", .{arg});
                if (suggestFlag(arg)) |suggested| {
                    std.debug.print("  hint: did you mean '{s}'?\n", .{suggested});
                }
                return error.UnknownFlag;
            }
        }

        // Validate TLS cert/key pairing — both must be provided together
        if (config.tls_cert != null and config.tls_key == null) {
            std.debug.print("error: --tls-cert requires --tls-key\n", .{});
            return error.MissingTlsPair;
        }
        if (config.tls_key != null and config.tls_cert == null) {
            std.debug.print("error: --tls-key requires --tls-cert\n", .{});
            return error.MissingTlsPair;
        }

        // Warn if --ca-file or --tls-no-system-ca given without --target-tls
        if (!config.target_tls and config.ca_file != null) {
            std.debug.print("WARNING: --ca-file has no effect without --target-tls\n", .{});
        }
        if (!config.target_tls and config.tls_no_system_ca) {
            std.debug.print("WARNING: --tls-no-system-ca has no effect without --target-tls\n", .{});
        }
        if (config.runtime_model == .thread_per_connection and config.runtime_worker_threads != 0) {
            std.debug.print("WARNING: --runtime-worker-threads has no effect unless --runtime-model worker-pool is selected\n", .{});
        }

        // When --tls-no-system-ca is set without --ca-file, no CAs will be
        // trusted at all — every upstream HTTPS handshake will fail. Warn
        // the user to pair it with --ca-file.
        if (config.tls_no_system_ca and config.ca_file == null and config.target_tls) {
            std.debug.print("WARNING: --tls-no-system-ca without --ca-file means NO certificates are trusted — upstream HTTPS will fail\n", .{});
            std.debug.print("  hint: use --ca-file <path> to provide your self-signed CA bundle\n", .{});
        }

        // Require --admin-token or --admin-api-key-file when --admin-api is enabled
        // to prevent unauthenticated access to entity management endpoints.
        if (config.admin_api and config.admin_token == null and config.admin_api_key_file == null) {
            std.debug.print("error: --admin-api requires --admin-token <secret> or --admin-api-key-file <path> for authentication\n", .{});
            return error.MissingAdminToken;
        }

        // Validate Vault combinations
        if (config.vault_backend == .file and config.vault_file_path == null) {
            std.debug.print("error: --vault-backend file requires --vault-file-path\n", .{});
            return error.MissingVaultFilePath;
        }

        if (config.admin_api) {
            if (config.admin_listen_address) |admin_listen_address| {
                const admin_addr = std.net.Address.parseIpAndPort(admin_listen_address) catch unreachable;
                const proxy_addr = std.net.Address.parseIp(config.listen_host, config.listen_port) catch unreachable;
                if (std.net.Address.eql(admin_addr, proxy_addr)) {
                    std.debug.print("error: --admin-listen-address must differ from the public proxy listener address\n", .{});
                    return error.InvalidAdminListenAddress;
                }
            }
        }

        if (!config.admin_api and config.admin_listen_address != null) {
            std.debug.print("WARNING: --admin-listen-address has no effect without --admin-api\n", .{});
        }
        if (!config.admin_api and config.admin_allowlist != null) {
            std.debug.print("WARNING: --admin-allowlist has no effect without --admin-api\n", .{});
        }
        if (!config.admin_api and config.admin_read_only) {
            std.debug.print("WARNING: --admin-read-only has no effect without --admin-api\n", .{});
        }
        if (!config.admin_api and config.admin_mutation_rate_limit_per_minute_src != .default) {
            std.debug.print("WARNING: --admin-mutation-rate-limit has no effect without --admin-api\n", .{});
        }

        // mTLS: all three files must be provided together
        const mtls_count: u8 = @as(u8, if (config.mtls_ca != null) 1 else 0) +
            @as(u8, if (config.mtls_cert != null) 1 else 0) +
            @as(u8, if (config.mtls_key != null) 1 else 0);
        if (mtls_count > 0 and mtls_count < 3) {
            std.debug.print("error: --mtls-ca, --mtls-cert, and --mtls-key must all be specified together\n", .{});
            return error.InvalidMtlsConfig;
        }

        return config;
    }
};

/// Verify that a file exists and starts with a PEM header ("-----BEGIN").
/// Used to catch obviously wrong file paths or non-PEM content at startup
/// rather than at connection time.
fn checkPemFile(path: []const u8, label: []const u8) Config.ParseError!void {
    const file = std.fs.cwd().openFile(path, .{}) catch {
        std.debug.print("error: cannot open {s} PEM file '{s}'\n", .{ label, path });
        return error.InvalidMtlsPemFormat;
    };
    defer file.close();
    var hdr: [16]u8 = undefined;
    const n = file.readAll(&hdr) catch 0;
    if (n < 10 or !std.mem.startsWith(u8, hdr[0..n], "-----BEGIN")) {
        std.debug.print("error: {s} file '{s}' is not a valid PEM file (missing '-----BEGIN' header)\n", .{ label, path });
        return error.InvalidMtlsPemFormat;
    }
}

const testing = std.testing;

test "Config - parse valid arguments" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-host",
        "0.0.0.0",
        "--listen-port",
        "9090",
        "--target-host",
        "api.example.com",
        "--target-port",
        "443",
        "--fuzzy-threshold",
        "0.9",
        "--max-connections",
        "1000",
        "--log-level",
        "debug",
    };

    var config = try Config.parse(std.testing.allocator, &args);
    defer config.deinit();

    try testing.expectEqualStrings("0.0.0.0", config.listen_host);
    try testing.expectEqual(ConfigSource.cli_flag, config.listen_host_src);
    try testing.expectEqual(@as(u16, 9090), config.listen_port);
    try testing.expectEqualStrings("api.example.com", config.target_host);
    try testing.expectEqual(@as(u16, 443), config.target_port);
    try testing.expectEqual(@as(f32, 0.9), config.fuzzy_threshold);
    try testing.expectEqual(@as(u32, 1000), config.max_connections);
    try testing.expectEqual(RuntimeModel.thread_per_connection, config.runtime_model);
    try testing.expectEqual(@as(usize, 0), config.runtime_worker_threads);
    try testing.expectEqual(LogLevel.debug, config.log_level);
    try testing.expectEqual(@as(?[]const u8, null), config.entity_file);
}

test "Config - missing value" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-host",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingValue, res);
}

test "Config - default listen host is sidecar-safe localhost" {
    const args = [_][]const u8{"nanomask"};

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings("127.0.0.1", cfg.listen_host);
    try testing.expectEqualStrings("127.0.0.1", cfg.healthcheckHost());
}

test "Config - gateway listen host is accepted" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-host",
        "0.0.0.0",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    var address_buf: [32]u8 = undefined;
    try testing.expectEqualStrings("0.0.0.0", cfg.listen_host);
    try testing.expectEqualStrings("127.0.0.1", cfg.healthcheckHost());
    try testing.expectEqualStrings("0.0.0.0:8081", try cfg.formatListenAddress(&address_buf));
}

test "Config - listen host env var is accepted" {
    var cfg = Config{ .allocator = std.testing.allocator };
    defer cfg.deinit();

    try Config.applyEnvVar(&cfg, "NANOMASK_LISTEN_HOST", "0.0.0.0", std.testing.allocator);

    try testing.expectEqualStrings("0.0.0.0", cfg.listen_host);
    try testing.expectEqual(ConfigSource.env_var, cfg.listen_host_src);
}

test "Config - invalid port" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-port",
        "99999",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidPort, res);
}

test "Config - invalid listen host" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-host",
        "not-an-ip",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidListenHost, res);
}

test "Config - out of range fuzzy threshold" {
    const args = [_][]const u8{
        "nanomask",
        "--fuzzy-threshold",
        "1.5",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidThreshold, res);
}

test "Config - unknown flag" {
    const args = [_][]const u8{
        "nanomask",
        "--unknown-flag",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.UnknownFlag, res);
}

test "Config - unknown flag suggestion" {
    try testing.expectEqualStrings("--target-tls", Config.suggestFlag("--target_tls").?);
}

test "Config - unknown flag without close suggestion" {
    try testing.expect(Config.suggestFlag("--totally-different") == null);
}

test "Config - help flag" {
    const args = [_][]const u8{
        "nanomask",
        "--help",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.HelpRequested, res);
}

test "Config - help text includes optional feature surface" {
    try testing.expect(std.mem.indexOf(u8, Config.help_text, "--enable-email") != null);
    try testing.expect(std.mem.indexOf(u8, Config.help_text, "--enable-healthcare") != null);
    try testing.expect(std.mem.indexOf(u8, Config.help_text, "--schema-file") != null);
    try testing.expect(std.mem.indexOf(u8, Config.help_text, "--hash-key-file") != null);
    try testing.expect(std.mem.indexOf(u8, Config.help_text, "--unsupported-request-body-behavior") != null);
    try testing.expect(std.mem.indexOf(u8, Config.help_text, "--runtime-model") != null);
    try testing.expect(std.mem.indexOf(u8, Config.help_text, "--runtime-worker-threads") != null);
}

test "Config - invalid max connections zero" {
    const args = [_][]const u8{
        "nanomask",
        "--max-connections",
        "0",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidMaxConnections, res);
}

test "Config - runtime worker pool flags" {
    const args = [_][]const u8{
        "nanomask",
        "--runtime-model",
        "worker-pool",
        "--runtime-worker-threads",
        "12",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqual(RuntimeModel.worker_pool, cfg.runtime_model);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.runtime_model_src);
    try testing.expectEqual(@as(usize, 12), cfg.runtime_worker_threads);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.runtime_worker_threads_src);
}

test "Config - runtime model env vars" {
    var cfg = Config{ .allocator = std.testing.allocator };
    defer cfg.deinit();

    try Config.applyEnvVar(&cfg, "NANOMASK_RUNTIME_MODEL", "worker-pool", std.testing.allocator);
    try Config.applyEnvVar(&cfg, "NANOMASK_RUNTIME_WORKER_THREADS", "6", std.testing.allocator);

    try testing.expectEqual(RuntimeModel.worker_pool, cfg.runtime_model);
    try testing.expectEqual(ConfigSource.env_var, cfg.runtime_model_src);
    try testing.expectEqual(@as(usize, 6), cfg.runtime_worker_threads);
    try testing.expectEqual(ConfigSource.env_var, cfg.runtime_worker_threads_src);
}

test "Config - invalid runtime model" {
    const args = [_][]const u8{
        "nanomask",
        "--runtime-model",
        "event-loop",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidRuntimeModel, res);
}

test "Config - invalid runtime worker threads" {
    const args = [_][]const u8{
        "nanomask",
        "--runtime-worker-threads",
        "many",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidRuntimeWorkerThreads, res);
}

test "Config - valid watch interval" {
    const args = [_][]const u8{
        "nanomask",
        "--watch-interval",
        "5000",
    };

    var config = try Config.parse(std.testing.allocator, &args);
    defer config.deinit();

    try testing.expectEqual(@as(u64, 5000), config.watch_interval_ms);
    try testing.expectEqual(ConfigSource.cli_flag, config.watch_interval_ms_src);
}

test "Config - invalid watch interval zero" {
    const args = [_][]const u8{
        "nanomask",
        "--watch-interval",
        "0",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidWatchInterval, res);
}

test "Config - invalid watch interval non-numeric" {
    const args = [_][]const u8{
        "nanomask",
        "--watch-interval",
        "abc",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidWatchInterval, res);
}

test "Config - admin-api flag" {
    const args = [_][]const u8{
        "nanomask",
        "--admin-api",
        "--admin-token",
        "test-secret",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.admin_api);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.admin_api_src);
}

test "Config - admin-api without token fails" {
    const args = [_][]const u8{
        "nanomask",
        "--admin-api",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingAdminToken, res);
}

test "Config - dedicated admin listener and allowlist flags" {
    const args = [_][]const u8{
        "nanomask",
        "--admin-api",
        "--admin-token",
        "test-secret",
        "--admin-listen-address",
        "127.0.0.1:9091",
        "--admin-allowlist",
        "127.0.0.1,::1",
        "--admin-read-only",
        "--admin-mutation-rate-limit",
        "12",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings("127.0.0.1:9091", cfg.admin_listen_address.?);
    try testing.expectEqualStrings("127.0.0.1,::1", cfg.admin_allowlist.?);
    try testing.expect(cfg.admin_read_only);
    try testing.expectEqual(@as(u32, 12), cfg.admin_mutation_rate_limit_per_minute);
}

test "Config - admin listen address must differ from proxy listener" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        "8081",
        "--admin-api",
        "--admin-token",
        "test-secret",
        "--admin-listen-address",
        "127.0.0.1:8081",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidAdminListenAddress, res);
}

test "Config - admin allowlist rejects invalid IPs" {
    const args = [_][]const u8{
        "nanomask",
        "--admin-api",
        "--admin-token",
        "test-secret",
        "--admin-allowlist",
        "127.0.0.1,not-an-ip",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidAdminAllowlist, res);
}

test "Config - admin-token flag" {
    const args = [_][]const u8{
        "nanomask",
        "--admin-token",
        "mysecret",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings("mysecret", cfg.admin_token.?);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.admin_token_src);
}

test "Config - admin-token missing value" {
    const args = [_][]const u8{
        "nanomask",
        "--admin-token",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingValue, res);
}

test "Config - entity-file-sync flag" {
    const args = [_][]const u8{
        "nanomask",
        "--entity-file-sync",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.entity_file_sync);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.entity_file_sync_src);
}

test "Config - tls-cert without tls-key" {
    // Create a temporary cert file for the test
    const tmp_cert = "test_tls_cert.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_cert, .{});
        defer f.close();
        try f.writeAll("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_cert) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--tls-cert",
        tmp_cert,
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingTlsPair, res);
}

test "Config - tls-key without tls-cert" {
    const tmp_key = "test_tls_key.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_key, .{});
        defer f.close();
        try f.writeAll("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_key) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--tls-key",
        tmp_key,
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingTlsPair, res);
}

test "Config - tls-cert and tls-key valid pair" {
    const tmp_cert = "test_tls_cert2.pem";
    const tmp_key = "test_tls_key2.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_cert, .{});
        defer f.close();
        try f.writeAll("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_cert) catch {};
    {
        var f = try std.fs.cwd().createFile(tmp_key, .{});
        defer f.close();
        try f.writeAll("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_key) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--tls-cert",
        tmp_cert,
        "--tls-key",
        tmp_key,
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings(tmp_cert, cfg.tls_cert.?);
    try testing.expectEqualStrings(tmp_key, cfg.tls_key.?);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.tls_cert_src);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.tls_key_src);
}

test "Config - tls-cert file not found" {
    const args = [_][]const u8{
        "nanomask",
        "--tls-cert",
        "nonexistent_tls_cert_12345.pem",
        "--tls-key",
        "nonexistent_tls_key_12345.pem",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.TlsCertNotFound, res);
}

test "Config - tls-key file not found" {
    const tmp_cert = "test_tls_cert3.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_cert, .{});
        defer f.close();
        try f.writeAll("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_cert) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--tls-cert",
        tmp_cert,
        "--tls-key",
        "nonexistent_tls_key_12345.pem",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.TlsKeyNotFound, res);
}

test "Config - target-tls flag" {
    const args = [_][]const u8{
        "nanomask",
        "--target-tls",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.target_tls);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.target_tls_src);
}

test "Config - tls-no-system-ca flag" {
    const args = [_][]const u8{
        "nanomask",
        "--tls-no-system-ca",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.tls_no_system_ca);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.tls_no_system_ca_src);
}

test "Config - ca-file with valid file" {
    const tmp_ca = "test_ca_bundle.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_ca, .{});
        defer f.close();
        try f.writeAll("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_ca) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--ca-file",
        tmp_ca,
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings(tmp_ca, cfg.ca_file.?);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.ca_file_src);
}

test "Config - ca-file not found" {
    const args = [_][]const u8{
        "nanomask",
        "--ca-file",
        "nonexistent_ca_12345.pem",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.CaFileNotFound, res);
}

test "Config - target-tls + tls-no-system-ca combo" {
    const args = [_][]const u8{
        "nanomask",
        "--target-tls",
        "--tls-no-system-ca",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.target_tls);
    try testing.expect(cfg.tls_no_system_ca);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.target_tls_src);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.tls_no_system_ca_src);
}

test "Config - tls-no-system-ca + ca-file is valid (complementary)" {
    const tmp_ca = "test_ca_combo.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_ca, .{});
        defer f.close();
        try f.writeAll("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_ca) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--target-tls",
        "--tls-no-system-ca",
        "--ca-file",
        tmp_ca,
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.tls_no_system_ca);
    try testing.expectEqualStrings(tmp_ca, cfg.ca_file.?);
}

test "Config - healthcheck flag" {
    const args = [_][]const u8{
        "nanomask",
        "--healthcheck",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.healthcheck);
}

test "Config - upstream timeout flags" {
    const args = [_][]const u8{
        "nanomask",
        "--upstream-connect-timeout-ms",
        "1500",
        "--upstream-read-timeout-ms",
        "2500",
        "--upstream-request-timeout-ms",
        "3500",
        "--shutdown-drain-timeout-ms",
        "4500",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqual(@as(u64, 1500), cfg.upstream_connect_timeout_ms);
    try testing.expectEqual(@as(u64, 2500), cfg.upstream_read_timeout_ms);
    try testing.expectEqual(@as(u64, 3500), cfg.upstream_request_timeout_ms);
    try testing.expectEqual(@as(u64, 4500), cfg.shutdown_drain_timeout_ms);
}

test "Config - upstream timeout env vars" {
    var cfg = Config{ .allocator = std.testing.allocator };
    defer cfg.deinit();

    try Config.applyEnvVar(&cfg, "NANOMASK_UPSTREAM_CONNECT_TIMEOUT_MS", "1111", std.testing.allocator);
    try Config.applyEnvVar(&cfg, "NANOMASK_UPSTREAM_READ_TIMEOUT_MS", "2222", std.testing.allocator);
    try Config.applyEnvVar(&cfg, "NANOMASK_UPSTREAM_REQUEST_TIMEOUT_MS", "3333", std.testing.allocator);
    try Config.applyEnvVar(&cfg, "NANOMASK_SHUTDOWN_DRAIN_TIMEOUT_MS", "4444", std.testing.allocator);

    try testing.expectEqual(@as(u64, 1111), cfg.upstream_connect_timeout_ms);
    try testing.expectEqual(@as(u64, 2222), cfg.upstream_read_timeout_ms);
    try testing.expectEqual(@as(u64, 3333), cfg.upstream_request_timeout_ms);
    try testing.expectEqual(@as(u64, 4444), cfg.shutdown_drain_timeout_ms);
}

// --- Epic 8: Schema-aware redaction flag tests ---

test "Config - schema-default flag valid values" {
    const args = [_][]const u8{
        "nanomask",
        "--schema-default",
        "REDACT",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings("REDACT", cfg.schema_default.?);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.schema_default_src);
}

test "Config - schema-default invalid value" {
    const args = [_][]const u8{
        "nanomask",
        "--schema-default",
        "DELETE",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidSchemaDefault, res);
}

test "Config - schema-default missing value" {
    const args = [_][]const u8{
        "nanomask",
        "--schema-default",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingValue, res);
}

test "Config - hash-key valid 64 hex chars" {
    const valid_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const args = [_][]const u8{
        "nanomask",
        "--hash-key",
        valid_key,
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings(valid_key, cfg.hash_key.?);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.hash_key_src);
}

test "Config - hash-key invalid length" {
    const args = [_][]const u8{
        "nanomask",
        "--hash-key",
        "tooshort",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidHashKey, res);
}

test "Config - hash-key invalid hex chars" {
    // 64 chars but contains 'g' which is not valid hex
    const args = [_][]const u8{
        "nanomask",
        "--hash-key",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidHashKey, res);
}

// --- Epic 9: NMV4-010 Detection Profiles ---

test "Config - parse valid profile" {
    const args = [_][]const u8{
        "nanomask",
        "--profile",
        "hipaa-safe-harbor",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqual(Profile.hipaa_safe_harbor, cfg.profile);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.profile_src);
    // Verify some expected profile expansions
    try testing.expect(cfg.enable_email);
    try testing.expect(cfg.enable_dates);
    try testing.expect(cfg.enable_context_rules);
}

test "Config - invalid profile returns error" {
    const args = [_][]const u8{
        "nanomask",
        "--profile",
        "unknown-profile",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidProfile, res);
}

test "Config - missing profile value returns error" {
    const args = [_][]const u8{
        "nanomask",
        "--profile",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingValue, res);
}

test "Config - cli flags override profile defaults" {
    // We parse 'hipaa-safe-harbor' early in the args list, then specifically
    // disable dates manually later. Note: Nanomask args parsing currently uses boolean
    // true-only flags (e.g. --enable-dates). Normally to 'disable' a profile default,
    // arg parsers need a --disable-* flag, but since Zig config currently only has
    // --enable-*, we simulate the concept by seeing if an env var config overrides it
    // since environment variables allow 'false'.
    var cfg = Config{ .allocator = std.testing.allocator };
    defer cfg.deinit();

    // 1. Env sets profile to hipaa-safe-harbor (which enables dates)
    try Config.applyEnvVar(&cfg, "NANOMASK_PROFILE", "hipaa-safe-harbor", std.testing.allocator);
    try testing.expect(cfg.enable_dates);

    // 2. Env explicitly disables dates (overriding profile)
    try Config.applyEnvVar(&cfg, "NANOMASK_ENABLE_DATES", "false", std.testing.allocator);
    try testing.expect(!cfg.enable_dates);
}

test "Config - hash-key missing value" {
    const args = [_][]const u8{
        "nanomask",
        "--hash-key",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingValue, res);
}

test "Config - hash-key-file not found" {
    const args = [_][]const u8{
        "nanomask",
        "--hash-key-file",
        "nonexistent_hash_key_12345.txt",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.HashKeyFileNotFound, res);
}

test "Config - schema-file not found" {
    const args = [_][]const u8{
        "nanomask",
        "--schema-file",
        "nonexistent_schema_12345.txt",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.SchemaFileNotFound, res);
}

test "Config - unsupported body behavior defaults" {
    const args = [_][]const u8{"nanomask"};

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqual(UnsupportedBodyBehavior.reject, cfg.unsupported_request_body_behavior);
    try testing.expectEqual(UnsupportedBodyBehavior.bypass, cfg.unsupported_response_body_behavior);
}

test "Config - unsupported body behavior flags" {
    const args = [_][]const u8{
        "nanomask",
        "--unsupported-request-body-behavior",
        "bypass",
        "--unsupported-response-body-behavior",
        "reject",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqual(UnsupportedBodyBehavior.bypass, cfg.unsupported_request_body_behavior);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.unsupported_request_body_behavior_src);
    try testing.expectEqual(UnsupportedBodyBehavior.reject, cfg.unsupported_response_body_behavior);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.unsupported_response_body_behavior_src);
}

test "Config - unsupported body behavior invalid value" {
    const args = [_][]const u8{
        "nanomask",
        "--unsupported-request-body-behavior",
        "drop",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidUnsupportedBodyBehavior, res);
}

test "Config - validate-config flag" {
    const args = [_][]const u8{
        "nanomask",
        "--validate-config",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.validate_config);
}

test "Config - validate-config combined with other flags" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-host",
        "0.0.0.0",
        "--target-host",
        "api.openai.com",
        "--target-port",
        "443",
        "--target-tls",
        "--enable-email",
        "--validate-config",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.validate_config);
    try testing.expectEqualStrings("0.0.0.0", cfg.listen_host);
    try testing.expectEqualStrings("api.openai.com", cfg.target_host);
    try testing.expectEqual(@as(u16, 443), cfg.target_port);
    try testing.expect(cfg.target_tls);
    try testing.expect(cfg.enable_email);
}

test "Config - validate-config defaults to false" {
    const args = [_][]const u8{"nanomask"};

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(!cfg.validate_config);
}

test "Config - vault-backend valid type" {
    const args = [_][]const u8{
        "nanomask",
        "--vault-backend",
        "file",
        "--vault-file-path",
        "/tmp/vault.enc",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqual(VaultBackend.file, cfg.vault_backend);
    try testing.expectEqualStrings("/tmp/vault.enc", cfg.vault_file_path.?);
}

test "Config - vault-backend file requires path" {
    const args = [_][]const u8{
        "nanomask",
        "--vault-backend",
        "file",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingVaultFilePath, res);
}

test "Config - vault-backend invalid type" {
    const args = [_][]const u8{
        "nanomask",
        "--vault-backend",
        "postgres",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidVaultBackend, res);
}

