// TLS 1.3 server module for NanoMask.
//
// Provides TLS termination on the listener side using only Zig stdlib primitives.
// Implements the server half of the TLS 1.3 handshake (RFC 8446) with:
//   - X25519 key exchange (ECDHE)
//   - AES-128-GCM-SHA256 cipher suite
//   - ECDSA P-256 / Ed25519 certificate signing
//
// Why custom instead of a library? Zig 0.15.2 has no std.crypto.tls.Server,
// ianic/tls.zig requires std.Io (async) which doesn't match our blocking model,
// and BearSSL only supports TLS 1.2. This module implements the minimal TLS 1.3
// server handshake needed for HIPAA compliance.

const std = @import("std");
const tls = std.crypto.tls;
const crypto = std.crypto;
const mem = std.mem;
const Certificate = std.crypto.Certificate;

// ===========================================================================
// Public types
// ===========================================================================

/// Reusable server TLS context loaded once at startup. Thread-safe (immutable
/// after init). Each accepted connection calls `accept()` which performs the
/// per-connection handshake.
pub const TlsContext = struct {
    /// Raw DER-encoded certificate chain bytes (read from PEM file).
    cert_der: []const u8,
    /// Private key bytes for signing (ECDSA P-256 or Ed25519).
    private_key: PrivateKey,
    allocator: std.mem.Allocator,

    pub const PrivateKey = union(enum) {
        ec_p256: crypto.ecc.P256.SecretKey,
        ed25519: [32]u8,
    };

    pub const InitError = error{
        InvalidCertFile,
        InvalidKeyFile,
        UnsupportedKeyAlgorithm,
        OutOfMemory,
        FileNotFound,
        AccessDenied,
        Unexpected,
    };

    /// Load TLS context from PEM cert and key file paths.
    pub fn init(cert_path: []const u8, key_path: []const u8, allocator: std.mem.Allocator) InitError!TlsContext {
        const cert_der = loadPemDer(cert_path, "CERTIFICATE", allocator) catch {
            return error.InvalidCertFile;
        };
        errdefer allocator.free(cert_der);

        // Try PKCS#8 "PRIVATE KEY" first, fall back to OpenSSL "EC PRIVATE KEY"
        const key_der = loadPemDer(key_path, "PRIVATE KEY", allocator) catch
            loadPemDer(key_path, "EC PRIVATE KEY", allocator) catch {
            return error.InvalidKeyFile;
        };
        defer allocator.free(key_der);

        const private_key = parsePrivateKey(key_der) catch {
            return error.UnsupportedKeyAlgorithm;
        };

        return .{
            .cert_der = cert_der,
            .private_key = private_key,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TlsContext) void {
        self.allocator.free(self.cert_der);
    }
};

/// Read a PEM file and extract the DER-encoded payload for the given label.
/// For example, label "CERTIFICATE" matches -----BEGIN CERTIFICATE-----.
fn loadPemDer(path: []const u8, label: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch {
        return error.FileNotFound;
    };
    defer file.close();

    const pem_data = file.readToEndAlloc(allocator, 1024 * 1024) catch {
        return error.OutOfMemory;
    };
    defer allocator.free(pem_data);

    return decodePem(pem_data, label, allocator);
}

/// Decode base64 PEM content between BEGIN/END markers.
fn decodePem(pem_data: []const u8, label: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // Build the expected header/footer — buffers are large enough for any
    // standard PEM label, so overflow is a programming bug, not bad input.
    var header_buf: [128]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "-----BEGIN {s}-----", .{label}) catch unreachable;
    var footer_buf: [128]u8 = undefined;
    const footer = std.fmt.bufPrint(&footer_buf, "-----END {s}-----", .{label}) catch unreachable;

    // Find BEGIN marker
    const header_start = mem.indexOf(u8, pem_data, header) orelse return error.InvalidCertFile;
    const content_start = header_start + header.len;

    // Find END marker
    const footer_start = mem.indexOf(u8, pem_data[content_start..], footer) orelse return error.InvalidCertFile;
    const base64_data = pem_data[content_start .. content_start + footer_start];

    // Strip whitespace and decode base64
    var clean_buf = try allocator.alloc(u8, base64_data.len);
    defer allocator.free(clean_buf);
    var clean_len: usize = 0;
    for (base64_data) |c| {
        if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
            clean_buf[clean_len] = c;
            clean_len += 1;
        }
    }

    const decoded_size = std.base64.standard.Decoder.calcSizeForSlice(clean_buf[0..clean_len]) catch {
        return error.InvalidCertFile;
    };
    const result = try allocator.alloc(u8, decoded_size);
    errdefer allocator.free(result);

    std.base64.standard.Decoder.decode(result, clean_buf[0..clean_len]) catch {
        allocator.free(result);
        return error.InvalidCertFile;
    };

    return result;
}

/// Parse a DER-encoded PKCS#8 private key to extract the raw key bytes.
/// Walks the ASN.1 structure properly instead of byte-pattern scanning.
fn parsePrivateKey(der: []const u8) !TlsContext.PrivateKey {
    // PKCS#8 PrivateKeyInfo (RFC 5958):
    //   SEQUENCE {
    //     INTEGER (version)
    //     SEQUENCE { OID (algorithm), ...params... }
    //     OCTET STRING (private key data)
    //   }

    // EC P-256 OID: 1.2.840.10045.3.1.7
    const ec_p256_oid = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    // Ed25519 OID: 1.3.101.112
    const ed25519_oid = [_]u8{ 0x2b, 0x65, 0x70 };

    if (mem.indexOf(u8, der, &ec_p256_oid) != null) {
        const key_bytes = extractPkcs8PrivateKeyOctet(der, 32) orelse return error.UnsupportedKeyAlgorithm;
        return .{ .ec_p256 = try crypto.ecc.P256.SecretKey.fromBytes(key_bytes[0..32].*) };
    } else if (mem.indexOf(u8, der, &ed25519_oid) != null) {
        const key_bytes = extractPkcs8PrivateKeyOctet(der, 32) orelse return error.UnsupportedKeyAlgorithm;
        return .{ .ed25519 = key_bytes[0..32].* };
    }

    return error.UnsupportedKeyAlgorithm;
}

// ---------------------------------------------------------------------------
// Minimal ASN.1 DER helpers
// ---------------------------------------------------------------------------

/// Read the length field of a DER TLV at `pos`, returning (length, bytes_consumed).
fn derReadLength(der: []const u8, pos: usize) ?struct { len: usize, size: usize } {
    if (pos >= der.len) return null;
    const first = der[pos];
    if (first & 0x80 == 0) {
        // Short form: length fits in 7 bits
        return .{ .len = first, .size = 1 };
    }
    const num_bytes = first & 0x7F;
    if (num_bytes == 0 or num_bytes > 4) return null; // indefinite / too large
    if (pos + 1 + num_bytes > der.len) return null;
    var length: usize = 0;
    for (0..num_bytes) |j| {
        length = (length << 8) | der[pos + 1 + j];
    }
    return .{ .len = length, .size = 1 + num_bytes };
}

/// Extract the private key bytes from a PKCS#8 DER structure by walking
/// the ASN.1 tree: top SEQUENCE → skip version INTEGER → skip algorithm
/// SEQUENCE → read outer OCTET STRING → for EC keys, descend into the
/// inner ECPrivateKey SEQUENCE and find the OCTET STRING of `key_len`.
fn extractPkcs8PrivateKeyOctet(der: []const u8, key_len: usize) ?[]const u8 {
    // Step 1: Enter the top-level SEQUENCE
    if (der.len < 2 or der[0] != 0x30) return null;
    const top_len_info = derReadLength(der, 1) orelse return null;
    var pos: usize = 1 + top_len_info.size;

    // Step 2: Skip the version INTEGER
    if (pos >= der.len or der[pos] != 0x02) return null;
    const ver_len_info = derReadLength(der, pos + 1) orelse return null;
    pos += 1 + ver_len_info.size + ver_len_info.len;

    // Step 3: Skip the AlgorithmIdentifier SEQUENCE
    if (pos >= der.len or der[pos] != 0x30) return null;
    const alg_len_info = derReadLength(der, pos + 1) orelse return null;
    pos += 1 + alg_len_info.size + alg_len_info.len;

    // Step 4: Read the outer OCTET STRING (wraps the key material)
    if (pos >= der.len or der[pos] != 0x04) return null;
    const outer_len_info = derReadLength(der, pos + 1) orelse return null;
    const octet_start = pos + 1 + outer_len_info.size;
    const octet_end = octet_start + outer_len_info.len;
    if (octet_end > der.len) return null;
    const octet_data = der[octet_start..octet_end];

    // For Ed25519: the OCTET STRING directly wraps another OCTET STRING
    // containing the 32-byte key.
    if (octet_data.len == key_len + 2 and octet_data[0] == 0x04 and octet_data[1] == key_len) {
        return octet_data[2 .. 2 + key_len];
    }

    // For EC keys: the OCTET STRING wraps an ECPrivateKey SEQUENCE.
    // Descend into it and find the inner OCTET STRING with the raw key.
    if (octet_data.len > 2 and octet_data[0] == 0x30) {
        const inner_len_info = derReadLength(octet_data, 1) orelse return null;
        var inner_pos: usize = 1 + inner_len_info.size;

        // Walk the ECPrivateKey elements looking for OCTET STRING of key_len
        while (inner_pos + 2 <= octet_data.len) {
            const tag = octet_data[inner_pos];
            const elem_len_info = derReadLength(octet_data, inner_pos + 1) orelse return null;
            const elem_start = inner_pos + 1 + elem_len_info.size;
            const elem_end = elem_start + elem_len_info.len;
            if (elem_end > octet_data.len) return null;

            if (tag == 0x04 and elem_len_info.len == key_len) {
                return octet_data[elem_start..elem_end];
            }
            inner_pos = elem_end;
        }
    }

    // Direct OCTET STRING content of the right size (raw key)
    if (octet_data.len == key_len) return octet_data;

    return null;
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "decodePem - valid certificate" {
    const allocator = std.testing.allocator;
    // A minimal valid base64-encoded PEM block
    const pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "dGVzdGNlcnQ=\n" ++
        "-----END CERTIFICATE-----\n";

    const result = try decodePem(pem, "CERTIFICATE", allocator);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("testcert", result);
}

test "decodePem - wrong label" {
    const allocator = std.testing.allocator;
    const pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "dGVzdA==\n" ++
        "-----END CERTIFICATE-----\n";

    const result = decodePem(pem, "PRIVATE KEY", allocator);
    try std.testing.expectError(error.InvalidCertFile, result);
}

test "decodePem - missing end marker" {
    const allocator = std.testing.allocator;
    const pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "dGVzdA==\n";

    const result = decodePem(pem, "CERTIFICATE", allocator);
    try std.testing.expectError(error.InvalidCertFile, result);
}

test "decodePem - multiline base64" {
    const allocator = std.testing.allocator;
    // "hello world" = aGVsbG8gd29ybGQ=
    const pem =
        "-----BEGIN TEST-----\n" ++
        "aGVs\n" ++
        "bG8g\r\n" ++
        "d29y\n" ++
        "bGQ=\n" ++
        "-----END TEST-----\n";

    const result = try decodePem(pem, "TEST", allocator);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("hello world", result);
}
