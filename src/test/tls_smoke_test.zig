// TLS module smoke tests
//
// Validates that the TLS context initialisation, PEM parsing, and
// private key extraction code paths in src/crypto/tls.zig continue
// to work correctly. These tests exercise the public interface without
// requiring a full handshake.

const std = @import("std");
const tls_mod = @import("../crypto/tls.zig");

// ---------------------------------------------------------------------------
// TlsContext.init — error paths (file not found)
// ---------------------------------------------------------------------------

test "TlsContext.init - missing cert file returns InvalidCertFile" {
    const allocator = std.testing.allocator;
    const result = tls_mod.TlsContext.init(
        "/nonexistent/path/cert.pem",
        "/nonexistent/path/key.pem",
        allocator,
    );
    try std.testing.expectError(error.InvalidCertFile, result);
}

test "TlsContext.init - missing key file returns InvalidKeyFile" {
    const allocator = std.testing.allocator;

    // Create a temporary valid cert PEM to get past the cert check
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const cert_pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "dGVzdGNlcnQ=\n" ++
        "-----END CERTIFICATE-----\n";
    const cert_file = try tmp_dir.dir.createFile("cert.pem", .{});
    defer cert_file.close();
    try cert_file.writeAll(cert_pem);

    // Use the real cert path but a nonexistent key path
    var cert_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cert_path = try tmp_dir.dir.realpath("cert.pem", &cert_path_buf);

    const result = tls_mod.TlsContext.init(
        cert_path,
        "/nonexistent/path/key.pem",
        allocator,
    );
    try std.testing.expectError(error.InvalidKeyFile, result);
}

// ---------------------------------------------------------------------------
// PEM decode — extends existing tests in tls.zig
// ---------------------------------------------------------------------------

test "decodePem via TlsContext.init - empty PEM content is rejected" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Empty file (no PEM markers at all)
    const empty_file = try tmp_dir.dir.createFile("empty.pem", .{});
    defer empty_file.close();
    try empty_file.writeAll("");

    var cert_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cert_path = try tmp_dir.dir.realpath("empty.pem", &cert_path_buf);

    const result = tls_mod.TlsContext.init(
        cert_path,
        cert_path,
        allocator,
    );
    try std.testing.expectError(error.InvalidCertFile, result);
}

// ---------------------------------------------------------------------------
// TlsContext lifecycle — oversized cert rejection
// ---------------------------------------------------------------------------

test "TlsContext.init - oversized cert DER is rejected" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Create a PEM with more than 8 KB of DER content
    // Base64 encoding: 3 bytes → 4 chars, so we need ~11 KB base64 for >8 KB DER
    const oversized_payload = "A" ** (12 * 1024); // ~9 KB decoded
    const cert_pem = "-----BEGIN CERTIFICATE-----\n" ++
        oversized_payload ++
        "\n-----END CERTIFICATE-----\n";

    const cert_file = try tmp_dir.dir.createFile("big.pem", .{});
    defer cert_file.close();
    try cert_file.writeAll(cert_pem);

    var cert_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cert_path = try tmp_dir.dir.realpath("big.pem", &cert_path_buf);

    const result = tls_mod.TlsContext.init(
        cert_path,
        cert_path,
        allocator,
    );
    try std.testing.expectError(error.InvalidCertFile, result);
}

// ---------------------------------------------------------------------------
// Happy-path: valid EC P-256 cert + PKCS#8 key → successful init
// ---------------------------------------------------------------------------

test "TlsContext.init - valid EC P-256 cert and key succeeds" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // --- Generate a real EC P-256 keypair ---
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var secret_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&secret_bytes);
    const sk = try EcdsaP256.SecretKey.fromBytes(secret_bytes);
    const kp = try EcdsaP256.KeyPair.fromSecretKey(sk);

    // --- Build a minimal self-signed X.509 v3 certificate (DER) ---
    // This is the smallest valid structure TlsContext needs: the PEM
    // decoder only checks BEGIN/END markers and base64; the init path
    // validates DER size ≤ 8 KB and then extracts cert_der verbatim.
    const cert_der = buildMinimalCertDer(&kp);

    // --- Build PKCS#8 PrivateKeyInfo wrapping the 32-byte EC key ---
    const key_der = buildEcP256Pkcs8Der(&secret_bytes);

    // --- base64-encode and wrap in PEM ---
    const cert_pem = try pemEncode(allocator, "CERTIFICATE", &cert_der);
    defer allocator.free(cert_pem);
    const key_pem = try pemEncode(allocator, "PRIVATE KEY", &key_der);
    defer allocator.free(key_pem);

    // Write to temp files
    const cert_file = try tmp_dir.dir.createFile("cert.pem", .{});
    defer cert_file.close();
    try cert_file.writeAll(cert_pem);

    const key_file = try tmp_dir.dir.createFile("key.pem", .{});
    defer key_file.close();
    try key_file.writeAll(key_pem);

    var cert_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cert_path = try tmp_dir.dir.realpath("cert.pem", &cert_path_buf);
    var key_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const key_path = try tmp_dir.dir.realpath("key.pem", &key_path_buf);

    var ctx = try tls_mod.TlsContext.init(cert_path, key_path, allocator);
    defer ctx.deinit();

    // Verify the parsed key matches the original private key bytes
    switch (ctx.private_key) {
        .ec_p256 => |key_bytes| {
            try std.testing.expectEqualSlices(u8, &secret_bytes, &key_bytes);
        },
        .ed25519 => return error.UnexpectedKeyType,
    }
}

// ===========================================================================
// Helpers — minimal DER construction for test PEM generation
// ===========================================================================

/// Build a minimal self-signed X.509 certificate DER.
/// This produces a syntactically valid DER that TlsContext accepts.
fn buildMinimalCertDer(kp: *const std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair) [300]u8 {
    // Minimal TBSCertificate structure with fixed fields:
    //   SEQUENCE {
    //     [0] EXPLICIT INTEGER (version v3 = 2)
    //     INTEGER (serialNumber = 1)
    //     SEQUENCE { OID sha256WithECDSA }
    //     SEQUENCE { ... issuer CN=test ... }
    //     SEQUENCE { ... validity ... }
    //     SEQUENCE { ... subject CN=test ... }
    //     SEQUENCE { ... subjectPublicKeyInfo (EC P-256) ... }
    //   }
    //
    // We use a pre-built template and patch in the public key.
    var buf: [300]u8 = [_]u8{0} ** 300;

    // EC P-256 OID: 1.2.840.10045.3.1.7
    const ec_p256_oid = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    // ecPublicKey OID: 1.2.840.10045.2.1
    const ec_pub_oid = [_]u8{ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
    // sha256WithECDSA OID: 1.2.840.10045.4.3.2
    const sig_alg_oid = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };

    // Simple CN=test as UTF8String
    // SET { SEQUENCE { OID 2.5.4.3, UTF8String "test" } }
    const cn_rdn = [_]u8{
        0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x05, 0x74, 0x65, 0x73, 0x74, 0x73,
    };

    // Validity: UTCTime "250101000000Z" to "350101000000Z"
    const validity = [_]u8{
        0x30, 0x1e, // SEQUENCE
        0x17, 0x0d, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
        0x17, 0x0d, 0x33, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    };

    // Uncompressed public key point: 0x04 || x(32) || y(32) = 65 bytes
    const pub_key_bytes = kp.public_key.toUncompressedSec1();

    // SubjectPublicKeyInfo for EC P-256:
    //   SEQUENCE {
    //     SEQUENCE { OID ecPublicKey, OID P-256 }
    //     BIT STRING (65 bytes uncompressed)
    //   }
    // BIT STRING: tag(1) + len(1) + unused_bits(1) + 65 = 68 total TLV
    // Inner SEQUENCE: ec_pub_oid(9) + ec_p256_oid(10) = 19
    // SPKI SEQUENCE: inner_seq(2+19) + bitstring(2+66) = 89

    var pos: usize = 0;

    // We'll build TBSCertificate content first, then wrap in outer SEQUENCE later
    var tbs: [250]u8 = undefined;
    var tpos: usize = 0;

    // version [0] EXPLICIT INTEGER 2
    tbs[tpos] = 0xa0;
    tbs[tpos + 1] = 0x03;
    tbs[tpos + 2] = 0x02;
    tbs[tpos + 3] = 0x01;
    tbs[tpos + 4] = 0x02;
    tpos += 5;

    // serialNumber INTEGER 1
    tbs[tpos] = 0x02;
    tbs[tpos + 1] = 0x01;
    tbs[tpos + 2] = 0x01;
    tpos += 3;

    // signature AlgorithmIdentifier
    tbs[tpos] = 0x30;
    tbs[tpos + 1] = @intCast(sig_alg_oid.len);
    tpos += 2;
    @memcpy(tbs[tpos..][0..sig_alg_oid.len], &sig_alg_oid);
    tpos += sig_alg_oid.len;

    // issuer
    @memcpy(tbs[tpos..][0..cn_rdn.len], &cn_rdn);
    tpos += cn_rdn.len;

    // validity
    @memcpy(tbs[tpos..][0..validity.len], &validity);
    tpos += validity.len;

    // subject (same as issuer for self-signed)
    @memcpy(tbs[tpos..][0..cn_rdn.len], &cn_rdn);
    tpos += cn_rdn.len;

    // subjectPublicKeyInfo
    const spki_inner_len = ec_pub_oid.len + ec_p256_oid.len;
    const bitstring_content_len: usize = 1 + 65; // unused_bits + point
    const spki_len = 2 + spki_inner_len + 2 + bitstring_content_len;

    tbs[tpos] = 0x30;
    tbs[tpos + 1] = @intCast(spki_len);
    tpos += 2;

    // algorithm SEQUENCE
    tbs[tpos] = 0x30;
    tbs[tpos + 1] = @intCast(spki_inner_len);
    tpos += 2;
    @memcpy(tbs[tpos..][0..ec_pub_oid.len], &ec_pub_oid);
    tpos += ec_pub_oid.len;
    @memcpy(tbs[tpos..][0..ec_p256_oid.len], &ec_p256_oid);
    tpos += ec_p256_oid.len;

    // BIT STRING
    tbs[tpos] = 0x03;
    tbs[tpos + 1] = @intCast(bitstring_content_len);
    tbs[tpos + 2] = 0x00; // unused bits
    tpos += 3;
    @memcpy(tbs[tpos..][0..65], &pub_key_bytes);
    tpos += 65;

    // Wrap TBSCertificate in SEQUENCE
    // Then the outer Certificate SEQUENCE wraps TBS + sigAlg + sigValue
    // For our test we only need the cert_der to be ≤ 8 KB — TlsContext
    // stores it verbatim. The actual X.509 signature is not validated by
    // TlsContext.init, so we add dummy signature bytes.

    // signatureAlgorithm (same as above)
    var sig_alg: [2 + sig_alg_oid.len]u8 = undefined;
    sig_alg[0] = 0x30;
    sig_alg[1] = @intCast(sig_alg_oid.len);
    @memcpy(sig_alg[2..], &sig_alg_oid);

    // signatureValue BIT STRING (dummy)
    const dummy_sig = [_]u8{ 0x03, 0x03, 0x00, 0x30, 0x00 };

    // TBS SEQUENCE
    const tbs_seq_len = tpos;
    // Certificate SEQUENCE content = TBS_SEQ + sigAlg + sigValue
    const cert_content_len = (2 + tbs_seq_len) + sig_alg.len + dummy_sig.len;

    // Outer SEQUENCE
    buf[pos] = 0x30;
    pos += 1;
    // Use two-byte length encoding to keep it simple
    buf[pos] = 0x81;
    buf[pos + 1] = @intCast(cert_content_len);
    pos += 2;

    // TBS SEQUENCE header
    buf[pos] = 0x30;
    buf[pos + 1] = 0x81;
    buf[pos + 2] = @intCast(tbs_seq_len);
    pos += 3;
    @memcpy(buf[pos..][0..tbs_seq_len], tbs[0..tbs_seq_len]);
    pos += tbs_seq_len;

    @memcpy(buf[pos..][0..sig_alg.len], &sig_alg);
    pos += sig_alg.len;
    @memcpy(buf[pos..][0..dummy_sig.len], &dummy_sig);
    pos += dummy_sig.len;

    // Return a fixed-size array; unused tail stays zero (fine for test).
    return buf;
}

/// Build a PKCS#8 PrivateKeyInfo DER for an EC P-256 key.
///
/// SEQUENCE {
///   INTEGER 0  (version)
///   SEQUENCE { OID ecPublicKey, OID P-256 }
///   OCTET STRING {
///     SEQUENCE {           -- ECPrivateKey (RFC 5915)
///       INTEGER 1
///       OCTET STRING (32 bytes of private key)
///     }
///   }
/// }
fn buildEcP256Pkcs8Der(secret_key: *const [32]u8) [80]u8 {
    // Pre-computed fixed portions
    const ec_pub_oid = [_]u8{ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
    const ec_p256_oid = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

    var buf: [80]u8 = [_]u8{0} ** 80;
    var pos: usize = 0;

    // ECPrivateKey inner SEQUENCE content:
    //   INTEGER 1 (3 bytes) + OCTET STRING tag(1) + len(1) + 32 bytes = 37
    const ec_priv_content_len: usize = 3 + 2 + 32;
    // ECPrivateKey SEQUENCE TLV: tag(1) + len(1) + content
    const ec_priv_seq_len: usize = 2 + ec_priv_content_len;
    // Outer OCTET STRING wrapping ECPrivateKey: tag(1) + len(1) + ec_priv_seq
    const outer_octet_len: usize = 2 + ec_priv_seq_len;
    // AlgorithmIdentifier SEQUENCE content
    const alg_content_len: usize = ec_pub_oid.len + ec_p256_oid.len;
    // AlgorithmIdentifier SEQUENCE TLV
    const alg_seq_len: usize = 2 + alg_content_len;
    // version INTEGER 0 TLV
    const ver_len: usize = 3;
    // Total PrivateKeyInfo SEQUENCE content
    const pki_content_len: usize = ver_len + alg_seq_len + outer_octet_len;

    // PrivateKeyInfo SEQUENCE
    buf[pos] = 0x30;
    buf[pos + 1] = @intCast(pki_content_len);
    pos += 2;

    // version INTEGER 0
    buf[pos] = 0x02;
    buf[pos + 1] = 0x01;
    buf[pos + 2] = 0x00;
    pos += 3;

    // AlgorithmIdentifier SEQUENCE
    buf[pos] = 0x30;
    buf[pos + 1] = @intCast(alg_content_len);
    pos += 2;
    @memcpy(buf[pos..][0..ec_pub_oid.len], &ec_pub_oid);
    pos += ec_pub_oid.len;
    @memcpy(buf[pos..][0..ec_p256_oid.len], &ec_p256_oid);
    pos += ec_p256_oid.len;

    // Outer OCTET STRING
    buf[pos] = 0x04;
    buf[pos + 1] = @intCast(ec_priv_seq_len);
    pos += 2;

    // ECPrivateKey SEQUENCE
    buf[pos] = 0x30;
    buf[pos + 1] = @intCast(ec_priv_content_len);
    pos += 2;

    // version INTEGER 1
    buf[pos] = 0x02;
    buf[pos + 1] = 0x01;
    buf[pos + 2] = 0x01;
    pos += 3;

    // privateKey OCTET STRING (32 bytes)
    buf[pos] = 0x04;
    buf[pos + 1] = 0x20;
    pos += 2;
    @memcpy(buf[pos..][0..32], secret_key);
    pos += 32;

    return buf;
}

/// Base64-encode DER bytes and wrap in PEM with the given label.
fn pemEncode(allocator: std.mem.Allocator, label: []const u8, der: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const b64_len = encoder.calcSize(der.len);

    // "-----BEGIN <label>-----\n" + base64 + "\n-----END <label>-----\n"
    const header_prefix = "-----BEGIN ";
    const header_suffix = "-----\n";
    const footer_prefix = "\n-----END ";
    const footer_suffix = "-----\n";
    const total = header_prefix.len + label.len + header_suffix.len +
        b64_len +
        footer_prefix.len + label.len + footer_suffix.len;

    const result = try allocator.alloc(u8, total);
    var pos: usize = 0;

    @memcpy(result[pos..][0..header_prefix.len], header_prefix);
    pos += header_prefix.len;
    @memcpy(result[pos..][0..label.len], label);
    pos += label.len;
    @memcpy(result[pos..][0..header_suffix.len], header_suffix);
    pos += header_suffix.len;

    _ = encoder.encode(result[pos..][0..b64_len], der);
    pos += b64_len;

    @memcpy(result[pos..][0..footer_prefix.len], footer_prefix);
    pos += footer_prefix.len;
    @memcpy(result[pos..][0..label.len], label);
    pos += label.len;
    @memcpy(result[pos..][0..footer_suffix.len], footer_suffix);

    return result;
}
