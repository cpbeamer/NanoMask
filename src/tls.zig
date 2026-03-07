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

// ===========================================================================
// Public types
// ===========================================================================

/// Reusable server TLS context loaded once at startup. Thread-safe (immutable
/// after init). Each accepted connection calls `accept()` which performs the
/// per-connection handshake.
/// Maximum certificate DER size we support (8 KB). Rejects oversized certs
/// at init time rather than risking a stack buffer overflow during handshake.
const max_cert_der_len = 8 * 1024;

pub const TlsContext = struct {
    /// Raw DER-encoded certificate chain bytes (read from PEM file).
    cert_der: []const u8,
    /// Private key bytes for signing (ECDSA P-256 or Ed25519).
    private_key: PrivateKey,
    allocator: std.mem.Allocator,

    pub const PrivateKey = union(enum) {
        ec_p256: [32]u8,
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
        if (cert_der.len > max_cert_der_len) {
            allocator.free(cert_der);
            return error.InvalidCertFile;
        }
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
        const ec_bytes = key_bytes[0..32].*;
        // Validate the key by constructing an ECDSA secret key
        _ = crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(ec_bytes) catch
            return error.InvalidKeyFile;

        return .{ .ec_p256 = ec_bytes };
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
// TLS 1.3 Server Stream — per-connection encrypted I/O
// ===========================================================================

const Io = std.Io;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Sha256 = crypto.hash.sha2.Sha256;
const Hmac = crypto.auth.hmac.Hmac(Sha256);
const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);

/// Per-connection TLS state providing encrypted Reader/Writer interfaces.
/// Created by `TlsContext.accept()` after a successful handshake.
pub const TlsServerStream = struct {
    /// Plaintext reader interface — decrypts incoming TLS records.
    reader_state: Io.Reader,
    /// Plaintext writer interface — encrypts outgoing TLS records.
    writer_state: Io.Writer,

    // Underlying raw socket I/O
    raw_reader: *Io.Reader,
    raw_writer: *Io.Writer,

    // Application traffic keys
    client_key: [Aes128Gcm.key_length]u8,
    server_key: [Aes128Gcm.key_length]u8,
    client_iv: [Aes128Gcm.nonce_length]u8,
    server_iv: [Aes128Gcm.nonce_length]u8,

    read_seq: u64,
    write_seq: u64,

    // Decrypted plaintext buffer for reads — a TLS record can hold up to 16KB
    plaintext_buf: [tls.max_ciphertext_inner_record_len]u8,
    plaintext_start: usize,
    plaintext_end: usize,

    pub fn reader(self: *TlsServerStream) *Io.Reader {
        return &self.reader_state;
    }

    pub fn writer(self: *TlsServerStream) *Io.Writer {
        return &self.writer_state;
    }

    // --- Reader vtable implementation ---

    fn tlsReaderStream(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *TlsServerStream = @alignCast(@fieldParentPtr("reader_state", io_r));

        // Serve from plaintext buffer first
        if (self.plaintext_start < self.plaintext_end) {
            const avail = self.plaintext_end - self.plaintext_start;
            const max_bytes = if (limit.toInt()) |n| @min(avail, n) else avail;
            const n = io_w.write(self.plaintext_buf[self.plaintext_start..][0..max_bytes]) catch
                return error.WriteFailed;
            self.plaintext_start += n;
            return n;
        }

        // Need to read and decrypt the next TLS record
        self.plaintext_start = 0;
        self.plaintext_end = 0;

        // Read record header (5 bytes): content_type(1) + legacy_version(2) + length(2)
        const header = self.raw_reader.peek(tls.record_header_len) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
        };

        const content_type: tls.ContentType = @enumFromInt(header[0]);
        const record_len = @as(u16, header[3]) << 8 | header[4];
        self.raw_reader.toss(tls.record_header_len);

        if (record_len > tls.max_ciphertext_len) return error.ReadFailed;

        // Read the full record payload
        const record_data = self.raw_reader.take(record_len) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
        };

        // Handle alert records
        if (content_type == .alert) {
            return error.EndOfStream;
        }

        // For application_data, decrypt
        if (content_type != .application_data) return error.ReadFailed;

        if (record_len < Aes128Gcm.tag_length + 1) return error.ReadFailed;
        const ciphertext_len = record_len - Aes128Gcm.tag_length;
        const ciphertext = record_data[0..ciphertext_len];
        const auth_tag = record_data[ciphertext_len..][0..Aes128Gcm.tag_length].*;

        // Build nonce: XOR the IV with the sequence counter
        var nonce: [Aes128Gcm.nonce_length]u8 = self.client_iv;
        const seq_bytes = mem.toBytes(mem.nativeTo(u64, self.read_seq, .big));
        const nonce_offset = Aes128Gcm.nonce_length - 8;
        for (0..8) |i| {
            nonce[nonce_offset + i] ^= seq_bytes[i];
        }
        self.read_seq += 1;

        // Additional data is the record header
        const ad = header[0..tls.record_header_len];

        // Decrypt into plaintext buffer
        Aes128Gcm.decrypt(
            self.plaintext_buf[0..ciphertext_len],
            ciphertext,
            auth_tag,
            ad,
            nonce,
            self.client_key,
        ) catch return error.ReadFailed;

        // Strip content type byte and padding zeros (RFC 8446 §5.2)
        var pt_len = ciphertext_len;
        while (pt_len > 0 and self.plaintext_buf[pt_len - 1] == 0) pt_len -= 1;
        if (pt_len == 0) return error.ReadFailed;
        pt_len -= 1; // Remove the content type byte

        self.plaintext_end = pt_len;

        // Now serve from the freshly decrypted buffer
        const avail = self.plaintext_end - self.plaintext_start;
        const max_bytes = if (limit.toInt()) |n| @min(avail, n) else avail;
        if (max_bytes == 0) return error.EndOfStream;
        const n = io_w.write(self.plaintext_buf[self.plaintext_start..][0..max_bytes]) catch
            return error.WriteFailed;
        self.plaintext_start += n;
        return n;
    }

    // --- Writer vtable implementation ---

    fn tlsWriterDrain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *TlsServerStream = @alignCast(@fieldParentPtr("writer_state", io_w));

        // Gather all bytes to encrypt
        var total: usize = 0;
        // First, the buffered bytes in io_w
        const buffered = io_w.buffered();
        total += buffered.len;
        for (data[0 .. data.len - 1]) |d| total += d.len;
        total += data[data.len - 1].len * splat;

        // Assemble plaintext into a temp buffer
        var plaintext: [tls.max_ciphertext_inner_record_len]u8 = undefined;
        // Cap at max plaintext size minus 1 (for content type byte)
        const max_pt = tls.max_ciphertext_inner_record_len - 1;
        const pt_len = @min(total, max_pt);

        var pos: usize = 0;
        // Copy buffered data
        const buf_copy = @min(buffered.len, pt_len);
        @memcpy(plaintext[0..buf_copy], buffered[0..buf_copy]);
        pos += buf_copy;

        // Copy data slices
        for (data[0 .. data.len - 1]) |d| {
            if (pos >= pt_len) break;
            const copy_len = @min(d.len, pt_len - pos);
            @memcpy(plaintext[pos..][0..copy_len], d[0..copy_len]);
            pos += copy_len;
        }
        // Copy splatted pattern
        const pattern = data[data.len - 1];
        if (pattern.len > 0) {
            for (0..splat) |_| {
                if (pos >= pt_len) break;
                const copy_len = @min(pattern.len, pt_len - pos);
                @memcpy(plaintext[pos..][0..copy_len], pattern[0..copy_len]);
                pos += copy_len;
            }
        }

        // Append content type byte (application_data = 23)
        plaintext[pos] = @intFromEnum(tls.ContentType.application_data);
        const inner_len = pos + 1;

        // Build nonce
        var nonce: [Aes128Gcm.nonce_length]u8 = self.server_iv;
        const seq_bytes = mem.toBytes(mem.nativeTo(u64, self.write_seq, .big));
        const nonce_offset = Aes128Gcm.nonce_length - 8;
        for (0..8) |i| {
            nonce[nonce_offset + i] ^= seq_bytes[i];
        }
        self.write_seq += 1;

        // Record header
        const encrypted_len: u16 = @intCast(inner_len + Aes128Gcm.tag_length);
        var record_header: [tls.record_header_len]u8 = undefined;
        record_header[0] = @intFromEnum(tls.ContentType.application_data);
        mem.writeInt(u16, record_header[1..3], @intFromEnum(tls.ProtocolVersion.tls_1_2), .big);
        mem.writeInt(u16, record_header[3..5], encrypted_len, .big);

        // Encrypt
        var ciphertext: [tls.max_ciphertext_inner_record_len + 1]u8 = undefined;
        var tag: [Aes128Gcm.tag_length]u8 = undefined;
        Aes128Gcm.encrypt(
            ciphertext[0..inner_len],
            &tag,
            plaintext[0..inner_len],
            &record_header,
            nonce,
            self.server_key,
        );

        // Write record header + ciphertext + tag to raw socket
        self.raw_writer.writeAll(&record_header) catch return error.WriteFailed;
        self.raw_writer.writeAll(ciphertext[0..inner_len]) catch return error.WriteFailed;
        self.raw_writer.writeAll(&tag) catch return error.WriteFailed;
        self.raw_writer.flush() catch return error.WriteFailed;

        // Mark buffer as consumed
        io_w.end = 0;

        // Return how many bytes from data were consumed (excluding buffer)
        return Io.Writer.countSplat(data, splat);
    }

    fn tlsWriterFlush(io_w: *Io.Writer) Io.Writer.Error!void {
        if (io_w.end == 0) return;
        // Drain the remaining buffered data
        _ = try tlsWriterDrain(io_w, &.{""}, 1);
    }

    const reader_vtable: Io.Reader.VTable = .{
        .stream = tlsReaderStream,
    };

    const writer_vtable: Io.Writer.VTable = .{
        .drain = tlsWriterDrain,
        .flush = tlsWriterFlush,
    };
};

// ===========================================================================
// Handshake helpers
// ===========================================================================

const hkdfExpandLabel = tls.hkdfExpandLabel;

fn emptyHash() [Sha256.digest_length]u8 {
    return tls.emptyHash(Sha256);
}

/// Build a TLS record: header(5) + payload
fn writeRecord(
    writer: *Io.Writer,
    content_type: tls.ContentType,
    payload: []const u8,
) !void {
    var header: [tls.record_header_len]u8 = undefined;
    header[0] = @intFromEnum(content_type);
    mem.writeInt(u16, header[1..3], @intFromEnum(tls.ProtocolVersion.tls_1_2), .big);
    mem.writeInt(u16, header[3..5], @as(u16, @intCast(payload.len)), .big);
    try writer.writeAll(&header);
    try writer.writeAll(payload);
    try writer.flush();
}

/// Encrypt a handshake message and write it as an application_data record.
fn writeEncryptedRecord(
    writer: *Io.Writer,
    plaintext: []const u8,
    inner_content_type: tls.ContentType,
    key: [Aes128Gcm.key_length]u8,
    iv: [Aes128Gcm.nonce_length]u8,
    seq: *u64,
) !void {
    // inner plaintext = plaintext + content_type byte
    var inner: [tls.max_ciphertext_inner_record_len]u8 = undefined;
    @memcpy(inner[0..plaintext.len], plaintext);
    inner[plaintext.len] = @intFromEnum(inner_content_type);
    const inner_len = plaintext.len + 1;

    // Build nonce
    var nonce: [Aes128Gcm.nonce_length]u8 = iv;
    const seq_bytes = mem.toBytes(mem.nativeTo(u64, seq.*, .big));
    for (0..8) |i| {
        nonce[Aes128Gcm.nonce_length - 8 + i] ^= seq_bytes[i];
    }

    // Record header (needed as AAD)
    const encrypted_len: u16 = @intCast(inner_len + Aes128Gcm.tag_length);
    var record_header: [tls.record_header_len]u8 = undefined;
    record_header[0] = @intFromEnum(tls.ContentType.application_data);
    mem.writeInt(u16, record_header[1..3], @intFromEnum(tls.ProtocolVersion.tls_1_2), .big);
    mem.writeInt(u16, record_header[3..5], encrypted_len, .big);

    var ciphertext: [tls.max_ciphertext_inner_record_len + 1]u8 = undefined;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(ciphertext[0..inner_len], &tag, inner[0..inner_len], &record_header, nonce, key);

    try writer.writeAll(&record_header);
    try writer.writeAll(ciphertext[0..inner_len]);
    try writer.writeAll(&tag);
    try writer.flush();
    seq.* += 1;
}

/// Read + decrypt a TLS record. Returns the inner content type and plaintext length.
fn readEncryptedRecord(
    reader_io: *Io.Reader,
    key: [Aes128Gcm.key_length]u8,
    iv: [Aes128Gcm.nonce_length]u8,
    seq: *u64,
    out: []u8,
) !struct { content_type: tls.ContentType, len: usize } {
    const header = try reader_io.peek(tls.record_header_len);
    const record_len = @as(u16, header[3]) << 8 | header[4];
    reader_io.toss(tls.record_header_len);

    if (record_len > tls.max_ciphertext_len or record_len < Aes128Gcm.tag_length + 1)
        return error.ReadFailed;

    const record_data = try reader_io.take(record_len);
    const ct_len = record_len - Aes128Gcm.tag_length;
    const ciphertext = record_data[0..ct_len];
    const auth_tag = record_data[ct_len..][0..Aes128Gcm.tag_length].*;

    var nonce: [Aes128Gcm.nonce_length]u8 = iv;
    const seq_bytes = mem.toBytes(mem.nativeTo(u64, seq.*, .big));
    for (0..8) |i| {
        nonce[Aes128Gcm.nonce_length - 8 + i] ^= seq_bytes[i];
    }
    seq.* += 1;

    Aes128Gcm.decrypt(out[0..ct_len], ciphertext, auth_tag, header[0..tls.record_header_len], nonce, key) catch
        return error.ReadFailed;

    // Strip trailing zeros and content type byte
    var pt_len = ct_len;
    while (pt_len > 0 and out[pt_len - 1] == 0) pt_len -= 1;
    if (pt_len == 0) return error.ReadFailed;
    pt_len -= 1;
    const ct: tls.ContentType = @enumFromInt(out[pt_len]);
    return .{ .content_type = ct, .len = pt_len };
}

// ===========================================================================
// TlsContext.accept() — TLS 1.3 server handshake
// ===========================================================================

pub const AcceptError = error{
    ReadFailed,
    WriteFailed,
    EndOfStream,
    HandshakeFailed,
    UnsupportedClient,
};

/// Extension to TlsContext: perform a TLS 1.3 handshake on an accepted connection.
/// `io_buf` provides backing storage for the returned TlsServerStream's
/// Io.Writer buffer. Must be >= 16 KB; the first 16 KB is used for the writer.
pub fn accept(
    ctx: *const TlsContext,
    raw_reader: *Io.Reader,
    raw_writer: *Io.Writer,
    io_buf: []u8,
) AcceptError!TlsServerStream {
    if (io_buf.len < 32 * 1024) return error.HandshakeFailed;

    // ----- Step 1: Read ClientHello -----
    const ch_header = raw_reader.peek(tls.record_header_len) catch return error.ReadFailed;
    if (ch_header[0] != @intFromEnum(tls.ContentType.handshake)) return error.HandshakeFailed;
    const ch_record_len = @as(u16, ch_header[3]) << 8 | ch_header[4];
    raw_reader.toss(tls.record_header_len);

    const ch_data = raw_reader.take(ch_record_len) catch return error.ReadFailed;

    // Parse ClientHello handshake message
    if (ch_data.len < 4) return error.HandshakeFailed;
    if (ch_data[0] != @intFromEnum(tls.HandshakeType.client_hello)) return error.HandshakeFailed;
    const ch_msg_len = @as(u24, ch_data[1]) << 16 | @as(u24, ch_data[2]) << 8 | ch_data[3];
    if (ch_msg_len + 4 > ch_data.len) return error.HandshakeFailed;
    const ch_body = ch_data[4 .. 4 + ch_msg_len];

    // ClientHello body: version(2) + random(32) + session_id_len(1) + session_id + ...
    if (ch_body.len < 35) return error.HandshakeFailed;
    const session_id_len = ch_body[34];
    var pos: usize = 35 + session_id_len;
    if (pos + 2 > ch_body.len) return error.HandshakeFailed;

    // Skip cipher suites — we only offer AES_128_GCM_SHA256
    const cs_len = @as(u16, ch_body[pos]) << 8 | ch_body[pos + 1];
    pos += 2 + cs_len;

    // Skip compression methods
    if (pos >= ch_body.len) return error.HandshakeFailed;
    const comp_len = ch_body[pos];
    pos += 1 + comp_len;

    // Parse extensions to find key_share (X25519) and supported_versions (TLS 1.3)
    if (pos + 2 > ch_body.len) return error.HandshakeFailed;
    const ext_len = @as(u16, ch_body[pos]) << 8 | ch_body[pos + 1];
    pos += 2;
    const ext_end = pos + ext_len;
    if (ext_end > ch_body.len) return error.HandshakeFailed;

    var client_x25519_key: ?[32]u8 = null;
    var supports_tls13 = false;

    while (pos + 4 <= ext_end) {
        const ext_type = @as(u16, ch_body[pos]) << 8 | ch_body[pos + 1];
        const ext_data_len = @as(u16, ch_body[pos + 2]) << 8 | ch_body[pos + 3];
        pos += 4;
        const ext_data_end = pos + ext_data_len;
        if (ext_data_end > ext_end) break;

        if (ext_type == @intFromEnum(tls.ExtensionType.supported_versions)) {
            // List of versions: length(1) + versions(2 each)
            if (ext_data_len >= 3) {
                const ver_list_len = ch_body[pos];
                var vpos: usize = pos + 1;
                const vend = vpos + ver_list_len;
                while (vpos + 2 <= vend) {
                    const ver = @as(u16, ch_body[vpos]) << 8 | ch_body[vpos + 1];
                    if (ver == @intFromEnum(tls.ProtocolVersion.tls_1_3)) {
                        supports_tls13 = true;
                    }
                    vpos += 2;
                }
            }
        } else if (ext_type == @intFromEnum(tls.ExtensionType.key_share)) {
            // key_share_client: list_len(2) + entries
            if (ext_data_len >= 2) {
                const ks_list_len = @as(u16, ch_body[pos]) << 8 | ch_body[pos + 1];
                var kpos: usize = pos + 2;
                const kend = kpos + ks_list_len;
                while (kpos + 4 <= kend) {
                    const group = @as(u16, ch_body[kpos]) << 8 | ch_body[kpos + 1];
                    const key_len = @as(u16, ch_body[kpos + 2]) << 8 | ch_body[kpos + 3];
                    kpos += 4;
                    if (group == @intFromEnum(tls.NamedGroup.x25519) and key_len == 32 and kpos + 32 <= kend) {
                        client_x25519_key = ch_body[kpos..][0..32].*;
                    }
                    kpos += key_len;
                }
            }
        }
        pos = ext_data_end;
    }

    if (!supports_tls13 or client_x25519_key == null) return error.UnsupportedClient;

    // ----- Step 2: Generate server key pair & compute shared secret -----
    var server_privkey: [32]u8 = undefined;
    crypto.random.bytes(&server_privkey);
    const server_kp = crypto.dh.X25519.recoverPublicKey(server_privkey) catch return error.HandshakeFailed;
    const shared_secret = crypto.dh.X25519.scalarmult(server_privkey, client_x25519_key.?) catch return error.HandshakeFailed;

    // ----- Step 3: Transcript hash -----
    var transcript = Sha256.init(.{});
    // Hash the full ClientHello handshake message (type + length + body)
    transcript.update(ch_data[0 .. 4 + ch_msg_len]);

    // ----- Step 4: Build & send ServerHello -----
    var server_random: [32]u8 = undefined;
    crypto.random.bytes(&server_random);
    const session_id = ch_body[35 .. 35 + session_id_len];

    // ServerHello body
    var sh_body: [512]u8 = undefined;
    var sh_pos: usize = 0;

    // legacy_version = TLS 1.2
    mem.writeInt(u16, sh_body[0..2], @intFromEnum(tls.ProtocolVersion.tls_1_2), .big);
    sh_pos = 2;
    @memcpy(sh_body[sh_pos..][0..32], &server_random);
    sh_pos += 32;
    sh_body[sh_pos] = session_id_len;
    sh_pos += 1;
    @memcpy(sh_body[sh_pos..][0..session_id_len], session_id);
    sh_pos += session_id_len;
    // cipher_suite = AES_128_GCM_SHA256
    mem.writeInt(u16, sh_body[sh_pos..][0..2], @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256), .big);
    sh_pos += 2;
    sh_body[sh_pos] = 0; // legacy_compression_method
    sh_pos += 1;

    // Extensions
    const ext_start_pos = sh_pos;
    sh_pos += 2; // placeholder for extensions length

    // supported_versions extension (type=43, len=2, value=0x0304)
    mem.writeInt(u16, sh_body[sh_pos..][0..2], @intFromEnum(tls.ExtensionType.supported_versions), .big);
    sh_pos += 2;
    mem.writeInt(u16, sh_body[sh_pos..][0..2], 2, .big); // extension data length
    sh_pos += 2;
    mem.writeInt(u16, sh_body[sh_pos..][0..2], @intFromEnum(tls.ProtocolVersion.tls_1_3), .big);
    sh_pos += 2;

    // key_share extension (type=51, len=36, group=x25519, key_len=32, key)
    mem.writeInt(u16, sh_body[sh_pos..][0..2], @intFromEnum(tls.ExtensionType.key_share), .big);
    sh_pos += 2;
    mem.writeInt(u16, sh_body[sh_pos..][0..2], 36, .big); // extension data length
    sh_pos += 2;
    mem.writeInt(u16, sh_body[sh_pos..][0..2], @intFromEnum(tls.NamedGroup.x25519), .big);
    sh_pos += 2;
    mem.writeInt(u16, sh_body[sh_pos..][0..2], 32, .big); // key length
    sh_pos += 2;
    @memcpy(sh_body[sh_pos..][0..32], &server_kp);
    sh_pos += 32;

    // Fill extensions length
    const extensions_len: u16 = @intCast(sh_pos - ext_start_pos - 2);
    mem.writeInt(u16, sh_body[ext_start_pos..][0..2], extensions_len, .big);

    // Wrap in handshake message: type(1) + length(3) + body
    var sh_msg: [4 + 512]u8 = undefined;
    sh_msg[0] = @intFromEnum(tls.HandshakeType.server_hello);
    sh_msg[1] = 0;
    mem.writeInt(u16, sh_msg[2..4], @intCast(sh_pos), .big);
    @memcpy(sh_msg[4..][0..sh_pos], sh_body[0..sh_pos]);
    const sh_msg_len = 4 + sh_pos;

    // Write ServerHello as cleartext handshake record
    writeRecord(raw_writer, .handshake, sh_msg[0..sh_msg_len]) catch return error.WriteFailed;

    // Update transcript with ServerHello
    transcript.update(sh_msg[0..sh_msg_len]);

    // Send ChangeCipherSpec (compatibility)
    writeRecord(raw_writer, .change_cipher_spec, &.{1}) catch return error.WriteFailed;

    // ----- Step 5: Key derivation -----
    const hello_hash = transcript.peek();
    const zeroes = [1]u8{0} ** Sha256.digest_length;
    const early_secret = Hkdf.extract(&[1]u8{0}, &zeroes);
    const empty_hash = emptyHash();
    const hs_derived = hkdfExpandLabel(Hkdf, early_secret, "derived", &empty_hash, Sha256.digest_length);
    const handshake_secret = Hkdf.extract(&hs_derived, &shared_secret);

    const server_hs_secret = hkdfExpandLabel(Hkdf, handshake_secret, "s hs traffic", &hello_hash, Sha256.digest_length);
    const client_hs_secret = hkdfExpandLabel(Hkdf, handshake_secret, "c hs traffic", &hello_hash, Sha256.digest_length);

    const server_hs_key = hkdfExpandLabel(Hkdf, server_hs_secret, "key", "", Aes128Gcm.key_length);
    const server_hs_iv = hkdfExpandLabel(Hkdf, server_hs_secret, "iv", "", Aes128Gcm.nonce_length);
    const client_hs_key = hkdfExpandLabel(Hkdf, client_hs_secret, "key", "", Aes128Gcm.key_length);
    const client_hs_iv = hkdfExpandLabel(Hkdf, client_hs_secret, "iv", "", Aes128Gcm.nonce_length);

    const server_finished_key = hkdfExpandLabel(Hkdf, server_hs_secret, "finished", "", Hmac.key_length);
    const client_finished_key = hkdfExpandLabel(Hkdf, client_hs_secret, "finished", "", Hmac.key_length);

    var server_write_seq: u64 = 0;

    // ----- Step 6: Send EncryptedExtensions (empty) -----
    const ee_msg = [_]u8{
        @intFromEnum(tls.HandshakeType.encrypted_extensions),
        0, 0, 2, // length = 2
        0, 0, // extensions length = 0
    };
    writeEncryptedRecord(raw_writer, &ee_msg, .handshake, server_hs_key, server_hs_iv, &server_write_seq) catch
        return error.WriteFailed;
    transcript.update(&ee_msg);

    // ----- Step 7: Send Certificate -----
    // Build Certificate handshake message
    var cert_msg: [4 + 1 + 3 + max_cert_der_len + 2]u8 = undefined;
    const cert_der = ctx.cert_der;
    const cert_body_len: u24 = @intCast(1 + 3 + 3 + cert_der.len + 2);
    cert_msg[0] = @intFromEnum(tls.HandshakeType.certificate);
    cert_msg[1] = @intCast(cert_body_len >> 16);
    cert_msg[2] = @intCast((cert_body_len >> 8) & 0xFF);
    cert_msg[3] = @intCast(cert_body_len & 0xFF);
    cert_msg[4] = 0; // certificate_request_context length = 0
    // certificate_list length (3 bytes)
    const cert_list_len: u24 = @intCast(3 + cert_der.len + 2);
    cert_msg[5] = @intCast(cert_list_len >> 16);
    cert_msg[6] = @intCast((cert_list_len >> 8) & 0xFF);
    cert_msg[7] = @intCast(cert_list_len & 0xFF);
    // cert_data length (3 bytes)
    const cert_data_len: u24 = @intCast(cert_der.len);
    cert_msg[8] = @intCast(cert_data_len >> 16);
    cert_msg[9] = @intCast((cert_data_len >> 8) & 0xFF);
    cert_msg[10] = @intCast(cert_data_len & 0xFF);
    @memcpy(cert_msg[11..][0..cert_der.len], cert_der);
    const cert_ext_pos = 11 + cert_der.len;
    cert_msg[cert_ext_pos] = 0; // extensions length = 0
    cert_msg[cert_ext_pos + 1] = 0;
    const cert_msg_len = cert_ext_pos + 2;

    writeEncryptedRecord(raw_writer, cert_msg[0..cert_msg_len], .handshake, server_hs_key, server_hs_iv, &server_write_seq) catch
        return error.WriteFailed;
    transcript.update(cert_msg[0..cert_msg_len]);

    // ----- Step 8: Send CertificateVerify -----
    const cv_transcript_hash = transcript.peek();
    // Construct the content to sign: 64 spaces + "TLS 1.3, server CertificateVerify\x00" + hash
    var sign_content: [64 + 33 + 1 + Sha256.digest_length]u8 = undefined;
    @memset(sign_content[0..64], ' ');
    const cv_label = "TLS 1.3, server CertificateVerify";
    @memcpy(sign_content[64..][0..cv_label.len], cv_label);
    sign_content[64 + cv_label.len] = 0;
    @memcpy(sign_content[64 + cv_label.len + 1 ..][0..Sha256.digest_length], &cv_transcript_hash);

    // Sign the transcript and build CertificateVerify message
    const cv_result: struct { scheme: u16, sig_bytes: [128]u8, sig_len: u16 } = switch (ctx.private_key) {
        .ec_p256 => |secret_bytes| blk: {
            const EcdsaP256 = crypto.sign.ecdsa.EcdsaP256Sha256;
            const sk = EcdsaP256.SecretKey.fromBytes(secret_bytes) catch return error.HandshakeFailed;
            const kp = EcdsaP256.KeyPair.fromSecretKey(sk) catch return error.HandshakeFailed;
            const sig = kp.sign(&sign_content, null) catch return error.HandshakeFailed;
            const raw = sig.toBytes();
            var buf: [128]u8 = undefined;
            @memcpy(buf[0..raw.len], &raw);
            break :blk .{
                .scheme = @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256),
                .sig_bytes = buf,
                .sig_len = raw.len,
            };
        },
        .ed25519 => |secret_bytes| blk: {
            const kp = crypto.sign.Ed25519.KeyPair.generateDeterministic(
                secret_bytes,
            ) catch return error.HandshakeFailed;
            const sig = kp.sign(&sign_content, null) catch return error.HandshakeFailed;
            const raw = sig.toBytes();
            var buf: [128]u8 = undefined;
            @memcpy(buf[0..raw.len], &raw);
            break :blk .{
                .scheme = @intFromEnum(tls.SignatureScheme.ed25519),
                .sig_bytes = buf,
                .sig_len = raw.len,
            };
        },
    };

    var cv_msg: [4 + 2 + 2 + 128]u8 = undefined;
    cv_msg[0] = @intFromEnum(tls.HandshakeType.certificate_verify);
    const cv_body_len: u16 = 2 + 2 + cv_result.sig_len;
    cv_msg[1] = 0;
    mem.writeInt(u16, cv_msg[2..4], cv_body_len, .big);
    mem.writeInt(u16, cv_msg[4..6], cv_result.scheme, .big);
    mem.writeInt(u16, cv_msg[6..8], cv_result.sig_len, .big);
    @memcpy(cv_msg[8..][0..cv_result.sig_len], cv_result.sig_bytes[0..cv_result.sig_len]);
    const cv_msg_len = 8 + cv_result.sig_len;

    writeEncryptedRecord(raw_writer, cv_msg[0..cv_msg_len], .handshake, server_hs_key, server_hs_iv, &server_write_seq) catch
        return error.WriteFailed;
    transcript.update(cv_msg[0..cv_msg_len]);

    // ----- Step 9: Send server Finished -----
    const finished_hash = transcript.peek();
    var verify_data: [Sha256.digest_length]u8 = undefined;
    Hmac.create(&verify_data, &finished_hash, &server_finished_key);

    var fin_msg: [4 + Sha256.digest_length]u8 = undefined;
    fin_msg[0] = @intFromEnum(tls.HandshakeType.finished);
    fin_msg[1] = 0;
    mem.writeInt(u16, fin_msg[2..4], Sha256.digest_length, .big);
    @memcpy(fin_msg[4..][0..Sha256.digest_length], &verify_data);

    writeEncryptedRecord(raw_writer, &fin_msg, .handshake, server_hs_key, server_hs_iv, &server_write_seq) catch
        return error.WriteFailed;
    transcript.update(&fin_msg);

    // ----- Step 10: Derive application traffic keys -----
    const ap_derived = hkdfExpandLabel(Hkdf, handshake_secret, "derived", &empty_hash, Sha256.digest_length);
    const master_secret = Hkdf.extract(&ap_derived, &zeroes);

    const server_hs_hash = transcript.peek();
    const server_app_secret = hkdfExpandLabel(Hkdf, master_secret, "s ap traffic", &server_hs_hash, Sha256.digest_length);
    const client_app_secret = hkdfExpandLabel(Hkdf, master_secret, "c ap traffic", &server_hs_hash, Sha256.digest_length);

    const server_app_key = hkdfExpandLabel(Hkdf, server_app_secret, "key", "", Aes128Gcm.key_length);
    const server_app_iv = hkdfExpandLabel(Hkdf, server_app_secret, "iv", "", Aes128Gcm.nonce_length);
    const client_app_key = hkdfExpandLabel(Hkdf, client_app_secret, "key", "", Aes128Gcm.key_length);
    const client_app_iv = hkdfExpandLabel(Hkdf, client_app_secret, "iv", "", Aes128Gcm.nonce_length);

    // ----- Step 11: Skip CCS from client (if any) + Read client Finished -----
    // Some clients send a ChangeCipherSpec before Finished
    var client_read_seq: u64 = 0;
    var client_finished_buf: [tls.max_ciphertext_inner_record_len]u8 = undefined;

    // Peek at next record — could be CCS or encrypted
    const next_header = raw_reader.peek(tls.record_header_len) catch return error.ReadFailed;
    if (next_header[0] == @intFromEnum(tls.ContentType.change_cipher_spec)) {
        // Skip the CCS record
        const ccs_len = @as(u16, next_header[3]) << 8 | next_header[4];
        raw_reader.toss(tls.record_header_len);
        _ = raw_reader.take(ccs_len) catch return error.ReadFailed;
    }

    // Read client Finished (encrypted with handshake keys)
    const client_fin = readEncryptedRecord(
        raw_reader,
        client_hs_key,
        client_hs_iv,
        &client_read_seq,
        &client_finished_buf,
    ) catch return error.HandshakeFailed;

    if (client_fin.content_type != .handshake) return error.HandshakeFailed;
    if (client_fin.len < 4) return error.HandshakeFailed;
    if (client_finished_buf[0] != @intFromEnum(tls.HandshakeType.finished)) return error.HandshakeFailed;

    // Verify client Finished
    const client_verify_hash = transcript.peek();
    var expected_client_verify: [Sha256.digest_length]u8 = undefined;
    Hmac.create(&expected_client_verify, &client_verify_hash, &client_finished_key);

    if (!mem.eql(u8, client_finished_buf[4..][0..Sha256.digest_length], &expected_client_verify))
        return error.HandshakeFailed;

    // ----- Step 12: Return TlsServerStream with application keys -----
    // Wire the caller-provided io_buf as the Io.Writer buffer so the
    // writer vtable has valid memory for buffered writes.
    return TlsServerStream{
        .reader_state = .{
            .vtable = &TlsServerStream.reader_vtable,
            .buffer = io_buf[0 .. 16 * 1024],
            .seek = 0,
            .end = 0,
        },
        .writer_state = .{
            .vtable = &TlsServerStream.writer_vtable,
            .buffer = io_buf[16 * 1024 .. 32 * 1024],
            .end = 0,
        },
        .raw_reader = raw_reader,
        .raw_writer = raw_writer,
        .client_key = client_app_key,
        .server_key = server_app_key,
        .client_iv = client_app_iv,
        .server_iv = server_app_iv,
        .read_seq = 0,
        .write_seq = 0,
        .plaintext_buf = undefined,
        .plaintext_start = 0,
        .plaintext_end = 0,
    };
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
