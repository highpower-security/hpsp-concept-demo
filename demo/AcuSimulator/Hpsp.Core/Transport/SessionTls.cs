// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Transport/SessionTls.cs
//  Purpose: The operational TLS 1.3 session between a reader and the ACU
//           (specification sections 4 "Transport" and 5.3 "Cryptographic profile").
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  Once a reader has been paired it has a site certificate. From then on it
//  "phones home": it opens a TCP connection to the ACU on port 7500 and runs
//  TLS 1.3, the same protection used by banking websites. Both sides show a
//  certificate (mutual authentication) and both check that the other's
//  certificate was issued by THIS site's root, never by anyone else.
//
//  This file uses .NET's SslStream, which on Windows is Windows' own TLS
//  (SChannel) and on Linux is OpenSSL. BouncyCastle is NOT used here. The
//  BouncyCastle folder has the other engine for sessions (for Windows 10,
//  whose SChannel has no TLS 1.3) and the pairing connection.
//
//  Settings, from the specification:
//    - TLS 1.3 only.
//    - Application protocol (ALPN) "hpsp/1".
//    - ECDSA P-256 certificates on both sides.
//    - No session resumption (each connection does a full handshake).
//  Windows does not let an application pick the exact TLS 1.3 cipher, so the
//  connection may use AES-256-GCM instead of AES-128-GCM. Both are allowed.
// =============================================================================

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Hpsp.Core.Security;

namespace Hpsp.Core.Transport;

/// <summary>Facts about an established session, for the activity window.</summary>
/// <remarks>
/// <paramref name="KeyExchange"/> is the TLS key-exchange group, for example
/// "SecP256r1MLKEM768 (hybrid post-quantum)". It is null when the TLS engine does not report it:
/// .NET's SslStream (the Windows engine) has no way to ask which group Windows chose.
/// </remarks>
public sealed record TlsInfo(string Protocol, string Cipher, string Alpn, string PeerSubject, string PeerFingerprint, Guid? PeerDeviceId, string? KeyExchange = null)
{
    public override string ToString() => $"{Protocol}, {Cipher}, key exchange {KeyExchange ?? "not reported by this TLS engine"}, ALPN {Alpn}, peer \"{PeerSubject}\" ({PeerFingerprint})";
}

public static class SessionTls
{
    public static readonly SslApplicationProtocol Alpn = new("hpsp/1");
    public const int Port = 7500;

    // -------------------------------------------------------------------------
    //  ACU side (TLS server)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Accept TLS on a connection a reader opened. The reader MUST present a site
    /// certificate issued by <paramref name="siteRoot"/> with the client-auth purpose
    /// and a device UUID. Throws <see cref="AuthenticationException"/> otherwise.
    /// </summary>
    public static async Task<(SslStream Stream, TlsInfo Info)> AcceptAsync(
        TcpClient tcp, X509Certificate2 acuCertWithKey, X509Certificate2 siteRoot, CancellationToken ct)
    {
        string? reason = null;
        var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        var opts = new SslServerAuthenticationOptions
        {
            ServerCertificate = DemoPki.ForTls(acuCertWithKey),
            ClientCertificateRequired = true,
            EnabledSslProtocols = SslProtocols.Tls13,
            ApplicationProtocols = new List<SslApplicationProtocol> { Alpn },
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            AllowTlsResume = false,
            RemoteCertificateValidationCallback = (_, cert, _, _) =>
            {
                // We ignore the operating system's opinion and apply HPSP's rules ourselves.
                if (cert is null) { reason = "reader sent no certificate"; return false; }
                var c = new X509Certificate2(cert);
                reason = DemoPki.CheckChain(c, siteRoot, DemoPki.ClientAuth);
                if (reason is null && DemoPki.DeviceIdOf(c) is null) reason = "certificate has no device UUID";
                return reason is null;
            },
        };
        try { await ssl.AuthenticateAsServerAsync(opts, ct).ConfigureAwait(false); }
        catch (Exception e) { ssl.Dispose(); throw new AuthenticationException("TLS handshake failed: " + (reason ?? DemoPki.Explain(e)), e); }
        return (ssl, Describe(ssl));
    }

    // -------------------------------------------------------------------------
    //  Reader side (TLS client)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Connect to the ACU. The ACU MUST present a certificate issued by the site
    /// root with the server-auth purpose and naming the host we dialled.
    /// </summary>
    public static async Task<(SslStream Stream, TlsInfo Info)> ConnectAsync(
        string host, int port, X509Certificate2 readerCertWithKey, X509Certificate2 siteRoot, CancellationToken ct)
    {
        var tcp = new TcpClient { NoDelay = true };
        try { await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false); }
        catch { tcp.Dispose(); throw; }

        string? reason = null;
        var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        var opts = new SslClientAuthenticationOptions
        {
            TargetHost = host,
            ClientCertificates = new X509CertificateCollection { DemoPki.ForTls(readerCertWithKey) },
            EnabledSslProtocols = SslProtocols.Tls13,
            ApplicationProtocols = new List<SslApplicationProtocol> { Alpn },
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            AllowTlsResume = false,
            // Always offer our certificate; the ACU requires it.
            LocalCertificateSelectionCallback = (_, _, local, _, _) => local[0],
            RemoteCertificateValidationCallback = (_, cert, _, errors) =>
            {
                if (cert is null) { reason = "ACU sent no certificate"; return false; }
                var c = new X509Certificate2(cert);
                reason = DemoPki.CheckChain(c, siteRoot, DemoPki.ServerAuth);
                // The name in the ACU certificate must match the endpoint we were told to use.
                if (reason is null && errors.HasFlag(System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch))
                    reason = $"ACU certificate does not name \"{host}\"";
                return reason is null;
            },
        };
        try { await ssl.AuthenticateAsClientAsync(opts, ct).ConfigureAwait(false); }
        catch (Exception e) { ssl.Dispose(); tcp.Dispose(); throw new AuthenticationException("TLS handshake failed: " + (reason ?? DemoPki.Explain(e)), e); }
        return (ssl, Describe(ssl));
    }

    private static TlsInfo Describe(SslStream s)
    {
        var peer = s.RemoteCertificate is null ? null : new X509Certificate2(s.RemoteCertificate);
        string cipher;
        try { cipher = s.NegotiatedCipherSuite.ToString(); } catch { cipher = "unknown"; }
        return new TlsInfo(
            s.SslProtocol == SslProtocols.Tls13 ? "TLS 1.3" : s.SslProtocol.ToString(),
            cipher,
            s.NegotiatedApplicationProtocol.ToString(),
            peer?.Subject ?? "(none)",
            peer is null ? "-" : DemoPki.Fingerprint(peer),
            peer is null ? null : DemoPki.DeviceIdOf(peer));
    }
}

/// <summary>
/// An SslStream that ends the TLS session properly when it is closed: it sends TLS's
/// close_notify first, which SslStream does not do by itself. The other side can then
/// tell a normal close from a connection that was cut off (BouncyCastle reports the
/// latter as "truncated").
/// </summary>
public sealed class ClosingSslStream : Stream
{
    private readonly SslStream _s;
    private int _closed;
    public ClosingSslStream(SslStream s) => _s = s;

    public override bool CanRead => true; public override bool CanWrite => true; public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => _s.Read(buffer, offset, count);
    public override void Write(byte[] buffer, int offset, int count) => _s.Write(buffer, offset, count);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => _s.ReadAsync(buffer, offset, count, ct);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => _s.ReadAsync(buffer, ct);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => _s.WriteAsync(buffer, offset, count, ct);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => _s.WriteAsync(buffer, ct);
    public override void Flush() => _s.Flush();
    public override Task FlushAsync(CancellationToken ct) => _s.FlushAsync(ct);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _closed, 1) == 0)
        {
            // Send close_notify, but never wait long for it (the peer may have gone).
            try { _s.ShutdownAsync().Wait(500); } catch { }
            _s.Dispose();
        }
        base.Dispose(disposing);
    }
}
