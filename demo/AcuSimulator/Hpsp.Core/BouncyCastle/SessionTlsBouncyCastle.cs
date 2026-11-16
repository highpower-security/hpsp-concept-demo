// #############################################################################
// #                                                                           #
// #   BOUNCYCASTLE CODE - START                                               #
// #                                                                           #
// #   This file uses the BouncyCastle TLS library (MIT licence,               #
// #   https://www.bouncycastle.org/csharp/) to run the normal reader-to-ACU   #
// #   session with certificates. It is the "BouncyCastle" choice of the       #
// #   TLS engine setting, for Windows 10 (whose own TLS has no TLS 1.3) and   #
// #   to show that two different TLS implementations interoperate.           #
// #                                                                           #
// #   The other choice, "Windows", is Transport/SessionTls.cs, which uses     #
// #   .NET's SslStream and no BouncyCastle code at all.                       #
// #                                                                           #
// #############################################################################
//
//  HPSP Demo  -  Hpsp.Core
//  File:    BouncyCastle/SessionTlsBouncyCastle.cs
//  Purpose: The operational TLS 1.3 session, with mutual certificate
//           authentication, implemented with BouncyCastle.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
//
//  IN PLAIN TERMS
//  --------------
//  Exactly the same job as Transport/SessionTls.cs: both sides show a
//  certificate from the site root, and both check the other's. Both engines
//  speak standard TLS 1.3, so they interoperate: a reader using one engine can
//  talk to an ACU using the other. Certificate checks use the same DemoPki.CheckChain
//  rules as the Windows engine, so the security decisions are identical.
//
//  Settings: TLS 1.3 only; TLS_AES_128_GCM_SHA256 preferred, AES-256-GCM
//  accepted; P-256 key exchange; ECDSA P-256 signatures; ALPN "hpsp/1".
// =============================================================================

using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hpsp.Core.Security;
using Hpsp.Core.Transport;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcCertificate = Org.BouncyCastle.Tls.Certificate;
using BcCertificateRequest = Org.BouncyCastle.Tls.CertificateRequest;

namespace Hpsp.Core.BouncyCastle;

public static class SessionTlsBouncyCastle
{
    private static readonly ProtocolName Alpn = ProtocolName.AsUtf8Encoding("hpsp/1");
    private static readonly int[] Suites = { CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384 };

    /// <summary>ACU side: accept a reader's connection (TLS server).</summary>
    public static Task<(Stream Stream, TlsInfo Info)> AcceptAsync(TcpClient tcp, X509Certificate2 acuCertWithKey, X509Certificate2 siteRoot, CancellationToken ct)
        => Task.Run(() =>
        {
            var crypto = new BcTlsCrypto(new SecureRandom());
            var server = new HpspServer(crypto, acuCertWithKey, siteRoot);
            var proto = new TlsServerProtocol();          // non-blocking mode: see OwningStream
            using var cut = ct.Register(() => { try { tcp.Dispose(); } catch { } });   // timeout or cancel stops a waiting handshake
            try { proto.Accept(server); OwningStream.Handshake(proto, tcp.GetStream()); }
            catch (Exception e) { tcp.Dispose(); throw new System.Security.Authentication.AuthenticationException("TLS handshake failed: " + (server.Reason ?? DemoPki.Explain(e)), e); }
            return ((Stream)new OwningStream(proto, tcp), Describe(server.Ctx, server.PeerCert));
        }, ct);

    /// <summary>Reader side: connect to the ACU (TLS client).</summary>
    public static async Task<(Stream Stream, TlsInfo Info)> ConnectAsync(string host, int port, X509Certificate2 readerCertWithKey, X509Certificate2 siteRoot, CancellationToken ct)
    {
        var tcp = new TcpClient { NoDelay = true };
        try { await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false); }
        catch { tcp.Dispose(); throw; }
        return await Task.Run(() =>
        {
            var crypto = new BcTlsCrypto(new SecureRandom());
            var client = new HpspClient(crypto, readerCertWithKey, siteRoot, host);
            var proto = new TlsClientProtocol();          // non-blocking mode: see OwningStream
            using var cut = ct.Register(() => { try { tcp.Dispose(); } catch { } });
            try { proto.Connect(client); OwningStream.Handshake(proto, tcp.GetStream()); }
            catch (Exception e) { tcp.Dispose(); throw new System.Security.Authentication.AuthenticationException("TLS handshake failed: " + (client.Reason ?? DemoPki.Explain(e)), e); }
            return ((Stream)new OwningStream(proto, tcp), Describe(client.Ctx, client.PeerCert));
        }, ct).ConfigureAwait(false);
    }

    // ---- converting .NET certificates and keys into BouncyCastle form ----------

    private static BcCertificate ToBcChain(TlsCrypto crypto, X509Certificate2 cert) =>
        new(Array.Empty<byte>(), new[] { new CertificateEntry(crypto.CreateCertificate(cert.RawData), null) });

    private static ECPrivateKeyParameters ToBcKey(X509Certificate2 certWithKey)
    {
        using var k = certWithKey.GetECDsaPrivateKey() ?? throw new InvalidOperationException("certificate has no private key");
        var p = DemoPki.ExportPrivateParameters(k);    // works on Windows too (see there)
        var domain = new ECDomainParameters(ECNamedCurveTable.GetByName("P-256"));
        return new ECPrivateKeyParameters("EC", new BcBigInteger(1, p.D), domain);
    }

    private static TlsCredentialedSigner Signer(TlsContext ctx, BcTlsCrypto crypto, X509Certificate2 certWithKey, BcCertificate chain) =>
        new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(ctx), crypto, ToBcKey(certWithKey), chain,
            SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256));

    private static X509Certificate2? FirstCert(BcCertificate? c) =>
        c is null || c.IsEmpty ? null : new X509Certificate2(c.GetCertificateAt(0).GetEncoded());

    private static TlsInfo Describe(TlsContext ctx, X509Certificate2? peer)
    {
        var sp = ctx.SecurityParameters;
        string suite = sp.CipherSuite switch
        {
            CipherSuite.TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite.TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
            _ => "0x" + sp.CipherSuite.ToString("x4"),
        };
        return new TlsInfo("TLS 1.3", suite + " (BouncyCastle)", sp.ApplicationProtocol?.GetUtf8Decoding() ?? "",
            peer?.Subject ?? "(none)", peer is null ? "-" : DemoPki.Fingerprint(peer), peer is null ? null : DemoPki.DeviceIdOf(peer),
            PostQuantumGroups.Describe(sp.NegotiatedGroup));
    }

    private static IList<SignatureAndHashAlgorithm> EcdsaP256Only() =>
        new List<SignatureAndHashAlgorithm> { SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256) };

    // ---- server (ACU) -----------------------------------------------------------

    private sealed class HpspServer : AbstractTlsServer
    {
        private readonly BcTlsCrypto _crypto;
        private readonly X509Certificate2 _cert, _root;
        public string? Reason;
        public X509Certificate2? PeerCert;
        public HpspServer(BcTlsCrypto crypto, X509Certificate2 cert, X509Certificate2 root) : base(crypto) { _crypto = crypto; _cert = cert; _root = root; }
        public TlsContext Ctx => m_context;
        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.Only();
        protected override int[] GetSupportedCipherSuites() => Suites;
        // Hybrid post-quantum groups first, secp256r1 as the fallback (PostQuantumGroups.cs).
        public override int[] GetSupportedGroups() => PostQuantumGroups.Supported(_crypto);
        protected override IList<ProtocolName> GetProtocolNames() => new List<ProtocolName> { Alpn };
        public override TlsCredentials GetCredentials() => Signer(m_context, _crypto, _cert, ToBcChain(_crypto, _cert));

        // Ask the reader for its certificate: this is what makes the authentication mutual.
        public override BcCertificateRequest GetCertificateRequest() =>
            new(Array.Empty<byte>(), EcdsaP256Only(), null, null);

        // Record WHY an alert was raised (BouncyCastle turns any unexpected exception into
        // internal_error; this keeps the real reason for the activity window).
        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
        {
            if (Reason is null && alertLevel == AlertLevel.fatal)
                Reason = AlertDescription.GetText(alertDescription) + (cause is null ? (message is null ? "" : ": " + message) : ": " + DemoPki.Explain(cause));
        }
        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            if (Reason is null && alertLevel == AlertLevel.fatal) Reason = "the other side refused: " + AlertDescription.GetText(alertDescription);
        }

        public override void NotifyClientCertificate(BcCertificate clientCertificate)
        {
            PeerCert = FirstCert(clientCertificate);
            if (PeerCert is null) { Reason = "reader sent no certificate"; throw new TlsFatalAlert(AlertDescription.certificate_required); }
            Reason = DemoPki.CheckChain(PeerCert, _root, DemoPki.ClientAuth);
            if (Reason is null && DemoPki.DeviceIdOf(PeerCert) is null) Reason = "certificate has no device UUID";
            if (Reason is not null) throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }
    }

    // ---- client (reader) --------------------------------------------------------

    private sealed class HpspClient : AbstractTlsClient
    {
        private readonly BcTlsCrypto _crypto;
        private readonly X509Certificate2 _cert, _root;
        private readonly string _host;
        public string? Reason;
        public X509Certificate2? PeerCert;
        public HpspClient(BcTlsCrypto crypto, X509Certificate2 cert, X509Certificate2 root, string host) : base(crypto) { _crypto = crypto; _cert = cert; _root = root; _host = host; }
        public TlsContext Ctx => m_context;
        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.Only();
        protected override int[] GetSupportedCipherSuites() => Suites;
        // Hybrid post-quantum groups first, secp256r1 as the fallback (PostQuantumGroups.cs). The first
        // ClientHello already carries a hybrid key share, so a hybrid server needs no extra round trip.
        protected override IList<int> GetSupportedGroups(IList<int> namedGroupRoles) => PostQuantumGroups.Supported(_crypto).ToList();
        public override IList<int> GetEarlyKeyShareGroups() => new List<int> { PostQuantumGroups.Supported(_crypto)[0] };
        protected override IList<ProtocolName> GetProtocolNames() => new List<ProtocolName> { Alpn };
        protected override IList<SignatureAndHashAlgorithm> GetSupportedSignatureAlgorithms() => EcdsaP256Only();
        public override TlsAuthentication GetAuthentication() => new Auth(this);
        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
        {
            if (Reason is null && alertLevel == AlertLevel.fatal)
                Reason = AlertDescription.GetText(alertDescription) + (cause is null ? (message is null ? "" : ": " + message) : ": " + DemoPki.Explain(cause));
        }
        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            if (Reason is null && alertLevel == AlertLevel.fatal) Reason = "the other side refused: " + AlertDescription.GetText(alertDescription);
        }

        private sealed class Auth : TlsAuthentication
        {
            private readonly HpspClient _c;
            public Auth(HpspClient c) => _c = c;
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                _c.PeerCert = FirstCert(serverCertificate.Certificate);
                if (_c.PeerCert is null) { _c.Reason = "ACU sent no certificate"; throw new TlsFatalAlert(AlertDescription.certificate_required); }
                _c.Reason = DemoPki.CheckChain(_c.PeerCert, _c._root, DemoPki.ServerAuth);
                // The ACU certificate must name the host we dialled, as with the Windows engine.
                if (_c.Reason is null && !_c.PeerCert.MatchesHostname(_c._host, allowWildcards: false, allowCommonName: false))
                    _c.Reason = $"ACU certificate does not name \"{_c._host}\"";
                if (_c.Reason is not null) throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }
            public TlsCredentials GetClientCredentials(BcCertificateRequest certificateRequest) =>
                Signer(_c.m_context, _c._crypto, _c._cert, ToBcChain(_c._crypto, _c._cert));
        }
    }

    /// <summary>
    /// The TLS stream, which also closes the TCP connection when disposed.
    ///
    /// WHY "NON-BLOCKING" MODE: in its ordinary (blocking) mode, BouncyCastle keeps an
    /// internal lock while it waits for data to arrive. An HPSP session reads and writes
    /// at the same time (one task waits for the ACU's messages while another sends
    /// heartbeats and card events), so a write would wait for that lock until the other
    /// side happened to send something, and the session would freeze.
    /// In non-blocking mode BouncyCastle never touches the socket itself: we read bytes
    /// from TCP and hand them in (OfferInput), and we collect the bytes it wants sent
    /// (ReadOutput) and write them to TCP. Waiting for the network then happens outside
    /// any BouncyCastle lock.
    /// </summary>
    private sealed class OwningStream : Stream
    {
        private readonly TlsProtocol _p; private readonly TcpClient _tcp; private readonly NetworkStream _net;
        private readonly object _proto = new();      // guards every call into _p
        private readonly object _reading = new();    // one reader at a time
        private readonly byte[] _inBuf = new byte[16 * 1024 + 512];

        public OwningStream(TlsProtocol p, TcpClient tcp)
        {
            _p = p; _tcp = tcp; _net = tcp.GetStream();
            tcp.SendTimeout = 10_000;    // a peer that stops reading cannot block our writes for ever
        }

        /// <summary>Run the handshake: shuttle bytes between TCP and BouncyCastle until it is done.</summary>
        public static void Handshake(TlsProtocol p, NetworkStream net)
        {
            var buf = new byte[16 * 1024 + 512];
            Pump(p, net);
            while (p.IsHandshaking)
            {
                int n = net.Read(buf, 0, buf.Length);
                if (n <= 0) throw new IOException("connection closed during the TLS handshake");
                try { p.OfferInput(buf, 0, n); }
                finally { Pump(p, net); }   // send any alert or handshake reply
            }
        }

        /// <summary>Send whatever BouncyCastle has queued for the network.</summary>
        private static void Pump(TlsProtocol p, NetworkStream net)
        {
            int avail = p.GetAvailableOutputBytes();
            if (avail <= 0) return;
            var b = new byte[avail];
            int n = p.ReadOutput(b, 0, avail);
            net.Write(b, 0, n);
        }

        public override bool CanRead => true; public override bool CanWrite => true; public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            lock (_reading)
            {
                while (true)
                {
                    lock (_proto)
                    {
                        int avail = _p.GetAvailableInputBytes();
                        if (avail > 0) return _p.ReadInput(buffer, offset, Math.Min(count, avail));
                        if (_p.IsClosed) return 0;
                    }
                    int n = _net.Read(_inBuf, 0, _inBuf.Length);   // wait for the network: no BouncyCastle lock held
                    // The connection ended without TLS's close_notify: possibly cut off by an attacker.
                    // (Both engines send close_notify when they close normally; see SessionTls.)
                    if (n <= 0) throw new IOException("the connection closed without a TLS close_notify (truncated)");
                    lock (_proto) { try { _p.OfferInput(_inBuf, 0, n); } finally { Pump(_p, _net); } }
                }
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            lock (_proto) { _p.WriteApplicationData(buffer, offset, count); Pump(_p, _net); }
        }

        // The base Stream class runs ReadAsync and WriteAsync through ONE shared lock, so a
        // pending read would hold up every write. Running them separately avoids that.
        // (Cancelling does not interrupt a read that is already waiting; to stop one, dispose
        // the stream, which closes the socket. The engines always do that.)
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
            Task.Run(() => Read(buffer, offset, count), ct);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
            new(Task.Run(() => { var tmp = new byte[buffer.Length]; int n = Read(tmp, 0, tmp.Length); tmp.AsSpan(0, n).CopyTo(buffer.Span); return n; }, ct));
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
            Task.Run(() => Write(buffer, offset, count), ct);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) =>
            new(Task.Run(() => Write(buffer.ToArray(), 0, buffer.Length), ct));
        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Send close_notify if we can get at the protocol quickly; never wait long for it
                // (a writer stuck on a peer that stopped reading must not hang the close).
                if (Monitor.TryEnter(_proto, 500))
                {
                    try { _tcp.SendTimeout = 1000; } catch { }      // close_notify gets one second at most
                    try { _p.Close(); Pump(_p, _net); } catch { }
                    finally { Monitor.Exit(_proto); }
                }
                _tcp.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}

// #############################################################################
// #   BOUNCYCASTLE CODE - END                                                 #
// #############################################################################
