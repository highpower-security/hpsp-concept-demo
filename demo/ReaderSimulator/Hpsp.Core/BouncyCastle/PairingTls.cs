// #############################################################################
// #                                                                           #
// #   BOUNCYCASTLE CODE - START                                               #
// #                                                                           #
// #   This file uses the BouncyCastle TLS library (MIT licence,               #
// #   https://www.bouncycastle.org/csharp/) because Windows' built-in TLS     #
// #   cannot run TLS 1.3 with an external pre-shared key, which HPSP          #
// #   commissioning requires (specification 5.6, step 4).                     #
// #                                                                           #
// #   Everything BouncyCastle-specific for pairing is in this file.           #
// #                                                                           #
// #############################################################################
//
//  HPSP Demo  -  Hpsp.Core
//  File:    BouncyCastle/PairingTls.cs
//  Purpose: The TLS 1.3 connection used during pairing, protected by the
//           pre-shared key that SPAKE2+ produced.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
//
//  IN PLAIN TERMS
//  --------------
//  After SPAKE2+, the ACU and the reader share a secret 32-byte key, and
//  nobody else has it. They now start a normal TLS 1.3 handshake on the same
//  TCP connection, but instead of certificates they prove themselves with that
//  key (a "pre-shared key", PSK). A fresh elliptic-curve key exchange is still
//  done (mode psk_dhe_ke), so even that key leaking later would not expose this
//  conversation. Inside this encrypted link the ACU checks the reader's factory
//  identity and gives it its site certificate.
//
//  As the specification says, the READER acts as the TLS server here, and the
//  ACU as the TLS client. Settings:
//    - TLS 1.3 only, cipher TLS_AES_128_GCM_SHA256, group P-256
//    - ALPN "hpsp/1"
//    - PSK identity "hpsp-commissioning-1"
//  A wrong key makes the handshake fail with "Invalid PSK binder".
// =============================================================================

using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Hpsp.Core.BouncyCastle;

/// <summary>An open pairing TLS connection.</summary>
public sealed class PairingTlsConnection : IDisposable
{
    private readonly TlsProtocol _protocol;
    private readonly TlsContext _context;
    internal PairingTlsConnection(TlsProtocol protocol, TlsContext context, byte[] attestExporter)
    { _protocol = protocol; _context = context; AttestExporter = attestExporter; }

    /// <summary>The decrypted application data stream. HPSP frames go over this.</summary>
    public Stream Stream => _protocol.Stream;

    /// <summary>
    /// The 32-byte TLS exporter value (RFC 8446 section 7.5) with label
    /// "EXPORTER-HPSP-ATTEST" and an empty context. The reader's attestation
    /// signature covers it, so a recorded attestation cannot be replayed into a
    /// different session. (BouncyCastle only allows exporting at the moment the
    /// handshake completes, so it is captured there.)
    /// </summary>
    public byte[] AttestExporter { get; }

    public string Describe()
    {
        var sp = _context.SecurityParameters;
        string suite = sp.CipherSuite == CipherSuite.TLS_AES_128_GCM_SHA256 ? "TLS_AES_128_GCM_SHA256" : "0x" + sp.CipherSuite.ToString("x4");
        return $"TLS 1.3 (BouncyCastle), {suite}, pre-shared key + {NamedGroup.GetName(sp.NegotiatedGroup)} key exchange, ALPN {sp.ApplicationProtocol?.GetUtf8Decoding()}";
    }

    public void Dispose() { try { _protocol.Close(); } catch { /* already closed */ } }
}

public static class PairingTls
{
    public const int Port = 7501;
    public const string AttestLabel = "EXPORTER-HPSP-ATTEST";
    private static readonly byte[] Identity = Encoding.ASCII.GetBytes("hpsp-commissioning-1");
    private static readonly ProtocolName Alpn = ProtocolName.AsUtf8Encoding("hpsp/1");

    /// <summary>Reader side: run the TLS server handshake on an already-open stream.</summary>
    public static PairingTlsConnection AcceptAsReader(Stream tcp, byte[] psk)
    {
        var crypto = new BcTlsCrypto(new SecureRandom());
        var server = new ReaderPskServer(crypto, psk);
        var proto = new TlsServerProtocol(tcp);
        proto.Accept(server);                     // blocking; throws TlsFatalAlert on failure
        return new PairingTlsConnection(proto, server.Context, server.AttestExporter!);
    }

    /// <summary>ACU side: run the TLS client handshake on an already-open stream.</summary>
    public static PairingTlsConnection ConnectAsAcu(Stream tcp, byte[] psk)
    {
        var crypto = new BcTlsCrypto(new SecureRandom());
        var client = new AcuPskClient(crypto, psk);
        var proto = new TlsClientProtocol(tcp);
        proto.Connect(client);                    // blocking; throws TlsFatalAlert on failure
        return new PairingTlsConnection(proto, client.Context, client.AttestExporter!);
    }

    // ---- the BouncyCastle client and server definitions ----------------------

    private sealed class AcuPskClient : AbstractTlsClient
    {
        private readonly TlsPskExternal _psk;
        public AcuPskClient(TlsCrypto crypto, byte[] key) : base(crypto) =>
            _psk = new BasicTlsPskExternal(Identity, crypto.CreateSecret(key), PrfAlgorithm.tls13_hkdf_sha256);
        public TlsContext Context => m_context;
        public byte[]? AttestExporter { get; private set; }
        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();
            AttestExporter = m_context.ExportKeyingMaterial(AttestLabel, Array.Empty<byte>(), 32);
        }
        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.Only();
        protected override int[] GetSupportedCipherSuites() => new[] { CipherSuite.TLS_AES_128_GCM_SHA256 };
        protected override IList<int> GetSupportedGroups(IList<int> namedGroupRoles) => new List<int> { NamedGroup.secp256r1 };
        protected override IList<ProtocolName> GetProtocolNames() => new List<ProtocolName> { Alpn };
        public override IList<TlsPskExternal> GetExternalPsks() => new List<TlsPskExternal> { _psk };
        public override short[] GetPskKeyExchangeModes() => new[] { PskKeyExchangeMode.psk_dhe_ke };
        public override TlsAuthentication GetAuthentication() => new PskOnlyAuthentication();
    }

    private sealed class ReaderPskServer : AbstractTlsServer
    {
        private readonly TlsPskExternal _psk;
        public ReaderPskServer(TlsCrypto crypto, byte[] key) : base(crypto) =>
            _psk = new BasicTlsPskExternal(Identity, crypto.CreateSecret(key), PrfAlgorithm.tls13_hkdf_sha256);
        public TlsContext Context => m_context;
        public byte[]? AttestExporter { get; private set; }
        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();
            AttestExporter = m_context.ExportKeyingMaterial(AttestLabel, Array.Empty<byte>(), 32);
        }
        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.Only();
        protected override int[] GetSupportedCipherSuites() => new[] { CipherSuite.TLS_AES_128_GCM_SHA256 };
        public override int[] GetSupportedGroups() => new[] { NamedGroup.secp256r1 };
        protected override IList<ProtocolName> GetProtocolNames() => new List<ProtocolName> { Alpn };
        public override TlsPskExternal GetExternalPsk(IList<PskIdentity> identities)
        {
            foreach (var id in identities)
                if (Org.BouncyCastle.Utilities.Arrays.AreEqual(id.Identity, Identity)) return _psk;
            return null!;   // unknown identity: BouncyCastle aborts the handshake
        }
        public override TlsCredentials GetCredentials() => null!;   // PSK mode: no certificate is sent
    }

    /// <summary>In PSK mode the server must not send a certificate; if it does, refuse.</summary>
    private sealed class PskOnlyAuthentication : TlsAuthentication
    {
        public void NotifyServerCertificate(TlsServerCertificate serverCertificate) =>
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest) => null!;
    }
}

// #############################################################################
// #   BOUNCYCASTLE CODE - END                                                 #
// #############################################################################
