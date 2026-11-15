// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Security/DemoPki.cs
//  Purpose: Create and check the certificates the demo needs
//           (specification sections 5.4 "Identity and certificates" and 5.5 "Roles").
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  A certificate is a digital ID card: a public key plus some details, signed
//  by an issuer. The demo uses these:
//
//    Manufacturer CA    "the factory". Signs each reader's factory identity.
//    Reader IDevID      the reader's factory identity: proves what the device is.
//    Site root CA       "the building's badge office". Created by the ACU.
//    ACU certificate    proves to readers that they reached the real ACU.
//    Reader LDevID      the reader's site identity, issued during pairing.
//    Grant signer       the key that signs unlock grants (kept apart from the ACU).
//
//  Every key is ECDSA on the P-256 curve, the one curve HPSP uses. A reader's
//  certificates carry its device UUID as a URI "urn:uuid:..." in the Subject
//  Alternative Name, and the ACU checks it equals the device_id in hello.
//
//  DEMO ONLY: real products keep private keys in secure hardware, and a real
//  site root key is kept offline. Here everything is generated on the fly.
// =============================================================================

using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Hpsp.Core.Security;

public static class DemoPki
{
    // Extended key usage OIDs
    public const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    public const string ClientAuth = "1.3.6.1.5.5.7.3.2";
    /// <summary>
    /// The "HPSP grant signing" usage (spec 5.5): a grant signer's certificate carries this and
    /// neither TLS usage, so a TLS key can never be passed off as a grant signer.
    /// PLACEHOLDER: the real identifier is still to be allocated (spec 14.3). This one is under
    /// 32473, the enterprise number IANA reserves for documentation and examples (RFC 5612).
    /// </summary>
    public const string GrantSigning = "1.3.6.1.4.1.32473.1.1";

    /// <summary>A new P-256 key.</summary>
    public static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    // -------------------------------------------------------------------------
    //  Issuing
    // -------------------------------------------------------------------------

    /// <summary>A self-signed certificate authority (site root or manufacturer CA).</summary>
    public static X509Certificate2 CreateRoot(string commonName, int years = 10)
    {
        using var key = NewKey();
        var req = new CertificateRequest("CN=" + commonName, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        return req.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(years));
    }

    /// <summary>The ACU's TLS server certificate. Names are the host names and addresses readers will dial.</summary>
    public static X509Certificate2 IssueAcuCertificate(X509Certificate2 root, IEnumerable<string> names, int years = 2)
    {
        using var key = NewKey();
        var req = new CertificateRequest("CN=HPSP demo ACU", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ServerAuth) }, false));
        var san = new SubjectAlternativeNameBuilder();
        foreach (var n in names.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (IPAddress.TryParse(n, out var ip)) san.AddIpAddress(ip); else san.AddDnsName(n);
        }
        req.CertificateExtensions.Add(san.Build());
        return IssueWithKey(req, root, key, years);
    }

    /// <summary>A grant-signer certificate. Readers learn signer public keys from these.</summary>
    public static X509Certificate2 IssueGrantSigner(X509Certificate2 root, int years = 2)
    {
        using var key = NewKey();
        var req = new CertificateRequest("CN=HPSP demo grant signer", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(GrantSigning) }, true));
        return IssueWithKey(req, root, key, years);
    }

    /// <summary>A reader's factory identity (IDevID), signed by the manufacturer CA.</summary>
    public static X509Certificate2 IssueFactoryIdentity(X509Certificate2 manufacturerCa, Guid deviceId, string serial)
    {
        using var key = NewKey();
        var req = new CertificateRequest($"CN={deviceId}, SERIALNUMBER={serial}, O=HPSP demo manufacturer", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(DeviceIdSan(deviceId));
        return IssueWithKey(req, manufacturerCa, key, 20);
    }

    /// <summary>
    /// A reader's site identity (LDevID), issued by the site root from the
    /// certificate signing request the reader made during pairing. The reader
    /// keeps its private key; only the public key travels.
    /// </summary>
    public static X509Certificate2 IssueSiteIdentity(X509Certificate2 root, byte[] csrDer, Guid deviceId, int years = 2)
    {
        var csr = CertificateRequest.LoadSigningRequest(csrDer, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.Default);   // Default verifies the request's own signature
        // HPSP devices use ECDSA P-256 keys (spec 5.5); refuse anything else.
        using (var pub = csr.PublicKey.GetECDsaPublicKey())
            if (pub is null || pub.ExportParameters(false).Curve.Oid?.Value != "1.2.840.10045.3.1.7")
                throw new CryptographicException("the signing request is not for an ECDSA P-256 key");
        // We build our own request around the reader's public key, so nothing in the
        // reader's request (other extensions, other names) is copied blindly.
        var req = new CertificateRequest(new X500DistinguishedName("CN=" + deviceId), csr.PublicKey, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ClientAuth) }, false));
        req.CertificateExtensions.Add(DeviceIdSan(deviceId));
        var now = DateTimeOffset.UtcNow;
        using var rootKey = root.GetECDsaPrivateKey() ?? throw new InvalidOperationException("site root key missing");
        var notAfter = now.AddYears(years);
        if (notAfter > root.NotAfter) notAfter = root.NotAfter;         // never outlive the root
        return req.Create(root.SubjectName, X509SignatureGenerator.CreateForECDsa(rootKey), now.AddMinutes(-5), notAfter, NewSerial());
    }

    /// <summary>A certificate signing request (PKCS#10) for a new key, made by the reader during pairing.</summary>
    public static byte[] CreateCsr(ECDsa key, Guid deviceId)
    {
        var req = new CertificateRequest("CN=" + deviceId, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(DeviceIdSan(deviceId));
        return req.CreateSigningRequest();
    }

    private static X509Extension DeviceIdSan(Guid deviceId)
    {
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri("urn:uuid:" + deviceId.ToString("D")));
        return san.Build();
    }

    private static X509Certificate2 IssueWithKey(CertificateRequest req, X509Certificate2 issuer, ECDsa key, int years)
    {
        var now = DateTimeOffset.UtcNow;
        var notAfter = now.AddYears(years);
        if (notAfter > issuer.NotAfter) notAfter = issuer.NotAfter;
        using var issuerKey = issuer.GetECDsaPrivateKey() ?? throw new InvalidOperationException("issuer key missing");
        using var cert = req.Create(issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(issuerKey), now.AddMinutes(-5), notAfter, NewSerial());
        return cert.CopyWithPrivateKey(key);
    }

    private static byte[] NewSerial() { var s = RandomNumberGenerator.GetBytes(16); s[0] &= 0x7f; return s; }

    // -------------------------------------------------------------------------
    //  Checking
    // -------------------------------------------------------------------------

    /// <summary>
    /// Check that a certificate chains to the given root, is in date and, if
    /// <paramref name="requiredEku"/> is given, is allowed for that purpose.
    /// Returns null when valid, otherwise a short reason.
    /// </summary>
    public static string? CheckChain(X509Certificate2 cert, X509Certificate2 root, string? requiredEku)
    {
        // An end-entity certificate must not be a CA (and in particular not the root itself).
        if (cert.RawData.AsSpan().SequenceEqual(root.RawData)) return "the site root cannot be used here";
        if (cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is { CertificateAuthority: true })
            return "a CA certificate cannot be used here";
        if (requiredEku is not null)
        {
            // .NET treats a certificate WITHOUT an extended-key-usage list as good for every
            // purpose. HPSP requires the usage to be stated, so check the list ourselves.
            var ekus = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault()?.EnhancedKeyUsages
                .Cast<Oid>().Select(o => o.Value).ToList();
            if (ekus is null || !ekus.Contains(requiredEku)) return "certificate is not issued for this purpose";
            if (requiredEku == GrantSigning && (ekus.Contains(ServerAuth) || ekus.Contains(ClientAuth)))
                return "a grant signer certificate must not also be a TLS certificate";
        }
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;   // trust ONLY this root, never the OS store
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;      // HPSP distributes revocation itself (spec 5.10)
        if (requiredEku is not null) chain.ChainPolicy.ApplicationPolicy.Add(new Oid(requiredEku));
        if (!chain.Build(cert))
            return string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()).Where(s => s.Length > 0).DefaultIfEmpty("chain not valid"));
        // The chain must end at exactly our root (not just a certificate with the same name).
        var top = chain.ChainElements[^1].Certificate;
        if (!top.RawData.AsSpan().SequenceEqual(root.RawData)) return "chain does not end at the site root";
        return null;
    }

    /// <summary>Parse a DER certificate received from the network; null if it is not one.</summary>
    public static X509Certificate2? TryLoad(byte[]? der)
    {
        if (der is null || der.Length is 0 or > 8192) return null;
        try { return new X509Certificate2(der); } catch (CryptographicException) { return null; }
    }

    /// <summary>Like <see cref="DeviceIdOf"/>, but a malformed name gives null instead of an exception.</summary>
    public static Guid? TryDeviceIdOf(X509Certificate2 cert)
    {
        try { return DeviceIdOf(cert); } catch (Exception e) when (e is AsnContentException or CryptographicException) { return null; }
    }

    /// <summary>The device UUID from a certificate's urn:uuid: name, or null.</summary>
    public static Guid? DeviceIdOf(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.17") continue;
            var reader = new AsnReader(ext.RawData, AsnEncodingRules.DER);
            var seq = reader.ReadSequence();
            while (seq.HasData)
            {
                var tag = seq.PeekTag();
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 6)   // uniformResourceIdentifier
                {
                    string uri = seq.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6));
                    if (uri.StartsWith("urn:uuid:", StringComparison.OrdinalIgnoreCase) && Guid.TryParse(uri[9..], out var g)) return g;
                }
                else seq.ReadEncodedValue();
            }
        }
        return null;
    }

    /// <summary>A short fingerprint for display: the first 8 bytes of SHA-256 of the certificate.</summary>
    public static string Fingerprint(X509Certificate2 cert) =>
        string.Join(":", SHA256.HashData(cert.RawData).Take(8).Select(b => b.ToString("x2")));

    /// <summary>SHA-256 of a public key's SubjectPublicKeyInfo: the identifier HPSP uses for signers.</summary>
    public static byte[] SpkiHash(X509Certificate2 cert) => SHA256.HashData(cert.PublicKey.ExportSubjectPublicKeyInfo());

    // -------------------------------------------------------------------------
    //  Windows note
    // -------------------------------------------------------------------------

    /// <summary>
    /// Windows' TLS (SChannel) cannot use a private key that exists only in memory,
    /// which is how .NET creates them above. Exporting to PKCS#12 and re-importing
    /// places the key where SChannel can reach it. On Linux this is harmless.
    /// </summary>
    public static X509Certificate2 ForTls(X509Certificate2 certWithKey)
    {
        byte[] pfx = certWithKey.Export(X509ContentType.Pkcs12);
        return new X509Certificate2(pfx, (string?)null, X509KeyStorageFlags.Exportable);
    }

    /// <summary>Save a certificate with its key (DEMO ONLY: no password, plain file).</summary>
    public static byte[] ExportWithKey(X509Certificate2 c) => c.Export(X509ContentType.Pkcs12);
    public static X509Certificate2 ImportWithKey(byte[] pfx) => new(pfx, (string?)null, X509KeyStorageFlags.Exportable);
}
