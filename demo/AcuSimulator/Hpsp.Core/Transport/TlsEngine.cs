// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Transport/TlsEngine.cs
//  Purpose: Choose between the two TLS implementations, and describe the
//           platform the demo is running on.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  The demo can run the normal reader-to-ACU session with either:
//
//    Windows       .NET's SslStream, which uses the operating system's TLS.
//                  Needs TLS 1.3 support: Windows 11 (build 22000 or later).
//    BouncyCastle  a TLS library written entirely in .NET. Works on any
//                  Windows version, including Windows 10.
//
//  Both follow the same rules and check certificates the same way, so either
//  side can use either engine. Pairing always uses BouncyCastle, because no
//  built-in TLS supports the pre-shared key that pairing needs.
// =============================================================================

using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Hpsp.Core.BouncyCastle;
using Hpsp.Core.Security;
using Hpsp.Core.Localization;

namespace Hpsp.Core.Transport;

public enum TlsEngineKind { Windows, BouncyCastle }

public static class TlsEngine
{
    /// <summary>The longest a TLS handshake may take (spec 4.7). A silent peer is cut off.</summary>
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(15);

    /// <summary>ACU side: accept TLS on a reader's connection with the chosen engine.</summary>
    public static async Task<(Stream Stream, TlsInfo Info)> AcceptAsync(TlsEngineKind kind, TcpClient tcp, X509Certificate2 acuCert, X509Certificate2 root, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(HandshakeTimeout);
        // Closing the socket is what really stops a handshake that is waiting for data.
        using var cut = limit.Token.Register(() => { try { tcp.Dispose(); } catch { } });
        try
        {
            if (kind == TlsEngineKind.BouncyCastle) return await SessionTlsBouncyCastle.AcceptAsync(tcp, acuCert, root, limit.Token).ConfigureAwait(false);
            var (s, info) = await SessionTls.AcceptAsync(tcp, acuCert, root, limit.Token).ConfigureAwait(false);
            return (new ClosingSslStream(s), info);
        }
        catch (Exception) when (limit.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            throw new TimeoutException(L.T("the TLS handshake took too long"));
        }
    }

    /// <summary>Reader side: connect to the ACU with the chosen engine.</summary>
    public static async Task<(Stream Stream, TlsInfo Info)> ConnectAsync(TlsEngineKind kind, string host, int port, X509Certificate2 readerCert, X509Certificate2 root, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(HandshakeTimeout);
        try
        {
            if (kind == TlsEngineKind.BouncyCastle) return await SessionTlsBouncyCastle.ConnectAsync(host, port, readerCert, root, limit.Token).ConfigureAwait(false);
            var (s, info) = await SessionTls.ConnectAsync(host, port, readerCert, root, limit.Token).ConfigureAwait(false);
            return (new ClosingSslStream(s), info);
        }
        catch (Exception) when (limit.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            throw new TimeoutException(L.T("the TLS handshake took too long"));
        }
    }

    /// <summary>
    /// Is the Windows engine usable here? On Windows it needs build 22000 or later
    /// (Windows 11). Elsewhere (Linux, macOS) .NET uses OpenSSL, which has TLS 1.3.
    /// </summary>
    public static bool WindowsEngineAvailable(out string why)
    {
        if (OperatingSystem.IsWindows() && !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
        {
            why = "needs Windows 11: Windows 10 has no TLS 1.3";
            return false;
        }
        why = "";
        return true;
    }

    /// <summary>
    /// A quick, invisible self-test: run a real TLS 1.3 handshake with ourselves over
    /// the loopback address using throwaway certificates. Returns null on success,
    /// otherwise the reason. Proves the chosen engine works on this computer.
    /// </summary>
    public static async Task<string?> SelfTestAsync(TlsEngineKind kind)
    {
        try
        {
            var root = DemoPki.CreateRoot("HPSP self-test root", 1);
            var acu = DemoPki.IssueAcuCertificate(root, new[] { "localhost" }, 1);
            var id = Guid.NewGuid();
            using var key = DemoPki.NewKey();
            var reader = ECDsaCertificateExtensions.CopyWithPrivateKey(DemoPki.IssueSiteIdentity(root, DemoPki.CreateCsr(key, id), id, 1), key);
            var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var server = Task.Run(async () => { using var t = await l.AcceptTcpClientAsync(cts.Token); var (s, _) = await AcceptAsync(kind, t, acu, root, cts.Token); s.Dispose(); });
            var (c, _) = await ConnectAsync(kind, "localhost", port, reader, root, cts.Token);
            c.Dispose();
            await server;
            l.Stop();
            return null;
        }
        catch (Exception e) { return e.Message; }
    }
}

/// <summary>A one-line description of the computer, for the status bar.</summary>
public static class PlatformInfo
{
    public static string Describe()
    {
        string os;
        if (OperatingSystem.IsWindows())
        {
            int build = Environment.OSVersion.Version.Build;
            os = (build >= 22000 ? "Windows 11" : "Windows 10") + $" (build {build})";
        }
        else os = RuntimeInformation.OSDescription;
        var osArch = RuntimeInformation.OSArchitecture;
        var procArch = RuntimeInformation.ProcessArchitecture;
        string arch = osArch.ToString();
        // e.g. an x64 build running under emulation on an Arm computer
        if (procArch != osArch) arch += $" (this app is {procArch}, running under emulation: use the {osArch} build for best results)";
        return $"{os}, {arch}, .NET {Environment.Version}";
    }
}
