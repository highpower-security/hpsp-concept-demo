// =============================================================================
//  HPSP Demo  -  Hpsp.Core.Tests
//  File:    CoreTests.cs
//  Purpose: Tests of the building blocks: CBOR, grants, cards, SPAKE2+, TLS.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hpsp.Core.BouncyCastle;
using Hpsp.Core.Cards;
using Hpsp.Core.Cbor;
using Hpsp.Core.Protocol;
using Hpsp.Core.Security;
using Hpsp.Core.Transport;

namespace Hpsp.Core.Tests;

public static class CoreTests
{
    /// <summary>Further test groups added by other files (engine tests).</summary>
    public static readonly List<Func<Action<bool, string>, Task>> Extra = new();

    static byte[] Hex(string s) => Convert.FromHexString(s);

    // ---- convert the specification's JSON notation into a CBOR tree ------------
    //  Rule from the spec: members ending in _hex or _b64 hold bytes.
    public static object? FromJson(JsonElement e, string? key = null) => e.ValueKind switch
    {
        JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => FromJson(p.Value, p.Name)),
        JsonValueKind.Array => e.EnumerateArray().Select(x => FromJson(x, key)).ToList(),
        JsonValueKind.String when key is not null && key.EndsWith("_hex") => Hex(e.GetString()!),
        JsonValueKind.String when key is not null && key.EndsWith("_b64") => Encoding64.FromBase64Url(e.GetString()!),
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number when e.TryGetInt64(out var l) => l,
        JsonValueKind.Number => e.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => throw new InvalidOperationException("null in example"),
    };

    public static void Cbor(JsonElement examples, Action<bool, string> check)
    {
        int n = 0, ok = 0;
        foreach (var ex in examples.EnumerateArray())
        {
            JsonElement doc;
            try { doc = ex.ValueKind == JsonValueKind.String ? JsonDocument.Parse(ex.GetString()!).RootElement : ex; } catch { continue; }
            if (doc.ValueKind != JsonValueKind.Object || !doc.TryGetProperty("type", out _)) continue;
            n++;
            try
            {
                var tree = FromJson(doc);
                byte[] cbor = HpspCbor.Encode(tree);
                var msg = HpspMessage.Decode(cbor);
                // Encoding the decoded message again must give identical bytes (deterministic CBOR).
                if (msg.Encode().AsSpan().SequenceEqual(cbor)) ok++;
                else Console.WriteLine("   re-encode differs: " + msg.Describe());
            }
            catch (Exception e) { Console.WriteLine("   example failed: " + e.Message); }
        }
        check(n >= 100 && ok == n, $"all {n} example messages in the specification encode, decode and re-encode identically ({ok} ok)");

        // Inputs the profile MUST reject
        var bad = new (string, string)[]
        {
            ("trailing byte", "a161610100"), ("indefinite map", "bf616101ff"), ("tag", "a16161c101"),
            ("null", "a16161f6"), ("undefined", "a16161f7"), ("duplicate key", "a2616101616102"),
            ("integer key", "a10101"), ("not a map", "8101"), ("truncated", "a1616165"),
            ("too deep", "a161618181818181818101"),
        };
        foreach (var (name, hex) in bad)
        {
            bool rejected;
            try { HpspCbor.DecodeMessage(Hex(hex)); rejected = false; } catch (HpspCborException) { rejected = true; }
            check(rejected, "CBOR profile rejects: " + name);
        }
    }

    public static void Grants(JsonElement v, Action<bool, string> check)
    {
        var g = v.GetProperty("grant");
        var device = Guid.Parse(v.GetProperty("deviceId").GetString()!);
        byte[] nonce = Hex(v.GetProperty("nonceHex").GetString()!);
        ulong counter = g.GetProperty("counter").GetUInt64(), expires = g.GetProperty("expires").GetUInt64();
        byte[] input = GrantInput.Build(device, nonce, counter, (ushort)g.GetProperty("cid").GetInt32(), 1, 0, (uint)g.GetProperty("duration_ms").GetInt32(), expires);
        check(Convert.ToHexString(input).Equals(v.GetProperty("inputHex").GetString(), StringComparison.OrdinalIgnoreCase),
              "84-byte signing input matches Annex E byte for byte");

        // Rebuild the test signer from the published (test-only) key.
        byte[] pubRaw = Hex(v.GetProperty("pubHex").GetString()!);
        var key = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = Hex(v.GetProperty("privHex").GetString()!),
            Q = new ECPoint { X = pubRaw[1..33], Y = pubRaw[33..65] },
        });
        var signer = new GrantSigner(key);
        check(Convert.ToHexString(signer.SignerId).Equals(v.GetProperty("signerHex").GetString(), StringComparison.OrdinalIgnoreCase),
              "signer id (SHA-256 of the public key) matches Annex E");

        var specGrant = new Grant(signer.SignerId, counter, expires, Hex(v.GetProperty("sigHex").GetString()!));
        GrantVerifier Fresh(ulong block = 0)
        {
            var gv = new GrantVerifier(block);
            gv.SetSigners(new[] { new TrustedSigner(signer.SignerId, key.ExportSubjectPublicKeyInfo(), false) });
            return gv;
        }
        GrantResult Run(GrantVerifier gv, Grant gr, byte[] n, ulong? now, byte action = 1, byte param = 0) =>
            gv.Check(gr, device, n, 2, action, param, 5000, now, out _);

        var ver = Fresh();
        check(Run(ver, specGrant, nonce, null) == GrantResult.Ok, "the Annex E signature verifies");
        check(Run(ver, specGrant, nonce, null) == GrantResult.Replay, "the same grant again is refused as a replay");
        check(Run(Fresh(), specGrant, nonce, expires + 5) == GrantResult.Ok, "accepted within the 5-second clock allowance");
        check(Run(Fresh(), specGrant, nonce, expires + 6) == GrantResult.Expired, "an expired grant is refused");
        var other = (byte[])nonce.Clone(); other[0] ^= 1;
        check(Run(Fresh(), specGrant, other, null) == GrantResult.BadSignature, "a grant for another session is refused");
        check(Run(Fresh(), specGrant, nonce, null, action: 2) == GrantResult.BadSignature, "a grant for another action is refused");
        check(Run(Fresh(), specGrant, nonce, null, param: 1) == GrantResult.BadSignature, "the parameter byte is covered by the signature");
        var tampered = specGrant with { Signature = (byte[])specGrant.Signature.Clone() }; tampered.Signature[10] ^= 1;
        check(Run(Fresh(), tampered, nonce, null) == GrantResult.BadSignature, "a tampered signature is refused");
        check(Run(Fresh(1024), specGrant, nonce, null) == GrantResult.Replay, "after a reboot, counters below the floor are refused");
        var unknown = specGrant with { SignerId = new byte[32] };
        check(Run(Fresh(), unknown, nonce, null) == GrantResult.Unauthorized, "an unknown signer is refused");

        // A fresh signature from our signer must also verify, and be low-S.
        var fresh = signer.Sign(device, nonce, 5000, 2, 1, 0, 5000, expires);
        check(Run(Fresh(), fresh, nonce, null) == GrantResult.Ok, "a grant signed by GrantSigner verifies");
        var sHalf = new System.Numerics.BigInteger(fresh.Signature.AsSpan(32), true, true);
        var n = System.Numerics.BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", System.Globalization.NumberStyles.HexNumber);
        check(sHalf <= n / 2, "GrantSigner produces low-S signatures");
    }

    public static void Wiegand(Action<bool, string> check)
    {
        byte[] raw = Wiegand26.ToRaw(142, 54321);
        check(Convert.ToHexString(raw).ToLowerInvariant() == "c76a18c0", "facility 142, card 54321 encodes to c76a18c0 (the specification's example)");
        check(Wiegand26.TryDecode(raw, 26, out int fc, out int id) && fc == 142 && id == 54321, "and decodes back");
        raw[1] ^= 0x10;
        check(!Wiegand26.TryDecode(raw, 26, out _, out _), "a flipped bit fails the parity check");
        bool all = true;
        foreach (var (f, c) in new[] { (0, 0), (255, 65535), (1, 1), (128, 32768), (17, 4242) })
            all &= Wiegand26.TryDecode(Wiegand26.ToRaw(f, c), 26, out var f2, out var c2) && f2 == f && c2 == c;
        check(all, "round trip for edge values");
    }

    public static void Spake(JsonElement v, Action<bool, string> check)
    {
        // RFC 9383 Appendix C, P256-SHA256-HKDF-SHA256-HMAC-SHA256
        byte[] ctx = Encoding.ASCII.GetBytes("SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors");
        byte[] w0 = Hex("bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3");
        byte[] w1 = Hex("7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba");
        byte[] x = Hex("d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539");
        byte[] y = Hex("717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3");
        byte[] idP = "client"u8.ToArray(), idV = "server"u8.ToArray();
        byte[] L = Spake2Plus.ComputeL(w1);
        byte[] X = Spake2Plus.ProverShare(x, w0), Y = Spake2Plus.VerifierShare(y, w0);
        var p = Spake2Plus.ProverFinish(ctx, idP, idV, w0, w1, x, X, Y);
        var vv = Spake2Plus.VerifierFinish(ctx, idP, idV, w0, L, y, X, Y);
        string H(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        check(H(p.KMain) == "4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29", "RFC 9383 K_main reproduced");
        check(H(p.ConfirmP) == "926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527", "RFC 9383 confirmP reproduced");
        check(H(p.ConfirmV) == "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68", "RFC 9383 confirmV reproduced");
        check(H(p.KShared) == "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7", "RFC 9383 K_shared reproduced");
        check(H(vv.KShared) == H(p.KShared) && H(vv.ConfirmV) == H(p.ConfirmV), "prover and verifier agree");

        // HPSP commissioning vector (Annex E)
        var pk = v.GetProperty("pake");
        var (hw0, hw1) = Spake2Plus.DeriveW0W1(pk.GetProperty("code").GetString()!, Hex(pk.GetProperty("salt_hex").GetString()!), pk.GetProperty("iterations").GetInt32());
        check(H(hw0) == pk.GetProperty("w0_hex").GetString() && H(hw1) == pk.GetProperty("w1_hex").GetString(), "setup code stretched to Annex E w0 and w1");
        byte[] hx = Hex(pk.GetProperty("x_hex").GetString()!), hy = Hex(pk.GetProperty("y_hex").GetString()!);
        byte[] hX = Spake2Plus.ProverShare(hx, hw0), hY = Spake2Plus.VerifierShare(hy, hw0);
        var hp = Spake2Plus.ProverFinish(Spake2Plus.HpspContext, Spake2Plus.HpspProverId, Hex(pk.GetProperty("id_verifier_hex").GetString()!), hw0, hw1, hx, hX, hY);
        check(H(hp.KShared) == pk.GetProperty("K_shared_hex").GetString(), "Annex E K_shared reproduced");
        check(H(Spake2Plus.DerivePsk(hp.KShared)) == pk.GetProperty("psk_hex").GetString(), "Annex E commissioning pre-shared key reproduced");

        // A wrong code gives different keys, so the confirmations fail.
        var (bw0, bw1) = Spake2Plus.DeriveW0W1("AAAAAAAA", Hex(pk.GetProperty("salt_hex").GetString()!), pk.GetProperty("iterations").GetInt32());
        byte[] bX = Spake2Plus.ProverShare(hx, bw0);
        var good = Spake2Plus.VerifierFinish(Spake2Plus.HpspContext, Spake2Plus.HpspProverId, new byte[16], hw0, Spake2Plus.ComputeL(hw1), hy, bX, hY);
        var badP = Spake2Plus.ProverFinish(Spake2Plus.HpspContext, Spake2Plus.HpspProverId, new byte[16], bw0, bw1, hx, bX, hY);
        check(!Spake2Plus.ConfirmEquals(good.ConfirmP, badP.ConfirmP), "a wrong setup code fails confirmation");
        bool rejected;
        try { Spake2Plus.VerifierFinish(Spake2Plus.HpspContext, Spake2Plus.HpspProverId, new byte[16], hw0, Spake2Plus.ComputeL(hw1), hy, new byte[65], hY); rejected = false; }
        catch (CryptographicException) { rejected = true; }
        check(rejected, "an invalid share is rejected");
    }

    public static async Task PairingTlsTest(Action<bool, string> check)
    {
        byte[] psk = RandomNumberGenerator.GetBytes(32);
        async Task<(bool ok, string info, byte[]? exA, byte[]? exB)> Try(byte[] readerKey, byte[] acuKey)
        {
            var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            var server = Task.Run(() =>
            {
                using var s = l.AcceptTcpClient();
                try
                {
                    using var c = PairingTls.AcceptAsReader(s.GetStream(), readerKey);
                    var buf = new byte[4]; int r = c.Stream.Read(buf, 0, 4); c.Stream.Write(buf, 0, r);
                    return c.AttestExporter;
                }
                catch (Exception e) { Console.WriteLine("   server: " + e.GetType().Name + ": " + e.Message); return null; }
            });
            try
            {
                using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, port);
                using var c = PairingTls.ConnectAsAcu(tcp.GetStream(), acuKey);
                c.Stream.Write("ping"u8); var buf = new byte[4]; c.Stream.ReadExactly(buf);
                var ex = c.AttestExporter;
                var exB = await server;
                l.Stop();
                return (Encoding.ASCII.GetString(buf) == "ping", c.Describe(), ex, exB);
            }
            catch (Exception e) { Console.WriteLine("   client: " + e.GetType().Name + ": " + e.Message); await server; l.Stop(); return (false, "", null, null); }
        }
        var good = await Try(psk, psk);
        check(good.ok && good.info.Contains("TLS_AES_128_GCM_SHA256"), "TLS 1.3 with the pre-shared key: " + good.info);
        check(good.exA is not null && good.exB is not null && good.exA.AsSpan().SequenceEqual(good.exB), "both sides compute the same TLS exporter value (used by attestation)");
        var wrong = (byte[])psk.Clone(); wrong[0] ^= 1;
        check(!(await Try(psk, wrong)).ok, "a different pre-shared key is refused");
    }

    /// <summary>A small demo site: root, ACU certificate and one reader certificate.</summary>
    public static (System.Security.Cryptography.X509Certificates.X509Certificate2 root,
                   System.Security.Cryptography.X509Certificates.X509Certificate2 acu,
                   System.Security.Cryptography.X509Certificates.X509Certificate2 reader, Guid id) MakeSite()
    {
        var root = DemoPki.CreateRoot("HPSP test site root");
        var acu = DemoPki.IssueAcuCertificate(root, new[] { "localhost", "127.0.0.1" });
        var id = Guid.NewGuid();
        using var rk = DemoPki.NewKey();
        var reader = System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions.CopyWithPrivateKey(DemoPki.IssueSiteIdentity(root, DemoPki.CreateCsr(rk, id), id), rk);
        return (root, acu, reader, id);
    }

    public static async Task SessionTlsTest(Action<bool, string> check, bool useBouncyCastle)
    {
        var (root, acu, reader, id) = MakeSite();
        var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var tcp = await l.AcceptTcpClientAsync();
            var (s, info) = await SessionTls.AcceptAsync(tcp, acu, root, CancellationToken.None);
            var msg = await Framing.ReadAsync(s, 1024);
            await Framing.WriteAsync(s, msg!);
            s.Dispose();
            return info;
        });
        var (cs, cinfo) = await SessionTls.ConnectAsync("localhost", port, reader, root, CancellationToken.None);
        var body = HpspMessage.Cmd("get_caps", 1).Encode();
        await Framing.WriteAsync(cs, body);
        var echo = await Framing.ReadAsync(cs, 1024);
        var sinfo = await server; l.Stop(); cs.Dispose();
        check(cinfo.Protocol == "TLS 1.3" && cinfo.Alpn == "hpsp/1", "reader side: " + cinfo);
        check(sinfo.PeerDeviceId == id, "ACU side sees the reader's device UUID from its certificate");
        check(echo is not null && echo.AsSpan().SequenceEqual(body), "a framed message makes the round trip");

        // A reader certificate from a different site must be refused.
        var (_, _, foreignReader, _) = MakeSite();
        var l2 = new TcpListener(IPAddress.Loopback, 0); l2.Start(); int p2 = ((IPEndPoint)l2.LocalEndpoint).Port;
        var srv2 = Task.Run(async () => { using var t = await l2.AcceptTcpClientAsync(); try { await SessionTls.AcceptAsync(t, acu, root, CancellationToken.None); return "accepted"; } catch (Exception e) { return e.Message; } });
        try { await SessionTls.ConnectAsync("localhost", p2, foreignReader, root, CancellationToken.None); } catch { }
        string r2 = await srv2; l2.Stop();
        check(r2 != "accepted", "a reader certificate from another site is refused (" + Short(r2) + ")");

        // The reader must refuse an ACU from another site.
        var (_, foreignAcu, _, _) = MakeSite();
        var l3 = new TcpListener(IPAddress.Loopback, 0); l3.Start(); int p3 = ((IPEndPoint)l3.LocalEndpoint).Port;
        var srv3 = Task.Run(async () => { using var t = await l3.AcceptTcpClientAsync(); try { await SessionTls.AcceptAsync(t, foreignAcu, root, CancellationToken.None); } catch { } });
        string r3;
        try { await SessionTls.ConnectAsync("localhost", p3, reader, root, CancellationToken.None); r3 = "accepted"; } catch (Exception e) { r3 = e.Message; }
        await srv3; l3.Stop();
        check(r3 != "accepted", "an ACU certificate from another site is refused (" + Short(r3) + ")");
    }

    static string Short(string s) => s.Length > 90 ? s[..90] + "..." : s;
}

/// <summary>Both TLS engines, in all four combinations, must interoperate.</summary>
public static class EngineTests
{
    public static async Task Run(Action<bool, string> check)
    {
        Console.WriteLine("== TLS engines: Windows/OpenSSL and BouncyCastle, every combination ==");
        foreach (var serverKind in new[] { Transport.TlsEngineKind.Windows, Transport.TlsEngineKind.BouncyCastle })
        foreach (var clientKind in new[] { Transport.TlsEngineKind.Windows, Transport.TlsEngineKind.BouncyCastle })
        {
            var (root, acu, reader, id) = CoreTests.MakeSite();
            var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0); l.Start();
            int port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
            var server = Task.Run(async () =>
            {
                using var tcp = await l.AcceptTcpClientAsync();
                var (s, info) = await Transport.TlsEngine.AcceptAsync(serverKind, tcp, acu, root, CancellationToken.None);
                var m = await Protocol.Framing.ReadAsync(s, 1024); await Protocol.Framing.WriteAsync(s, m!); s.Dispose();
                return info;
            });
            string result;
            try
            {
                var (c, cinfo) = await Transport.TlsEngine.ConnectAsync(clientKind, "localhost", port, reader, root, CancellationToken.None);
                var body = Protocol.HpspMessage.Cmd("get_caps", 7).Encode();
                await Protocol.Framing.WriteAsync(c, body);
                var echo = await Protocol.Framing.ReadAsync(c, 1024);
                var sinfo = await server; c.Dispose();
                result = echo!.AsSpan().SequenceEqual(body) && sinfo.PeerDeviceId == id ? "ok: " + cinfo.Cipher : "data mismatch";
            }
            catch (Exception e) { result = "failed: " + e.Message; }
            l.Stop();
            check(result.StartsWith("ok"), $"ACU {serverKind} <-> reader {clientKind}: {result}");
        }
        check(await Transport.TlsEngine.SelfTestAsync(Transport.TlsEngineKind.Windows) is null, "self-test passes for the built-in engine");
        check(await Transport.TlsEngine.SelfTestAsync(Transport.TlsEngineKind.BouncyCastle) is null, "self-test passes for the BouncyCastle engine");

        // BouncyCastle engine must refuse a reader from another site too.
        var (r1, a1, _, _) = CoreTests.MakeSite();
        var (_, _, foreign, _) = CoreTests.MakeSite();
        var l2 = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0); l2.Start(); int p2 = ((System.Net.IPEndPoint)l2.LocalEndpoint).Port;
        var srv = Task.Run(async () => { using var t = await l2.AcceptTcpClientAsync(); try { await Transport.TlsEngine.AcceptAsync(Transport.TlsEngineKind.BouncyCastle, t, a1, r1, CancellationToken.None); return "accepted"; } catch (Exception e) { return e.Message; } });
        try { await Transport.TlsEngine.ConnectAsync(Transport.TlsEngineKind.BouncyCastle, "localhost", p2, foreign, r1, CancellationToken.None); } catch { }
        var r = await srv; l2.Stop();
        check(r != "accepted", "BouncyCastle engine refuses a reader certificate from another site");
        Console.WriteLine("   platform: " + Transport.PlatformInfo.Describe());
    }
}
