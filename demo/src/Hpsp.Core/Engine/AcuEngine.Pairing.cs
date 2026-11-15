// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/AcuEngine.Pairing.cs
//  Purpose: The ACU's side of pairing (commissioning), specification 5.6.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  "Add reader" in the ACU:
//    1. connects to the reader's pairing port (the reader's button must have
//       been pressed in the last 10 minutes);
//    2. runs SPAKE2+ with the setup code the installer typed or scanned;
//    3. starts TLS 1.3 with the key SPAKE2+ produced (BouncyCastle);
//    4. checks the reader's factory identity (attest_request), tells it about
//       the site (enroll), signs its new site certificate and installs it
//       (cert_install);
//    5. records the reader as paired. The reader then calls in on port 7500.
// =============================================================================

using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hpsp.Core.BouncyCastle;
using Hpsp.Core.Protocol;
using Hpsp.Core.Security;
using Hpsp.Core.Localization;

namespace Hpsp.Core.Engine;

public sealed partial class AcuEngine
{
    /// <summary>
    /// Pair a reader. <paramref name="codeOrQr"/> is the setup code ("7KQ4-M9TW") or
    /// the QR text ("HPSP:1:..."). Returns null on success, otherwise the reason.
    /// </summary>
    public async Task<string?> AddReaderAsync(string host, int port, string codeOrQr, string? name = null, CancellationToken ct = default)
    {
        if (!HasSite) return L.T("create a demo site first");
        Guid? expectId = null;
        string code;
        if (codeOrQr.Trim().StartsWith("HPSP:", StringComparison.OrdinalIgnoreCase))
        {
            if (!SetupCode.TryParseQr(codeOrQr, out var qid, out code, out var err)) return L.T("QR text: ") + err;
            expectId = qid;
        }
        else code = SetupCode.Normalize(codeOrQr) ?? "";
        if (code.Length != 8) return L.T("the setup code must be 8 characters from the code alphabet (no 0, O, 1 or I)");

        Log(ActivityKind.Info, L.F("Adding a reader at {0}:{1}…", host, port), "pairing");
        // The whole pairing must finish within a minute; a silent reader cannot hang the ACU.
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(ReaderEngine.PairingAttemptTimeout);
        ct = limit.Token;

        // A reader handles one pairing attempt at a time and closes any other connection at
        // once. If it is still finishing an earlier attempt, try again a few times.
        TcpClient tcp = null!; NetworkStream raw = null!; MessageChannel pake = null!; HpspMessage? p = null;
        for (int attempt = 1; ; attempt++)
        {
            tcp = new TcpClient { NoDelay = true };
            try { await tcp.ConnectAsync(host, port, ct); }
            catch (Exception e) { tcp.Dispose(); return Fail(L.F("cannot reach {0}:{1} ({2}). Is the reader's pairing window open?", host, port, e.Message)); }
            raw = tcp.GetStream();
            pake = new MessageChannel(raw, e => Activity?.Invoke(e), "pairing");   // not disposed: TLS continues on this stream
            try { p = await pake.ReceiveAsync(ct); } catch (IOException) { p = null; }
            if (p is not null || attempt == 4) break;
            tcp.Dispose();
            Log(ActivityKind.Info, L.T("The reader is busy with another pairing attempt; trying again…"), "pairing");
            await Task.Delay(700, ct);
        }
        using var tcpOwner = tcp;
        using var cut = ct.Register(() => { try { tcp.Dispose(); } catch { } });
        try
        {
            // ---- SPAKE2+ (the ACU is the prover) ----
            if (p is not { Type: "pake", Op: "pake_params" } || p.GetBytes("salt_b64") is not byte[] salt || p.GetLong("iterations") is not long iter
                || !Guid.TryParse(p.GetString("device_id"), out var deviceId))
                return Fail(L.T("the reader did not start pairing correctly"));
            if (expectId is Guid e1 && e1 != deviceId) return Fail(L.F("this is not the reader in the QR code (QR {0}, reader {1})", e1, deviceId));
            if (iter is < 1000 or > 10_000_000) return Fail(L.T("unreasonable iteration count from the reader"));

            var (w0, w1) = Spake2Plus.DeriveW0W1(code, salt, (int)iter);
            byte[] x = Spake2Plus.RandomScalar();
            byte[] shareP = Spake2Plus.ProverShare(x, w0);
            await pake.SendAsync(HpspMessage.Pake("pake_share", new() { ["share_p_b64"] = shareP }), ct);
            var r = await pake.ReceiveAsync(ct);
            if (r is { Type: "pake", Op: "pake_fail" }) return Fail(L.T("the reader refused: wrong setup code"));
            if (r is not { Type: "pake", Op: "pake_share" } || r.GetBytes("share_v_b64") is not byte[] shareV || r.GetBytes("confirm_v_b64") is not byte[] confirmV)
                return Fail(L.T("unexpected reply from the reader"));
            Spake2PlusKeys keys;
            try { keys = Spake2Plus.ProverFinish(Spake2Plus.HpspContext, Spake2Plus.HpspProverId, GrantInput.UuidBytes(deviceId), w0, w1, x, shareP, shareV); }
            catch (CryptographicException ex) { await SendFail(pake, ct); return Fail(L.T("invalid share from the reader: ") + ex.Message); }
            if (!Spake2Plus.ConfirmEquals(confirmV, keys.ConfirmV)) { await SendFail(pake, ct); return Fail(L.T("wrong setup code (the reader's confirmation did not match)")); }
            await pake.SendAsync(HpspMessage.Pake("pake_confirm", new() { ["confirm_p_b64"] = keys.ConfirmP }), ct);
            byte[] psk = Spake2Plus.DerivePsk(keys.KShared);
            Log(ActivityKind.Good, L.T("SPAKE2+ succeeded: both sides proved they know the setup code."), "pairing",
                secret: L.F("Setup code: {0}\nw0: {1}\nw1: {2}\nx (our random scalar): {3}\nK_shared: {4}\nPre-shared key for TLS: {5}", SetupCode.Pretty(code), Hex(w0), Hex(w1), Hex(x), Hex(keys.KShared), Hex(psk)));

            // ---- TLS 1.3 with the pre-shared key (BouncyCastle; the ACU is the client) ----
            using var tls = await Task.Run(() => PairingTls.ConnectAsAcu(raw, psk), ct);
            Log(ActivityKind.Good, L.T("Pairing TLS established: ") + tls.Describe(), "tls");
            var ch = new MessageChannel(tls.Stream, e => Activity?.Invoke(e), "pairing");
            long id = 1;

            // ---- attestation: is this genuine hardware? ----
            byte[] nonce = RandomNumberGenerator.GetBytes(32);
            var att = await Ask(ch, HpspMessage.Cmd("attest_request", id++, new() { ["nonce_b64"] = nonce }), ct);
            var chain = att.GetList("chain_b64")?.OfType<byte[]>().ToList();
            if (chain is not { Count: >= 2 } || att.GetBytes("sig_b64") is not byte[] attSig) return Fail(L.T("attestation reply incomplete"));
            if (DemoPki.TryLoad(chain[0]) is not { } idev || DemoPki.TryLoad(chain[1]) is not { } mfr) return Fail(L.T("attestation reply incomplete"));
            if (DemoPki.CheckChain(idev, mfr, null) is string why) return Fail(L.T("factory identity does not chain to its manufacturer: ") + why);
            if (DemoPki.TryDeviceIdOf(idev) != deviceId) return Fail(L.T("factory identity is for a different device"));
            using (var pub = idev.GetECDsaPublicKey())
                if (pub is null || !pub.VerifyData(ReaderEngine.AttestInput(deviceId, nonce, tls.AttestExporter), attSig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    return Fail(L.T("attestation signature is not valid for this session"));
            bool known;
            lock (_lock) known = _state.KnownManufacturersB64.Contains(Convert.ToBase64String(mfr.RawData));
            if (!known)
            {
                if (!AcceptUnknownManufacturers) return Fail(L.F("manufacturer root {0} is not trusted", DemoPki.Fingerprint(mfr)));
                lock (_lock) { _state.KnownManufacturersB64.Add(Convert.ToBase64String(mfr.RawData)); Save(); }
                Log(ActivityKind.Warning, L.F("Manufacturer root {0} seen for the first time and accepted (demo setting). A real site checks it against a trusted list.", DemoPki.Fingerprint(mfr)), "pairing");
            }
            Log(ActivityKind.Good, L.F("Factory identity verified: {0}, bound to this TLS session.", idev.Subject), "pairing");

            // ---- enroll: tell the reader about the site; get its signing request ----
            var root = SiteRoot!;
            var en = await Ask(ch, HpspMessage.Cmd("enroll", id++, new()
            {
                ["site_id"] = _state.SiteId!,
                ["anchors_b64"] = new List<object?> { root.RawData },
                ["endpoints"] = new List<object?> { new Dictionary<string, object?> { ["host"] = _state.EndpointHost, ["port"] = (long)_state.ListenPort } },
                ["trust_epoch"] = _state.TrustEpoch,
                ["time"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"),
            }), ct);
            if (en.GetBytes("csr_b64") is not byte[] csr) return Fail(L.T("no certificate signing request"));

            // ---- issue and install the site certificate ----
            X509Certificate2 site;
            try { site = DemoPki.IssueSiteIdentity(root, csr, deviceId); }
            catch (CryptographicException ex) { return Fail(L.T("bad signing request: ") + ex.Message); }
            var inst = await Ask(ch, HpspMessage.Cmd("cert_install", id++, new() { ["chain_b64"] = new List<object?> { site.RawData, root.RawData } }), ct);
            if (inst.GetString("state") != "operational") return Fail(L.T("the reader did not accept its certificate"));

            string serial = idev.SubjectName.Name?.Split(',').Select(t => t.Trim()).FirstOrDefault(t => t.StartsWith("SERIALNUMBER="))?[13..] ?? "";
            lock (_lock)
            {
                _state.Readers.RemoveAll(x => x.DeviceId == deviceId);
                _state.Readers.Add(new PairedReader
                {
                    DeviceId = deviceId, Name = string.IsNullOrWhiteSpace(name) ? L.F("Reader {0}", serial) : name.Trim(), Serial = serial,
                    PairedUtc = DateTime.UtcNow, FactoryFingerprint = DemoPki.Fingerprint(idev),
                    SiteCertFingerprint = DemoPki.Fingerprint(site), SiteCertSerialHex = site.SerialNumber.ToLowerInvariant(),
                });
                Save();
            }
            Log(ActivityKind.Good, L.F("READER PAIRED: {0} ({1}). Site certificate {2} issued. It will now connect on port {3}.", deviceId, serial, DemoPki.Fingerprint(site), _state.ListenPort), "pairing");
            Changed();
            return null;
        }
        catch (Exception e) when (e is IOException or Cbor.HpspCborException or CryptographicException or SocketException or InvalidOperationException or OperationCanceledException or ObjectDisposedException)
        {
            return Fail(L.T("pairing failed: ") + e.Message);
        }
    }

    private static async Task<HpspMessage> Ask(MessageChannel ch, HpspMessage cmd, CancellationToken ct)
    {
        await ch.SendAsync(cmd, ct);
        while (true)
        {
            var m = await ch.ReceiveAsync(ct) ?? throw new IOException(L.T("the reader closed the pairing session"));
            if (m.Re != cmd.Id) continue;
            if (m.Type == "err") throw new InvalidOperationException(L.F("{0} refused by the reader: {1} {2}", cmd.Op, m.GetString("code"), m.GetString("message")));
            return m;
        }
    }

    private static async Task SendFail(MessageChannel pake, CancellationToken ct)
    {
        try { await pake.SendAsync(HpspMessage.Pake("pake_fail"), ct); } catch { }
    }

    private string Fail(string why)
    {
        Log(ActivityKind.Refused, L.T("Add reader failed: ") + why, "pairing");
        return why;
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}
