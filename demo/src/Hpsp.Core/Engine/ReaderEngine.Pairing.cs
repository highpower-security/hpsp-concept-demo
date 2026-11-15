// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/ReaderEngine.Pairing.cs
//  Purpose: The reader's side of pairing (commissioning), specification 5.6.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  A new reader has no site. To join one:
//
//   1. Someone presses its pairing button (here: "Open pairing window"). That
//      proves a person is physically at the device. The reader then listens on
//      TCP port 7501 for 10 minutes. This is the ONLY time it listens at all.
//   2. The ACU connects. They run SPAKE2+ with the reader's setup code; the
//      code itself never crosses the network. Every attempt is counted BEFORE
//      the reader reveals anything that could be used to test a guess, and only
//      a correct code clears the count; so walking away mid-attempt still uses
//      up a try. After 5 failed attempts pairing is locked for 5 minutes, then
//      10, 20, 40 and at most 60 minutes for each further lock-out.
//   3. Both now share a key. They start TLS 1.3 with it (BouncyCastle; the
//      reader is the TLS server here).
//   4. Inside that encrypted link the ACU:
//        attest_request  - the reader proves its factory identity by signing a
//                          challenge tied to this exact TLS session;
//        enroll          - tells the reader its site, the site's root
//                          certificate and where to connect; the reader makes
//                          a brand-new key pair and returns a signing request;
//        cert_install    - gives the reader its site certificate.
//   5. The reader closes the window and dials the ACU for a normal session.
// =============================================================================

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hpsp.Core.BouncyCastle;
using Hpsp.Core.Protocol;
using Hpsp.Core.Security;
using Hpsp.Core.Localization;

namespace Hpsp.Core.Engine;

public sealed partial class ReaderEngine
{
    public const int MaxFailedAttempts = 5;
    public static readonly TimeSpan PairingWindowLength = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan LongestLockout = TimeSpan.FromMinutes(60);
    /// <summary>The first lock-out's length (5 minutes); later ones double. Tests shorten it.</summary>
    public TimeSpan FirstLockout { get; set; } = TimeSpan.FromMinutes(5);
    /// <summary>How long one pairing attempt may take before the connection is cut (spec 4.7).</summary>
    public static readonly TimeSpan PairingAttemptTimeout = TimeSpan.FromSeconds(60);
    /// <summary>How long the reader waits for each message from the ACU during pairing.</summary>
    public static readonly TimeSpan PairingStepTimeout = TimeSpan.FromSeconds(10);

    private TcpListener? _pairingListener;
    private CancellationTokenSource? _pairingCts;
    public DateTime? PairingWindowUntil { get; private set; }
    public bool PairingWindowOpen => PairingWindowUntil is DateTime t && t > DateTime.Now;

    /// <summary>Simulate pressing the pairing button: listen on the pairing port for 10 minutes.</summary>
    public void OpenPairingWindow()
    {
        if (PairingWindowOpen) return;
        ClearExpiredLockout();
        // An operational (paired) device ignores the pairing button (spec 5.6). Factory reset first.
        if (IsPaired) { Log(ActivityKind.Warning, L.T("This reader is already paired: the pairing button is ignored. Use Factory reset to pair it with another site."), "pairing"); return; }
        if (LockedOut) { Log(ActivityKind.Refused, L.F("Pairing is locked after {0} wrong codes, until {1:T}.", MaxFailedAttempts, LockedOutUntil), "pairing"); return; }
        try
        {
            _pairingListener = new TcpListener(IPAddress.Any, PairingPort);
            _pairingListener.Start();
        }
        catch (SocketException e) { Log(ActivityKind.Error, L.F("Cannot listen on port {0}: {1}", PairingPort, e.Message), "pairing"); return; }
        _pairingCts = new CancellationTokenSource(PairingWindowLength);
        PairingWindowUntil = DateTime.Now + PairingWindowLength;
        Log(ActivityKind.Info, L.F("Pairing button pressed: listening on port {0} until {1:T}. Setup code {2}.", PairingPort, PairingWindowUntil, SetupCode), "pairing");
        Changed();
        _ = Task.Run(() => PairingAcceptLoopAsync(_pairingListener, _pairingCts.Token));
    }

    public void ClosePairingWindow()
    {
        if (_pairingListener is null) return;
        try { _pairingCts?.Cancel(); _pairingListener.Stop(); } catch { }
        _pairingListener = null;
        PairingWindowUntil = null;
        Log(ActivityKind.Info, L.T("Pairing window closed."), "pairing");
        Changed();
    }

    private async Task PairingAcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        try
        {
            // One attempt at a time (spec 5.6): while one is running, any other connection is
            // closed at once rather than queued, so nobody can hold the window by waiting in line.
            Task? current = null;
            while (!ct.IsCancellationRequested)
            {
                TcpClient tcp;
                try { tcp = await listener.AcceptTcpClientAsync(ct); }
                catch { break; }
                if (current is { IsCompleted: false })
                {
                    Log(ActivityKind.Refused, L.F("Refused a second pairing connection from {0}: one attempt at a time.", tcp.Client.RemoteEndPoint), "pairing");
                    tcp.Dispose();
                    continue;
                }
                current = RunAttemptAsync(tcp, ct);
            }
            if (current is not null) await current;
        }
        catch (Exception e) { Log(ActivityKind.Error, L.T("Pairing stopped after an unexpected error: ") + e.Message, "pairing"); }
        finally { if (_pairingListener == listener) ClosePairingWindow(); }
    }

    private async Task RunAttemptAsync(TcpClient tcp, CancellationToken ct)
    {
        bool done;
        using (tcp)
        using (var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            // Each message must arrive within 10 s, and the whole attempt within 60 s; a silent
            // or slow peer is cut off. (ReceiveTimeout covers the TLS part, which reads the
            // socket directly; the token covers the SPAKE2+ part.)
            tcp.ReceiveTimeout = (int)PairingStepTimeout.TotalMilliseconds;
            attempt.CancelAfter(PairingAttemptTimeout);
            using var cut = attempt.Token.Register(() => { try { tcp.Dispose(); } catch { } });
            try { done = await PairOneAsync(tcp, attempt.Token); }
            catch (Exception e) { Log(ActivityKind.Error, L.T("Pairing attempt ended: ") + e.Message, "pairing"); done = false; }
        }
        if (done || LockedOut) ClosePairingWindow();
    }

    /// <summary>Receive one pairing message, waiting at most <see cref="PairingStepTimeout"/>.</summary>
    private static async Task<HpspMessage?> StepAsync(MessageChannel ch, CancellationToken ct)
    {
        using var step = CancellationTokenSource.CreateLinkedTokenSource(ct);
        step.CancelAfter(PairingStepTimeout);
        return await ch.ReceiveAsync(step.Token);
    }

    /// <summary>A lock-out that has run out is cleared, with a fresh set of attempts.</summary>
    private void ClearExpiredLockout()
    {
        lock (_lock)
        {
            if (_state.LockedOutUntilUtc is DateTime t && t <= DateTime.UtcNow)
            {
                _state.LockedOutUntilUtc = null;
                _state.FailedAttempts = 0;
                Save();
            }
        }
    }

    /// <summary>Handle one pairing attempt. Returns true when the reader is now paired.</summary>
    private async Task<bool> PairOneAsync(TcpClient tcp, CancellationToken ct)
    {
        string peer = tcp.Client.RemoteEndPoint?.ToString() ?? "?";
        Log(ActivityKind.Info, L.F("Pairing connection from {0}.", peer), "pairing");
        ClearExpiredLockout();
        if (LockedOut) { Log(ActivityKind.Refused, L.T("Refused: too many wrong codes."), "pairing"); return false; }
        var raw = tcp.GetStream();
        // NOTE: this channel must not be disposed, because TLS continues on the same stream.
        var pake = new MessageChannel(raw, e => Activity?.Invoke(e), "pairing");
        try
        {
            // ---- SPAKE2+ (the reader is the verifier) ----
            byte[] salt = Convert.FromHexString(_state.SaltHex), w0 = Convert.FromHexString(_state.W0Hex), verifierL = Convert.FromHexString(_state.LHex);
            byte[] idV = GrantInput.UuidBytes(_state.DeviceId);
            await pake.SendAsync(HpspMessage.Pake("pake_params", new()
            { ["v"] = 1L, ["device_id"] = _state.DeviceId.ToString("D"), ["salt_b64"] = salt, ["iterations"] = (long)_state.Iterations }), ct);

            var m1 = await StepAsync(pake, ct);
            if (m1 is not { Type: "pake", Op: "pake_share" } || m1.GetBytes("share_p_b64") is not byte[] shareP) throw new IOException("expected pake_share");
            byte[] y = Spake2Plus.RandomScalar();
            byte[] shareV = Spake2Plus.VerifierShare(y, w0);
            Spake2PlusKeys keys;
            try { keys = Spake2Plus.VerifierFinish(Spake2Plus.HpspContext, Spake2Plus.HpspProverId, idV, w0, verifierL, y, shareP, shareV); }
            catch (CryptographicException e) { await Fail(pake, L.T("invalid share: ") + e.Message, ct); return false; }

            // Count this attempt as failed NOW, before sending confirm_v (which would let the other
            // side test its guess offline). Only a correct confirm_p below clears the count.
            if (!RecordAttempt()) { await Fail(pake, L.T("too many wrong codes"), ct, counted: true); return false; }
            await pake.SendAsync(HpspMessage.Pake("pake_share", new() { ["share_v_b64"] = shareV, ["confirm_v_b64"] = keys.ConfirmV }), ct);

            var m2 = await StepAsync(pake, ct);
            if (m2 is { Type: "pake", Op: "pake_fail" }) { ReportFailure(L.T("the ACU's code did not match ours")); return false; }
            if (m2 is not { Type: "pake", Op: "pake_confirm" } || m2.GetBytes("confirm_p_b64") is not byte[] confirmP) throw new IOException("expected pake_confirm");
            if (!Spake2Plus.ConfirmEquals(confirmP, keys.ConfirmP)) { await Fail(pake, L.T("wrong setup code"), ct, counted: true); return false; }

            lock (_lock) { _state.FailedAttempts = 0; _state.LockedOutUntilUtc = null; _state.LockoutCount = 0; Save(); }
            byte[] psk = Spake2Plus.DerivePsk(keys.KShared);
            Log(ActivityKind.Good, L.T("Setup code confirmed by SPAKE2+. Starting TLS with the shared key."), "pairing",
                secret: L.F("y (our random scalar): {0}\nK_shared: {1}\nPre-shared key for TLS: {2}", Hex(y), Hex(keys.KShared), Hex(psk)));

            // ---- TLS 1.3 with the pre-shared key (BouncyCastle; we are the server) ----
            using var tls = await Task.Run(() => PairingTls.AcceptAsReader(raw, psk), ct);
            Log(ActivityKind.Good, L.T("Pairing TLS established: ") + tls.Describe(), "tls");
            var ch = new MessageChannel(tls.Stream, e => Activity?.Invoke(e), "pairing");
            return await PairingCommandsAsync(ch, tls.AttestExporter, ct);
        }
        catch (Exception e) when (e is IOException or Cbor.HpspCborException or CryptographicException or OperationCanceledException or SocketException or ObjectDisposedException)
        {
            // (BouncyCastle's TLS errors are IOExceptions, so they are caught here too.)
            Log(ActivityKind.Error, L.T("Pairing attempt ended: ") + e.Message, "pairing");
            Changed();
            return false;
        }
    }

    /// <summary>Send pake_fail and report. Failures before the attempt was counted are counted here.</summary>
    private async Task Fail(MessageChannel pake, string why, CancellationToken ct, bool counted = false)
    {
        try { await pake.SendAsync(HpspMessage.Pake("pake_fail"), ct); } catch { }
        if (!counted) RecordAttempt();
        ReportFailure(why);
    }

    /// <summary>
    /// Count one attempt (it stays counted unless the code turns out correct) and save the count.
    /// Returns false if this attempt reaches the limit, which starts a lock-out.
    /// </summary>
    private bool RecordAttempt()
    {
        ClearExpiredLockout();
        lock (_lock)
        {
            _state.FailedAttempts++;
            if (_state.FailedAttempts > MaxFailedAttempts) { Save(); return false; }
            if (_state.FailedAttempts == MaxFailedAttempts)
            {
                // This is the last allowed attempt. If it fails, the lock-out applies; if it
                // succeeds, the count is cleared below. Set the lock-out now so that walking
                // away cannot avoid it.
                var len = TimeSpan.FromTicks(Math.Min(LongestLockout.Ticks, FirstLockout.Ticks << Math.Min(_state.LockoutCount, 4)));
                _state.LockedOutUntilUtc = DateTime.UtcNow + len;
                _state.LockoutCount++;
                // (FailedAttempts stays at 5 while locked; ClearExpiredLockout gives a fresh 5
                //  attempts once the lock-out has run out, however this attempt ends.)
            }
            Save();
            return true;
        }
    }

    private void ReportFailure(string why)
    {
        int left = Math.Max(0, MaxFailedAttempts - _state.FailedAttempts);
        Log(ActivityKind.Refused, L.F("Pairing refused: {0}. Attempts left before lock-out: {1}.", why, left), "pairing");
        if (LockedOut)
        {
            Log(ActivityKind.Refused, L.F("Too many wrong codes: pairing locked until {0:T}.", LockedOutUntil), "pairing");
        }
        Changed();
    }

    // -------------------------------------------------------------------------
    //  Inside the pairing TLS session: attest_request, enroll, cert_install
    // -------------------------------------------------------------------------

    private async Task<bool> PairingCommandsAsync(MessageChannel ch, byte[] exporter, CancellationToken ct)
    {
        ECDsa? newKey = null;
        Guid siteId = Guid.Empty; X509Certificate2? anchor = null; string? host = null; int port = 7500; long epoch = 0;
        while (true)
        {
            var m = await ch.ReceiveAsync(ct);
            if (m is null) { Warn(L.T("The ACU closed the pairing session before finishing.")); return false; }
            if (m.Type != "cmd" || m.Id is not long id) continue;
            switch (m.Op)
            {
                case "attest_request":
                {
                    // Prove our factory identity: sign "HPSP1-ATTEST\0" || UUID || nonce || TLS exporter.
                    if (m.GetBytes("nonce_b64") is not byte[] nonce || nonce.Length != 32) { await ch.SendAsync(HpspMessage.Err("attest_request", id, "bad_request"), ct); break; }
                    var idev = FactoryIdentity;
                    byte[] input = AttestInput(_state.DeviceId, nonce, exporter);
                    using var k = idev.GetECDsaPrivateKey()!;
                    byte[] sig = k.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    await ch.SendAsync(HpspMessage.Rsp("attest_request", id, new()
                    { ["chain_b64"] = new List<object?> { idev.RawData, ManufacturerCa.RawData }, ["sig_b64"] = sig }), ct);
                    break;
                }
                case "enroll":
                {
                    var anchors = m.GetList("anchors_b64")?.OfType<byte[]>().ToList();
                    var eps = m.GetList("endpoints")?.OfType<Dictionary<string, object?>>().ToList();
                    if (IsPaired) { await ch.SendAsync(HpspMessage.Err("enroll", id, "wrong_state", "already paired"), ct); break; }
                    if (m.GetString("site_id") is not string sid || !Guid.TryParse(sid, out siteId) || anchors is not { Count: >= 1 } || eps is not { Count: >= 1 })
                    { await ch.SendAsync(HpspMessage.Err("enroll", id, "bad_request"), ct); break; }
                    anchor = DemoPki.TryLoad(anchors[0]);
                    if (anchor is null) { await ch.SendAsync(HpspMessage.Err("enroll", id, "bad_request", "anchor is not a certificate"), ct); break; }
                    host = eps[0].GetValueOrDefault("host") as string;
                    port = (int)(eps[0].GetValueOrDefault("port") as long? ?? 7500);
                    epoch = m.GetLong("trust_epoch") ?? 0;
                    // A brand-new key pair for the site identity. It never leaves the reader.
                    newKey?.Dispose();
                    newKey = DemoPki.NewKey();
                    byte[] csr = DemoPki.CreateCsr(newKey, _state.DeviceId);
                    Log(ActivityKind.Info, L.F("Enrolling in site {0}. New key pair made; sending a certificate signing request. Will connect to {1}:{2}. Site trust epoch {3}.", siteId, host, port, epoch), "pairing");
                    await ch.SendAsync(HpspMessage.Rsp("enroll", id, new() { ["csr_b64"] = csr }), ct);
                    break;
                }
                case "cert_install":
                {
                    var chain = m.GetList("chain_b64")?.OfType<byte[]>().ToList();
                    if (newKey is null || anchor is null || host is null || chain is not { Count: >= 1 })
                    { await ch.SendAsync(HpspMessage.Err("cert_install", id, "wrong_state", "enroll first"), ct); break; }
                    var cert = DemoPki.TryLoad(chain[0]);
                    if (cert is null) { await ch.SendAsync(HpspMessage.Err("cert_install", id, "bad_request", "not a certificate"), ct); break; }
                    // Check the certificate before accepting it: from our new site root, for us, with our key.
                    string? why = DemoPki.CheckChain(cert, anchor, DemoPki.ClientAuth);
                    // (why stays in English: it is also sent to the ACU, and wire text is never translated.)
                    if (why is null && DemoPki.TryDeviceIdOf(cert) != _state.DeviceId) why = "certificate is for another device";
                    if (why is null && !cert.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(newKey.ExportSubjectPublicKeyInfo())) why = "certificate is not for our new key";
                    if (why is not null)
                    {
                        Log(ActivityKind.Refused, L.T("Site certificate refused: ") + L.T(why), "pairing");
                        await ch.SendAsync(HpspMessage.Err("cert_install", id, "bad_request", why), ct);
                        break;
                    }
                    lock (_lock)
                    {
                        _state.SiteId = siteId.ToString("D");
                        _state.SiteRootB64 = Convert.ToBase64String(anchor.RawData);
                        _state.EndpointHost = host; _state.EndpointPort = port;
                        // The grant signer list arrives in the first session (trust_update), so until
                        // then we report epoch 0: "I have no trust list yet". (enroll gave us the
                        // site's current epoch, which we only log.)
                        _state.TrustEpoch = 0;
                        _state.SiteIdentityPfxB64 = Convert.ToBase64String(DemoPki.ExportWithKey(cert.CopyWithPrivateKey(newKey)));
                        _state.SignerCertsB64.Clear();
                        _grants = NewVerifier();
                        Save();
                    }
                    await ch.SendAsync(HpspMessage.Rsp("cert_install", id, new() { ["state"] = "operational" }), ct);
                    Log(ActivityKind.Good, L.F("PAIRED with site {0}. Site certificate installed ({1}). Connecting to the ACU.", siteId, DemoPki.Fingerprint(cert)), "pairing");
                    Changed();
                    return true;
                }
                default:
                    await ch.SendAsync(HpspMessage.Err(m.Op ?? "", id, "unsupported"), ct);
                    break;
            }
        }
    }

    /// <summary>The attestation signing input: "HPSP1-ATTEST\0" || device UUID || nonce || TLS exporter (spec 5.6, attest_request).</summary>
    public static byte[] AttestInput(Guid deviceId, byte[] nonce, byte[] exporter) =>
        "HPSP1-ATTEST\0"u8.ToArray().Concat(GrantInput.UuidBytes(deviceId)).Concat(nonce).Concat(exporter).ToArray();

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}
