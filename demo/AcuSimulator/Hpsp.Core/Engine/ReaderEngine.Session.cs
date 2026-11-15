// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/ReaderEngine.Session.cs
//  Purpose: The reader's operational session with the ACU: connect, hello,
//           heartbeats, events, and the commands the ACU sends.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  1. The reader dials the ACU (it never waits for the ACU to call it).
//  2. TLS 1.3 with certificates on both sides.
//  3. The reader sends "hello" with a fresh random 32-byte session value.
//     Every grant the ACU signs in this session must include that value, so a
//     grant recorded in any other session is useless.
//  4. The ACU answers with the time, the heartbeat interval and the event
//     number to resume from. The reader then replays any events the ACU has
//     not acknowledged.
//  5. From then on: events go up, commands come down, and a heartbeat every
//     few seconds shows both sides are alive. Three missed heartbeats and the
//     reader drops the session and dials again.
// =============================================================================

using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hpsp.Core.Protocol;
using Hpsp.Core.Security;
using Hpsp.Core.Transport;
using Hpsp.Core.Localization;

namespace Hpsp.Core.Engine;

public sealed partial class ReaderEngine
{
    private MessageChannel? _session;
    private CancellationTokenSource? _sessionCts;
    private byte[]? _sessionNonce;
    private bool _helloDone;
    private long _nextId = 1, _helloId, _heartbeatId;
    private int _heartbeatS = 10, _missedHeartbeats;
    private bool _heartbeatOutstanding;

    public string ConnectionStatus { get; private set; } = L.T("not connected");
    public TlsInfo? Tls { get; private set; }
    public byte[]? SessionNonce => _sessionNonce;
    public bool Connected => _helloDone;

    // =========================================================================
    //  Dial, run, and dial again
    // =========================================================================

    private async Task SessionLoopAsync(CancellationToken ct)
    {
        int backoffMs = 1000;
        while (!ct.IsCancellationRequested)
        {
            if (CablePulled) { SetStatus(L.T("cable unplugged")); await Delay(300, ct); continue; }
            if (!_state.IsPaired) { SetStatus(L.T("not paired: open the pairing window and add this reader from the ACU")); await Delay(1000, ct); continue; }
            var root = SiteRoot!; var me = SiteIdentity!;
            string host = _state.EndpointHost!; int port = _state.EndpointPort;
            SetStatus(L.F("connecting to {0}:{1} ({2})", host, port, TlsEngine));
            try
            {
                var (stream, info) = await Transport.TlsEngine.ConnectAsync(TlsEngine, host, port, me, root, ct);
                Tls = info;
                Log(ActivityKind.Good, L.F("TLS session established with the ACU: {0}", info), "tls");
                backoffMs = 1000;
                await RunSessionAsync(stream, ct);   // drops its own session when it ends
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e)
            {
                Log(ActivityKind.Error, L.T("Connection to the ACU failed: ") + e.Message, "tls");
            }
            if (ct.IsCancellationRequested) break;
            SetStatus(L.F("disconnected; retrying in {0} s", backoffMs / 1000));
            await Delay(backoffMs, ct);
            backoffMs = Math.Min(backoffMs * 2, 10_000);      // back off: 1, 2, 4, 8, 10 seconds
        }
        SetStatus("stopped");
    }

    private async Task RunSessionAsync(Stream stream, CancellationToken outer)
    {
        _sessionCts = CancellationTokenSource.CreateLinkedTokenSource(outer);
        var ct = _sessionCts.Token;
        var ch = new MessageChannel(stream, e => Activity?.Invoke(e), "session") { OurMaxMsg = 1024, OurMaxAssembled = 4096 };
        _session = ch;
        _helloDone = false; _liveEvents = false;
        _sessionNonce = RandomNumberGenerator.GetBytes(32);     // fresh for every session (spec 5.7)
        _heartbeatOutstanding = false; _missedHeartbeats = 0;
        Changed();

        // ---- hello ----
        long first, last;
        lock (_lock)
        {
            first = _state.PendingEvents.Count > 0 ? _state.PendingEvents.Min(e => e.Seq) : _seqNext - 1;
            last = _state.PendingEvents.Count > 0 ? _state.PendingEvents.Max(e => e.Seq) : _seqNext - 1;
        }
        _helloId = _nextId++;
        await ch.SendAsync(HpspMessage.Cmd("hello", _helloId, new()
        {
            ["versions"] = new List<object?> { 1L },
            ["device_id"] = _state.DeviceId.ToString("D"),
            ["manufacturer"] = Manufacturer, ["product"] = Product, ["hw_rev"] = HwRev, ["fw_version"] = FwVersion, ["serial"] = _state.Serial,
            ["dal"] = 1L, ["phy"] = "hpsp-e",
            ["max_msg"] = 1024L, ["max_assembled"] = 4096L, ["mono_now"] = Mono,
            ["caps_id"] = "demo-reader-1", ["time_valid"] = _clockOffset is not null,
            ["trust_epoch"] = _state.TrustEpoch, ["grant_floor"] = (long)_grants.Floor,
            ["session_nonce_b64"] = _sessionNonce,
            ["event_seq"] = new Dictionary<string, object?> { ["first"] = first, ["last"] = last },
        }), ct);
        SetStatus(L.T("hello sent, waiting for the ACU"));

        var heartbeat = Task.Run(() => HeartbeatLoopAsync(ch, ct), ct);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var m = await ch.ReceiveAsync(ct);
                if (m is null) { Warn(L.T("The ACU closed the session.")); break; }
                await HandleAsync(ch, m, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception e) when (e is IOException or Cbor.HpspCborException or ObjectDisposedException)
        {
            if (!ct.IsCancellationRequested) Warn(L.T("Session ended: ") + e.Message);
        }
        finally
        {
            _sessionCts.Cancel();
            try { await heartbeat; } catch { }
            // Drop only OUR session: after Stop() and Start() a newer one may already be running.
            if (_session == ch) DropSession(null); else ch.Dispose();
        }
    }

    // =========================================================================
    //  Messages from the ACU
    // =========================================================================

    private async Task HandleAsync(MessageChannel ch, HpspMessage m, CancellationToken ct)
    {
        switch (m.Type)
        {
            case "rsp" when m.Re == _helloId && !_helloDone: await OnHelloReplyAsync(ch, m, ct); return;
            case "rsp" when m.Re == _heartbeatId: _heartbeatOutstanding = false; _missedHeartbeats = 0; return;
            case "rsp": return;
            case "err" when m.Re == _helloId:
                Log(ActivityKind.Refused, L.F("The ACU refused hello: {0} {1}", m.GetString("code"), m.GetString("message")));
                throw new IOException(L.T("hello refused"));
            case "err": return;
            case "ack": if (m.GetLong("seq") is long s) Acknowledge(s); return;
            case "cmd": break;
            default: throw new IOException(L.T("unexpected message type ") + m.Type);   // unknown types close the session
        }

        long id = m.Id ?? 0;
        string op = m.Op ?? "";
        if (!_helloDone) { await ch.SendAsync(HpspMessage.Err(op, id, "forbidden", "hello not finished"), ct); return; }
        switch (op)
        {
            case "unlock": await OnUnlockAsync(ch, m, id, ct); break;
            case "lock":
                SetDoor(false, "command");
                await ch.SendAsync(HpspMessage.Rsp("lock", id, new() { ["cid"] = (long)StrikeCid, ["state"] = "locked" }), ct);
                break;
            case "set_indicator": await OnSetIndicatorAsync(ch, m, id, ct); break;
            case "trust_update": await OnTrustUpdateAsync(ch, m, id, ct); break;
            case "get_caps": await ch.SendAsync(HpspMessage.Rsp("get_caps", id, Capabilities()), ct); break;
            case "goodbye":
                await ch.SendAsync(HpspMessage.Rsp("goodbye", id), ct);
                throw new IOException(L.T("the ACU said goodbye"));
            default:
                await ch.SendAsync(HpspMessage.Err(op, id, "unsupported"), ct);
                break;
        }
    }

    private async Task OnHelloReplyAsync(MessageChannel ch, HpspMessage m, CancellationToken ct)
    {
        // Time comes only from the authenticated controller (spec 5.9).
        if (m.GetString("time") is string t && DateTimeOffset.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var acuTime))
            _clockOffset = acuTime - DateTimeOffset.UtcNow;
        if (m.GetLong("heartbeat_s") is long hb && hb is >= 2 and <= 60) _heartbeatS = (int)hb;
        if (m.GetLong("max_msg") is long mm && mm >= 1024) ch.PeerMaxMsg = (int)Math.Min(mm, 65536);
        if (m.GetLong("max_assembled") is long ma && ma >= 4096) ch.PeerMaxAssembled = (int)Math.Min(ma, 1 << 20);
        long resume = m.GetLong("resume_from") ?? 0;
        if (resume > 0) Acknowledge(resume - 1);              // everything before resume_from is safe at the ACU
        _helloDone = true;
        SetStatus(L.F("connected to {0}:{1}", _state.EndpointHost, _state.EndpointPort));
        Log(ActivityKind.Good, L.F("Session ready. Heartbeat every {0} s. Clock set from the ACU.", _heartbeatS));

        // Replay everything not yet acknowledged, strictly in order (spec 6.2). New events made
        // during the replay wait their turn (they are already in PendingEvents), so the ACU never
        // sees a newer number before an older one. Only after the replay do events go out live.
        long sentUpTo = long.MinValue; bool first = true;
        while (true)
        {
            List<StoredEvent> batch;
            lock (_lock)
            {
                batch = _state.PendingEvents.Where(e => e.Seq > sentUpTo).OrderBy(e => e.Seq).ToList();
                if (batch.Count == 0) { _liveEvents = true; break; }
            }
            if (first) Info(L.F("Replaying {0} unacknowledged event(s), seq {1} to {2}.", batch.Count, batch[0].Seq, batch[^1].Seq));
            first = false;
            foreach (var e in batch) await ch.SendAsync(HpspMessage.Decode(Convert.FromBase64String(e.CborB64)), ct, "replay");
            sentUpTo = batch[^1].Seq;
        }
    }

    /// <summary>True once the hello replay is finished and new events may be sent straight away.</summary>
    private bool _liveEvents;

    private async Task SendEventIfConnectedAsync(HpspMessage m)
    {
        var ch = _session;
        lock (_lock) if (ch is null || !_helloDone || !_liveEvents) return;   // kept in PendingEvents; sent by the replay
        try { await ch.SendAsync(m); } catch { /* the session loop will notice and reconnect */ }
    }

    // =========================================================================
    //  unlock: the security-critical part
    // =========================================================================

    private async Task OnUnlockAsync(MessageChannel ch, HpspMessage m, long id, CancellationToken ct)
    {
        // 1. Which door, and how?
        if (m.GetLong("cid") != StrikeCid) { await ch.SendAsync(HpspMessage.Err("unlock", id, "not_found", "no door with that cid"), ct); return; }
        string? mode = m.GetString("mode");
        long dur = m.GetLong("duration_ms") ?? 0;
        byte action;
        if (mode == "timed" && dur is >= 100 and <= 3_600_000) action = GrantAction.TimedUnlock;
        else if (mode == "latched" && dur == 0) action = GrantAction.LatchedUnlock;
        else { await ch.SendAsync(HpspMessage.Err("unlock", id, "bad_request", "mode or duration not valid"), ct); return; }
        var grant = Grant.FromMap(m.GetMap("grant"));
        if (grant is null) { await ch.SendAsync(HpspMessage.Err("unlock", id, "bad_request", "grant missing or malformed"), ct); return; }

        // 2. Check the grant against OUR device id and OUR session value.
        ulong? now = Now is DateTimeOffset n ? (ulong)n.ToUnixTimeSeconds() : null;
        var r = _grants.Check(grant, _state.DeviceId, _sessionNonce!, StrikeCid, action, 0, (uint)dur, now, out bool persist);
        if (r != GrantResult.Ok)
        {
            string code = GrantVerifier.ErrorCode(r);
            Log(ActivityKind.Refused, L.F("Unlock REFUSED: {0}. The door stays locked.", Explain(r)), "door");
            await ch.SendAsync(HpspMessage.Err("unlock", id, code), ct);
            // Report it as a security event, with the reason but never the grant itself (spec 5.13).
            AddEvent("security_event", 3, new() { ["kind"] = "grant_rejected", ["reason"] = code });
            return;
        }
        // 3. Never act on a counter we could not record (spec 5.8).
        if (persist) { lock (_lock) { _state.GrantBlock = _grants.ReservedBlock; Save(); } }

        // 4. Open the door, answer, and report.
        Log(ActivityKind.Good, L.F("Grant verified (counter {0}). Door UNLOCKED", grant.Counter) + (action == GrantAction.TimedUnlock ? L.F(" for {0:0.#} s.", dur / 1000.0) : " (latched)."), "door");
        await ch.SendAsync(HpspMessage.Rsp("unlock", id, action == GrantAction.TimedUnlock
            ? new() { ["cid"] = (long)StrikeCid, ["state"] = "unlocked", ["duration_ms"] = dur }
            : new() { ["cid"] = (long)StrikeCid, ["state"] = "unlocked" }), ct);
        SetDoor(true, "command", action == GrantAction.TimedUnlock ? (uint)dur : 0);
    }

    private static string Explain(GrantResult r) => r switch
    {
        GrantResult.Replay => L.T("replay (this grant's counter has already been used)"),
        GrantResult.Expired => L.T("expired grant"),
        GrantResult.BadSignature => L.T("bad signature (wrong session, altered, or signed for something else)"),
        GrantResult.Unauthorized => L.T("unknown or untrusted signer"),
        _ => r.ToString(),
    };

    private async Task OnSetIndicatorAsync(MessageChannel ch, HpspMessage m, long id, CancellationToken ct)
    {
        if (m.GetLong("cid") != LedCid) { await ch.SendAsync(HpspMessage.Err("set_indicator", id, "not_found"), ct); return; }
        string pattern = m.GetString("pattern") ?? "on";
        string color = m.GetString("color") ?? "green";
        long onMs = m.GetLong("on_ms") ?? 0, offMs = m.GetLong("off_ms") ?? 0, count = m.GetLong("count") ?? 0;
        int? forMs = count > 0 ? (int)((onMs + offMs) * count) : null;
        SetLed(pattern == "off" ? "off" : color, pattern, forMs);
        await ch.SendAsync(HpspMessage.Rsp("set_indicator", id), ct);
    }

    private async Task OnTrustUpdateAsync(MessageChannel ch, HpspMessage m, long id, CancellationToken ct)
    {
        long epoch = m.GetLong("epoch") ?? 0;
        var signers = m.GetList("signers_b64")?.OfType<byte[]>().ToList();
        if (epoch <= _state.TrustEpoch || signers is null || signers.Count is 0 or > 4)
        { await ch.SendAsync(HpspMessage.Err("trust_update", id, "bad_request", "epoch must increase; 1 to 4 signers"), ct); return; }
        // Every signer certificate must come from our site root AND be issued for grant signing
        // (not, say, the ACU's own TLS certificate), and must not be on the new revocation list.
        // NOTE: trust_update itself is not signed in this version of the spec (open item, Annex F):
        // it is trusted because it arrives over the mutually authenticated TLS session.
        var revoked = m.GetList("revoked_hex")?.OfType<byte[]>().Select(b => Convert.ToHexString(b).ToLowerInvariant()).ToList() ?? new();
        if (revoked.Count > 256) { await ch.SendAsync(HpspMessage.Err("trust_update", id, "bad_request", "too many revocations"), ct); return; }
        foreach (var der in signers)
        {
            string? why = SignerProblem(der, revoked);
            if (why is not null)
            {
                Log(ActivityKind.Refused, L.T("trust_update refused: ") + why);
                await ch.SendAsync(HpspMessage.Err("trust_update", id, "bad_request", "signer refused: " + why), ct);
                return;
            }
        }
        lock (_lock)
        {
            _state.TrustEpoch = epoch;
            _state.SignerCertsB64 = signers.Select(Convert.ToBase64String).ToList();
            _state.RevokedSerialsHex = revoked;
            _grants.SetSigners(TrustedSigners());
            Save();        // persist first, then answer (spec: trust_update)
        }
        Log(ActivityKind.Good, L.F("Trust updated: epoch {0}, {1} grant signer(s) now trusted.", epoch, signers.Count));
        await ch.SendAsync(HpspMessage.Rsp("trust_update", id, new() { ["epoch"] = epoch }), ct);
        Changed();
    }

    private Dictionary<string, object?> Capabilities() => new()
    {
        ["caps_id"] = "demo-reader-1", ["more"] = false, ["phy"] = new List<object?> { "hpsp-e" },
        ["profiles"] = new List<object?> { "reader", "electric_strike" },
        ["components"] = new List<object?>
        {
            new Dictionary<string, object?> { ["cid"] = (long)ReaderCid, ["kind"] = "reader", ["tech"] = new List<object?> { "prox" } },
            new Dictionary<string, object?> { ["cid"] = (long)StrikeCid, ["kind"] = "output", ["role"] = "lock", ["lock_type"] = "strike", ["door_release"] = true, ["fail"] = "secure", ["max_duration_ms"] = 3_600_000L },
            new Dictionary<string, object?> { ["cid"] = (long)LedCid, ["kind"] = "indicator", ["type"] = "led_rgb" },
        },
    };

    // =========================================================================
    //  Heartbeats
    // =========================================================================

    private async Task HeartbeatLoopAsync(MessageChannel ch, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Delay(_heartbeatS * 1000, ct);
            if (!_helloDone || ct.IsCancellationRequested) continue;
            if (_heartbeatOutstanding && ++_missedHeartbeats >= 3)
            {
                Warn(L.T("Three heartbeats unanswered: the session is dead. Dropping it and dialling again."));
                DropSession(null);
                return;
            }
            _heartbeatId = _nextId++;
            _heartbeatOutstanding = true;
            try
            {
                await ch.SendAsync(HpspMessage.Cmd("heartbeat", _heartbeatId, new()
                { ["status"] = "ok", ["mono_now"] = Mono, ["uptime_s"] = Mono / 1000 }), ct);
            }
            catch { return; }
        }
    }

    // =========================================================================
    //  Ending a session
    // =========================================================================

    /// <summary>True while the simulated network cable is unplugged.</summary>
    public bool CablePulled { get; private set; }

    /// <summary>
    /// Simulate pulling the network cable: drop the connection with no goodbye and stay
    /// offline until <see cref="PlugCable"/>. Card swipes meanwhile are kept and replayed later.
    /// </summary>
    public void PullCable()
    {
        if (CablePulled) return;
        CablePulled = true;
        Warn(L.T("Network cable pulled (simulated): the connection is dropped without a goodbye. Events are kept until it is plugged back in."));
        DropSession(L.T("cable unplugged"));
    }

    /// <summary>Plug the simulated cable back in; the reader reconnects and replays held events.</summary>
    public void PlugCable()
    {
        if (!CablePulled) return;
        CablePulled = false;
        Info(L.T("Network cable plugged back in."));
        Changed();
    }

    private void DropSession(string? why)
    {
        var ch = _session; _session = null;
        _helloDone = false; _liveEvents = false;
        Tls = null;
        try { _sessionCts?.Cancel(); } catch { }
        ch?.Dispose();
        if (why is not null) SetStatus(why);
        Changed();
    }

    private void SetStatus(string s) { ConnectionStatus = s; Changed(); }

    private static async Task Delay(int ms, CancellationToken ct)
    {
        try { await Task.Delay(ms, ct); } catch (OperationCanceledException) { }
    }
}
