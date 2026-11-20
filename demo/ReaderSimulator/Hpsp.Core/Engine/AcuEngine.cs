// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/AcuEngine.cs
//  Purpose: The simulated Access Control Unit (controller): its site, the
//           listener for reader sessions, and access decisions.
//           (Pairing is in AcuEngine.Pairing.cs; the attack demonstrations in
//           AcuEngine.Attacks.cs.)
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  The ACU waits for readers to call it on TCP port 7500. For each reader:
//    - TLS 1.3: the reader's certificate must come from this site's root and
//      name a device the ACU has paired and not removed;
//    - hello: the device ID inside must match the certificate;
//    - the ACU answers with the time, heartbeat interval and where to resume;
//    - if the reader's trust list is out of date, the ACU sends trust_update
//      with the grant signer's certificate.
//  When a card is reported, the ACU looks it up in the access list:
//    - allowed: it asks the grant signer for a grant bound to this reader and
//      this session, sends "unlock", and turns the reader's LED green;
//    - not allowed: no unlock; the LED flashes red.
// =============================================================================

using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hpsp.Core.Cards;
using Hpsp.Core.Protocol;
using Hpsp.Core.Security;
using Hpsp.Core.Transport;
using Hpsp.Core.Localization;

namespace Hpsp.Core.Engine;

/// <summary>One connected reader, as the ACU sees it.</summary>
public sealed class ReaderSession
{
    public Guid DeviceId { get; init; }
    public string Name { get; set; } = "";
    public string Address { get; init; } = "";
    public DateTime ConnectedAt { get; } = DateTime.Now;
    public TlsInfo? Tls { get; init; }
    public byte[]? SessionNonce { get; set; }
    public byte[]? PreviousSessionNonce { get; set; }
    public ulong GrantFloor { get; set; }
    public DateTime LastHeard { get; set; } = DateTime.Now;
    public long EventsReceived { get; set; }
    public long LastSeq { get; set; }
    public string DoorState { get; set; } = "locked";
    /// <summary>The device's monotonic clock, and our time when we learned it, for dating events.</summary>
    public long MonoNow { get; set; }
    public DateTime MonoAt { get; set; }
    internal MessageChannel? Channel { get; set; }
    internal CancellationTokenSource Cts { get; } = new();
    internal long NextId = 100;
    internal Dictionary<string, object?>? LastUnlockData { get; set; }
    public bool HelloDone { get; set; }
}

public sealed partial class AcuEngine : IDisposable
{
    public const int CredentialMaxAgeMs = 5000;     // spec 6.2: never act on an older card read
    public static readonly TimeSpan HelloTimeout = TimeSpan.FromSeconds(5);   // spec 4.7
    private const long MaxGrantFloor = 1L << 48;      // far beyond any real counter; refuses nonsense

    private readonly string _statePath, _accessPath;
    private readonly object _lock = new();
    private AcuState _state;
    private TcpListener? _listener;
    private CancellationTokenSource? _runCts;
    private readonly ConcurrentDictionary<Guid, ReaderSession> _sessions = new();

    public event Action<ActivityEntry>? Activity;
    public event Action? StateChanged;

    public TlsEngineKind TlsEngine { get; set; } = TlsEngineKind.Windows;
    public int HeartbeatSeconds { get; set; } = 10;
    /// <summary>DEMO: accept a reader's manufacturer root the first time it is seen.</summary>
    public bool AcceptUnknownManufacturers { get; set; } = true;
    public AccessList Access { get; private set; }
    public string DataFolder { get; }

    public AcuEngine(string dataFolder)
    {
        DataFolder = dataFolder;
        _statePath = Path.Combine(dataFolder, "acu-site.json");
        _accessPath = Path.Combine(dataFolder, "access-list.json");
        _state = AcuState.Load(_statePath);
        Access = AccessList.Load(_accessPath);
    }

    // =========================================================================
    //  What the window shows
    // =========================================================================

    public bool HasSite => _state.HasSite;
    public string? SiteId => _state.SiteId;
    public string SiteName => _state.SiteName;
    public long TrustEpoch => _state.TrustEpoch;
    public string EndpointHost => _state.EndpointHost;
    public int ListenPort => _state.ListenPort;
    public IReadOnlyList<string> AcuNames => _state.AcuNames;
    public ulong GrantCounter => _state.GrantCounter;
    public bool Listening => _listener is not null;
    public IReadOnlyList<PairedReader> PairedReaders { get { lock (_lock) return _state.Readers.ToList(); } }
    public IReadOnlyList<ReaderSession> Sessions => _sessions.Values.OrderBy(s => s.ConnectedAt).ToList();
    public (int Facility, int Card, string Reader)? LastCard { get; private set; }

    // Loaded once and kept until the site changes.
    public X509Certificate2? SiteRoot => Cached(ref _cRoot, _state.RootPfxB64);
    public X509Certificate2? AcuCertificate => Cached(ref _cAcu, _state.AcuPfxB64);
    public X509Certificate2? SignerCertificate => Cached(ref _cSigner, _state.SignerPfxB64);
    private (string? b64, X509Certificate2? cert) _cRoot, _cAcu, _cSigner;
    private static X509Certificate2? Cached(ref (string? b64, X509Certificate2? cert) slot, string? b64)
    {
        if (b64 is null) return null;
        if (slot.b64 != b64 || slot.cert is null) slot = (b64, DemoPki.ImportWithKey(Convert.FromBase64String(b64)));
        return slot.cert;
    }

    public string SecretsText()
    {
        if (!HasSite) return L.T("(no site yet)");
        string K(X509Certificate2 c) { using var k = c.GetECDsaPrivateKey(); return k is null ? "-" : Convert.ToHexString(DemoPki.ExportPrivateKeyPkcs8(k)).ToLowerInvariant(); }
        return L.F("Site root private key (PKCS#8): {0}\nACU TLS private key (PKCS#8): {1}\nGrant signer private key (PKCS#8): {2}", K(SiteRoot!), K(AcuCertificate!), K(SignerCertificate!));
    }

    // =========================================================================
    //  Creating the demo site
    // =========================================================================

    /// <summary>
    /// Create a new site: root, ACU certificate (for the given names) and grant signer.
    /// Existing paired readers are forgotten, because they trust the old root.
    /// </summary>
    public void CreateSite(string siteName, IEnumerable<string> acuNames, string endpointHost, int port = SessionTls.Port)
    {
        Stop();
        var names = acuNames.Select(n => n.Trim()).Where(n => n.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (!names.Contains(endpointHost, StringComparer.OrdinalIgnoreCase)) names.Add(endpointHost);
        var root = DemoPki.CreateRoot($"{siteName} root CA");
        var acu = DemoPki.IssueAcuCertificate(root, names);
        var signer = DemoPki.IssueGrantSigner(root);
        lock (_lock)
        {
            _state = new AcuState
            {
                SiteId = Guid.NewGuid().ToString("D"), SiteName = siteName, TrustEpoch = 1,
                RootPfxB64 = Convert.ToBase64String(DemoPki.ExportWithKey(root)),
                AcuPfxB64 = Convert.ToBase64String(DemoPki.ExportWithKey(acu)),
                SignerPfxB64 = Convert.ToBase64String(DemoPki.ExportWithKey(signer)),
                AcuNames = names, EndpointHost = endpointHost, ListenPort = port,
            };
            Save();
        }
        Log(ActivityKind.Good, L.F("Demo site \"{0}\" created. Root {1}, ACU certificate for {2}, grant signer {3}.", siteName, DemoPki.Fingerprint(root), string.Join(", ", names), DemoPki.Fingerprint(signer)), "site");
        Changed();
    }

    /// <summary>Names a reader on this network can use to reach this computer.</summary>
    public static List<string> SuggestedNames()
    {
        var list = new List<string> { "localhost", "127.0.0.1", Environment.MachineName };
        try
        {
            foreach (var a in Dns.GetHostAddresses(Dns.GetHostName()))
                if (a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a)) list.Add(a.ToString());
        }
        catch { }
        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    // =========================================================================
    //  Listening for readers
    // =========================================================================

    public void Start()
    {
        if (_listener is not null) return;
        if (!HasSite) { Log(ActivityKind.Warning, L.T("Create a demo site first.")); return; }
        try { _listener = new TcpListener(IPAddress.Any, _state.ListenPort); _listener.Start(); }
        catch (SocketException e) { _listener = null; Log(ActivityKind.Error, L.F("Cannot listen on port {0}: {1}", _state.ListenPort, e.Message)); return; }
        _runCts = new CancellationTokenSource();
        Log(ActivityKind.Info, L.F("ACU listening on port {0} ({1} TLS engine). Platform: {2}", _state.ListenPort, TlsEngine, PlatformInfo.Describe()));
        _ = Task.Run(() => AcceptLoopAsync(_listener, _runCts.Token));
        Changed();
    }

    public void Stop()
    {
        _runCts?.Cancel(); _runCts = null;
        try { _listener?.Stop(); } catch { }
        if (_listener is not null) Log(ActivityKind.Info, L.T("ACU stopped listening."));
        _listener = null;
        foreach (var s in _sessions.Values) Drop(s);
        Changed();
    }

    private async Task AcceptLoopAsync(TcpListener l, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient tcp;
            try { tcp = await l.AcceptTcpClientAsync(ct); } catch { break; }
            tcp.NoDelay = true;
            _ = Task.Run(() => HandleReaderAsync(tcp, ct));
        }
    }

    private async Task HandleReaderAsync(TcpClient tcp, CancellationToken ct)
    {
        string addr = tcp.Client.RemoteEndPoint?.ToString() ?? "?";
        Stream stream; TlsInfo info;
        try
        {
            (stream, info) = await Transport.TlsEngine.AcceptAsync(TlsEngine, tcp, AcuCertificate!, SiteRoot!, ct);
        }
        catch (Exception e)
        {
            Log(ActivityKind.Refused, L.F("Connection from {0} refused at TLS: {1}", addr, e.Message), "tls");
            tcp.Dispose();
            return;
        }
        Guid certId = info.PeerDeviceId ?? Guid.Empty;
        PairedReader? reader;
        lock (_lock) reader = _state.Readers.FirstOrDefault(r => r.DeviceId == certId);
        string name = reader?.Name ?? certId.ToString()[..8];
        Log(ActivityKind.Good, L.F("TLS session with {0} from {1}: {2}", name, addr, info), "tls", peer: name);

        var s = new ReaderSession { DeviceId = certId, Name = name, Address = addr, Tls = info };
        var ch = new MessageChannel(stream, e => Activity?.Invoke(e), "session", name) { OurMaxMsg = 1024, OurMaxAssembled = 8192 };
        s.Channel = ch;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, s.Cts.Token);
        try
        {
            // ---- the first message must be hello, within 5 seconds (spec 4.7) ----
            HpspMessage? hello;
            using (var helloCts = CancellationTokenSource.CreateLinkedTokenSource(linked.Token))
            {
                helloCts.CancelAfter(HelloTimeout);
                using var cut = helloCts.Token.Register(ch.Dispose);   // closing the stream ends a read that is waiting
                hello = await ch.ReceiveAsync(helloCts.Token);
            }
            if (hello is not { Type: "cmd", Op: "hello" } || hello.Id is not long hid) { Log(ActivityKind.Refused, L.T("First message was not hello; closing."), peer: name); return; }
            if (!Guid.TryParse(hello.GetString("device_id"), out var helloId) || helloId != certId)
            { await ch.SendAsync(HpspMessage.Err("hello", hid, "forbidden", "device_id does not match the certificate"), linked.Token); Log(ActivityKind.Refused, L.T("hello device_id does not match the TLS certificate."), peer: name); return; }
            if (reader is null || reader.Removed)
            { await ch.SendAsync(HpspMessage.Err("hello", hid, "unauthorized", "reader not paired with this ACU or removed"), linked.Token); Log(ActivityKind.Refused, L.F("Reader {0} is not paired here or was removed.", certId), peer: name); return; }

            // Check the hello BEFORE it replaces any existing session, so a bad hello cannot
            // knock a good session offline.
            if (hello.GetBytes("session_nonce_b64") is not { Length: 32 } nonce)
            { await ch.SendAsync(HpspMessage.Err("hello", hid, "bad_request", "session value must be 32 bytes"), linked.Token); return; }
            if (hello.GetLong("grant_floor") is not long floor || floor < 0 || floor > MaxGrantFloor)
            { await ch.SendAsync(HpspMessage.Err("hello", hid, "bad_request", "grant_floor missing or out of range"), linked.Token); return; }

            // Replace any older session from the same reader.
            if (_sessions.TryRemove(certId, out var old)) { s.PreviousSessionNonce = old.SessionNonce; Drop(old); }
            else s.PreviousSessionNonce = _lastNonces.GetValueOrDefault(certId);
            s.SessionNonce = nonce;
            s.GrantFloor = (ulong)floor;
            s.MonoNow = hello.GetLong("mono_now") ?? 0; s.MonoAt = DateTime.UtcNow;
            _sessions[certId] = s;

            // ---- where should the reader resume its events? ----
            var es = hello.GetMap("event_seq");
            long first = es?.GetValueOrDefault("first") as long? ?? 0, last = es?.GetValueOrDefault("last") as long? ?? 0;
            long resume = Math.Max(first, reader.LastAckedSeq + 1);
            if (first > reader.LastAckedSeq + 1 && reader.LastAckedSeq > 0)
                Log(ActivityKind.Warning, L.F("Events {0} to {1} are no longer held by the reader (a gap after a restart is normal).", reader.LastAckedSeq + 1, first - 1), peer: name);
            await ch.SendAsync(HpspMessage.Rsp("hello", hid, new()
            {
                ["version"] = 1L, ["max_msg"] = 1024L, ["max_assembled"] = 8192L, ["heartbeat_s"] = (long)HeartbeatSeconds,
                ["resume_from"] = resume, ["time"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"), ["trust_epoch"] = _state.TrustEpoch,
            }), linked.Token);
            if (hello.GetLong("max_msg") is long mm) ch.PeerMaxMsg = (int)Math.Clamp(mm, 1024, 65536);
            if (hello.GetLong("max_assembled") is long ma) ch.PeerMaxAssembled = (int)Math.Clamp(ma, 4096, 1 << 20);
            s.HelloDone = true;
            Log(ActivityKind.Good, L.F("Reader {0} is online. Session value {1}, grant floor {2}.", name, MessageSummary.Short(s.SessionNonce), s.GrantFloor), peer: name);
            Changed();

            // ---- bring the reader's trust list up to date ----
            if ((hello.GetLong("trust_epoch") ?? 0) < _state.TrustEpoch) await SendTrustUpdateAsync(s, linked.Token);

            // ---- main loop ----
            while (!linked.IsCancellationRequested)
            {
                var m = await ch.ReceiveAsync(linked.Token);
                if (m is null) { Log(ActivityKind.Warning, L.F("Reader {0} closed the session.", name), peer: name); break; }
                s.LastHeard = DateTime.Now;
                await HandleFromReaderAsync(s, m, linked.Token);
                Changed();
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception e) when (e is IOException or Cbor.HpspCborException or ObjectDisposedException or InvalidOperationException)
        {
            if (!linked.IsCancellationRequested) Log(ActivityKind.Warning, L.F("Session with {0} ended: {1}", name, e.Message), peer: name);
        }
        finally
        {
            if (_sessions.TryGetValue(certId, out var cur) && cur == s) { _sessions.TryRemove(certId, out _); _lastNonces[certId] = s.SessionNonce; }
            ch.Dispose();
            Log(ActivityKind.Info, L.F("Reader {0} is offline.", name), peer: name);
            Changed();
        }
    }

    private readonly ConcurrentDictionary<Guid, byte[]?> _lastNonces = new();

    private async Task SendTrustUpdateAsync(ReaderSession s, CancellationToken ct)
    {
        List<object?> revoked;
        lock (_lock) revoked = _state.Readers.Where(r => r.Removed && r.SiteCertSerialHex.Length > 0).Select(r => (object?)Convert.FromHexString(r.SiteCertSerialHex)).ToList();
        await s.Channel!.SendAsync(HpspMessage.Cmd("trust_update", s.NextId++, new()
        {
            ["epoch"] = _state.TrustEpoch,
            ["revoked_hex"] = revoked,
            ["signers_b64"] = new List<object?> { SignerCertificate!.RawData },
        }), ct, L.T("the reader's trust list is out of date"));
    }

    // =========================================================================
    //  Messages from a reader
    // =========================================================================

    private async Task HandleFromReaderAsync(ReaderSession s, HpspMessage m, CancellationToken ct)
    {
        var ch = s.Channel!;
        switch (m.Type)
        {
            case "cmd" when m.Op == "heartbeat":
                if (m.GetLong("mono_now") is long mn) { s.MonoNow = mn; s.MonoAt = DateTime.UtcNow; }
                await ch.SendAsync(HpspMessage.Rsp("heartbeat", m.Id ?? 0), ct);
                return;
            case "cmd":
                await ch.SendAsync(HpspMessage.Err(m.Op ?? "", m.Id, "unsupported"), ct);
                return;
            case "rsp" when m.Op == "unlock":
                s.DoorState = m.GetString("state") ?? s.DoorState;
                Log(ActivityKind.Good, L.F("{0}: door {1}.", s.Name, s.DoorState), peer: s.Name);
                return;
            case "err":
                Log(ActivityKind.Refused, L.F("{0} refused {1}: {2}", s.Name, m.Op, m.GetString("code")) + (m.GetString("message") is string msg ? " (" + msg + ")" : ""), peer: s.Name);
                return;
            case "rsp": return;
            case "evt": break;
            default: throw new IOException(L.T("unexpected message type ") + m.Type);
        }

        // ---- an event: store it (here: log it), acknowledge it, then act on it ----
        s.EventsReceived++;
        long seq = m.Seq ?? 0;
        s.LastSeq = seq;
        bool duplicate;
        lock (_lock)
        {
            var r = _state.Readers.FirstOrDefault(x => x.DeviceId == s.DeviceId);
            duplicate = r is not null && seq <= r.LastAckedSeq;
            if (r is not null && !duplicate) { r.LastAckedSeq = seq; Save(); }
        }
        await ch.SendAsync(HpspMessage.Ack(seq), ct);
        // An event we have already stored (a resend after a lost acknowledgment) is
        // acknowledged again but never acted on twice (spec 6.2).
        if (duplicate) { Log(ActivityKind.Info, L.F("{0}: event {1} already received; acknowledged again, not acted on.", s.Name, seq), peer: s.Name); return; }

        switch (m.Op)
        {
            case "credential": await OnCredentialAsync(s, m, ct); break;
            case "lock_state":
                s.DoorState = m.GetString("state") ?? s.DoorState;
                break;
            case "security_event":
                Log(ActivityKind.Refused, L.F("SECURITY EVENT from {0}: {1} {2}", s.Name, m.GetString("kind"), m.GetString("reason") ?? m.GetString("source") ?? ""), peer: s.Name);
                break;
        }
    }

    // =========================================================================
    //  Access decisions
    // =========================================================================

    private async Task OnCredentialAsync(ReaderSession s, HpspMessage m, CancellationToken ct)
    {
        // Decode the card from the raw bits, which are authoritative (fc/id in the event are only
        // a convenience). Bits that fail the parity check are a bad read: no access decision.
        int fc, card;
        if (!(m.GetBytes("raw_hex") is byte[] raw && m.GetLong("bits") is long bits && Wiegand26.TryDecode(raw, (int)bits, out fc, out card)))
        { Log(ActivityKind.Warning, L.F("{0}: card format not recognized.", s.Name), peer: s.Name); return; }
        LastCard = (fc, card, s.Name);

        // Never act on a stale card read (for example one replayed after a long network outage).
        // The age is worked out on the reader's own monotonic clock. A NEGATIVE age means the
        // read is from before the reader's clock restarted (a reboot), so it is just as stale.
        long ageMs = s.MonoNow + (long)(DateTime.UtcNow - s.MonoAt).TotalMilliseconds - (m.Mono ?? 0);
        if (ageMs < -2000) ageMs = long.MaxValue;
        if (ageMs > CredentialMaxAgeMs)
        {
            Log(ActivityKind.Warning, L.F("{0}: card FC {1} / {2} is {3:0.#} s old. Logged only; no door opened (limit {4} s).", s.Name, fc, card, ageMs == long.MaxValue ? double.PositiveInfinity : ageMs / 1000.0, CredentialMaxAgeMs / 1000), peer: s.Name);
            return;
        }

        var entry = Access.Find(fc, card);
        bool allow = entry?.Allowed ?? Access.AllowUnknownCards;
        string who = entry is null ? L.T("unknown card") : $"\"{entry.Name}\"";
        if (!allow)
        {
            string why = entry is null ? L.T("not in the access list") : L.T("access disabled for this card");
            Log(ActivityKind.Refused, L.F("ACCESS DENIED at {0}: FC {1}, card {2} ({3}, {4}). No grant is made.", s.Name, fc, card, who, why), "access", peer: s.Name);
            await SetLedAsync(s, "red", "blink", 200, 200, 3, ct);
            return;
        }
        Log(ActivityKind.Good, L.F("ACCESS GRANTED at {0}: FC {1}, card {2} ({3}). Asking the grant signer for a grant.", s.Name, fc, card, who), "access", peer: s.Name);
        await SendUnlockAsync(s, Access.UnlockMs, ct, "card " + card);
        await SetLedAsync(s, "green", "on", Access.UnlockMs, 0, 1, ct);
    }

    /// <summary>Sign a valid grant for this reader and session, and send unlock (also used by "Manual unlock").</summary>
    public async Task SendUnlockAsync(ReaderSession s, int durationMs, CancellationToken ct = default, string? why = null)
    {
        var data = new Dictionary<string, object?>
        {
            ["cid"] = (long)ReaderEngine.StrikeCid, ["mode"] = "timed", ["duration_ms"] = (long)durationMs,
            ["grant"] = SignGrant(s, s.SessionNonce!, (uint)durationMs, DateTimeOffset.UtcNow.AddSeconds(30)).ToMap(),
        };
        s.LastUnlockData = data;
        await s.Channel!.SendAsync(HpspMessage.Cmd("unlock", s.NextId++, data), ct, why);
    }

    /// <summary>Ask the grant signer for a grant. The counter always goes up and is saved first.</summary>
    private Grant SignGrant(ReaderSession s, byte[] nonce, uint durationMs, DateTimeOffset expires, ECDsa? otherKey = null)
    {
        ulong counter;
        lock (_lock)
        {
            // Counters are per reader: above everything already sent to it, and at least the
            // floor it reported in hello. Saved before the grant is used.
            var r = _state.Readers.FirstOrDefault(x => x.DeviceId == s.DeviceId && !x.Removed)
                ?? throw new InvalidOperationException(L.T("this reader has been removed"));
            counter = Math.Max(r.GrantCounter + 1, s.GrantFloor);
            r.GrantCounter = counter;
            _state.GrantCounter++;
            Save();
        }
        using var key = otherKey is null ? SignerCertificate!.GetECDsaPrivateKey()! : null;
        var signer = new GrantSigner(otherKey ?? key!);
        var g = signer.Sign(s.DeviceId, nonce, counter, ReaderEngine.StrikeCid, GrantAction.TimedUnlock, 0, durationMs, (ulong)expires.ToUnixTimeSeconds());
        Changed();
        return g;
    }

    private async Task SetLedAsync(ReaderSession s, string color, string pattern, int onMs, int offMs, int count, CancellationToken ct)
    {
        await s.Channel!.SendAsync(HpspMessage.Cmd("set_indicator", s.NextId++, new()
        { ["cid"] = (long)ReaderEngine.LedCid, ["pattern"] = pattern, ["color"] = color, ["on_ms"] = (long)onMs, ["off_ms"] = (long)offMs, ["count"] = (long)count }), ct);
    }

    public async Task SendLockAsync(ReaderSession s) =>
        await s.Channel!.SendAsync(HpspMessage.Cmd("lock", s.NextId++, new() { ["cid"] = (long)ReaderEngine.StrikeCid }));

    // =========================================================================
    //  Readers and the access list
    // =========================================================================

    public void RemoveReader(Guid id)
    {
        lock (_lock)
        {
            var r = _state.Readers.FirstOrDefault(x => x.DeviceId == id);
            if (r is null) return;
            r.Removed = true;
            _state.TrustEpoch++;           // revocation is distributed with a new trust epoch
            Save();
        }
        // Tell the readers that are online now about the new epoch and the revocation.
        foreach (var other in _sessions.Values.Where(x => x.DeviceId != id && x.HelloDone))
            _ = Task.Run(async () => { try { await SendTrustUpdateAsync(other, other.Cts.Token); } catch { } });
        if (_sessions.TryRemove(id, out var s)) Drop(s);
        Log(ActivityKind.Warning, L.F("Reader {0} removed. Its certificate is revoked (trust epoch {1}); it will be refused if it connects.", id, _state.TrustEpoch));
        Changed();
    }

    /// <summary>
    /// Put the ACU back to how it was before first use: no site, no keys, no paired readers and an empty
    /// access list. (The window's language and TLS-engine choices are kept; they are not ACU state.)
    /// </summary>
    public void FactoryReset()
    {
        Stop();                                  // closes every reader session and the listener
        lock (_lock)
        {
            _state = new AcuState();
            _cRoot = _cAcu = _cSigner = default;
            Access = new AccessList();
            _lastNonces.Clear();
            LastCard = null;
            Save();
            Access.Save(_accessPath);
        }
        Log(ActivityKind.Warning, L.T("Factory reset: the site, all keys, paired readers and the access list were removed. Create a demo site to start again."));
        Changed();
    }

    public void SaveAccessList() { Access.Save(_accessPath); Changed(); }

    private void Drop(ReaderSession s)
    {
        try { s.Cts.Cancel(); } catch { }
        s.Channel?.Dispose();
    }

    private void Save() { lock (_lock) _state.Save(_statePath); }
    private void Changed() => StateChanged?.Invoke();
    private void Log(ActivityKind k, string text, string channel = "session", string? peer = null, string? detail = null, string? secret = null) =>
        Activity?.Invoke(new ActivityEntry { Kind = k, Summary = text, Channel = channel, Peer = peer, Detail = detail, SecretDetail = secret });

    public void Dispose() => Stop();
}
