// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/ReaderEngine.cs
//  Purpose: The simulated reader: identity, door, LED, card swipes and events.
//           (Sessions are in ReaderEngine.Session.cs, pairing in
//           ReaderEngine.Pairing.cs.)
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  This is a door reader with no screen: everything the Reader Simulator
//  window shows comes from here. The simulated device has three parts, each
//  with a component number (cid) as in the specification:
//
//      cid 0   the card reader       (reports "credential" events)
//      cid 2   the door strike       (opened only by "unlock" with a valid grant)
//      cid 6   the LED               (set by the ACU with "set_indicator")
//
//  Every event gets the next sequence number and is kept until the ACU
//  acknowledges it, so nothing is lost if the network drops.
// =============================================================================

using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hpsp.Core.BouncyCastle;
using Hpsp.Core.Cards;
using Hpsp.Core.Cbor;
using Hpsp.Core.Protocol;
using Hpsp.Core.Security;
using Hpsp.Core.Transport;
using Hpsp.Core.Localization;

namespace Hpsp.Core.Engine;

public sealed partial class ReaderEngine : IDisposable
{
    public const ushort ReaderCid = 0, StrikeCid = 2, LedCid = 6;
    public const string Manufacturer = "HPSP Demo", Product = "Reader Simulator", HwRev = "sim", FwVersion = "0.5.0-demo";

    private readonly string _statePath;
    private readonly object _lock = new();
    private readonly Stopwatch _mono = Stopwatch.StartNew();    // the device's monotonic clock
    private ReaderState _state;
    private GrantVerifier _grants;
    private long _seqNext;
    private string? _startupNote;
    private CancellationTokenSource? _runCts;

    /// <summary>Every log line for the activity window.</summary>
    public event Action<ActivityEntry>? Activity;
    /// <summary>Raised whenever something the window shows has changed.</summary>
    public event Action? StateChanged;

    // ---- settings ----
    public TlsEngineKind TlsEngine { get; set; } = TlsEngineKind.Windows;
    public int PairingPort { get; set; } = PairingTls.Port;
    public string DataFolder { get; }

    public ReaderEngine(string dataFolder)
    {
        DataFolder = dataFolder;
        _statePath = Path.Combine(dataFolder, "reader-state.json");
        _state = ReaderState.Load(_statePath);
        if (_state.DeviceId == Guid.Empty) CreateFactoryIdentity();
        // Card reads are never kept across a restart (spec 6.2): an old swipe replayed after a
        // reboot must not open a door, and its age can no longer be judged (the monotonic clock
        // starts again from zero). Other events (door state, security events) are kept.
        int dropped = _state.PendingEvents.RemoveAll(e => e.Op is "credential" or "keypad");
        if (dropped > 0) _startupNote = L.F("{0} card read(s) from before the restart were discarded (card reads are not kept across a restart).", dropped);
        _grants = NewVerifier();
        _seqNext = _state.SeqBlock + 256;               // a gap after every start is expected (spec 6.2)
        _state.SeqBlock = _seqNext;
        Save();
    }

    // =========================================================================
    //  What the window shows
    // =========================================================================

    public Guid DeviceId => _state.DeviceId;
    public string Serial => _state.Serial;
    public string SetupCode => Engine.SetupCode.Pretty(_state.SetupCode);
    public string QrText => Engine.SetupCode.QrText(_state.DeviceId, _state.SetupCode);
    public bool IsPaired => _state.IsPaired;
    public string? SiteId => _state.SiteId;
    public string? Endpoint => _state.IsPaired ? $"{_state.EndpointHost}:{_state.EndpointPort}" : null;
    public long TrustEpoch => _state.TrustEpoch;
    public int SignerCount => _state.SignerCertsB64.Count;
    public int PendingEventCount { get { lock (_lock) return _state.PendingEvents.Count; } }
    public long LastSeq => _seqNext - 1;
    public ulong GrantFloor => _grants.Floor;
    public ulong LastGrantCounter => _grants.LastCounter;
    public int FailedAttempts => _state.FailedAttempts;
    public bool LockedOut => _state.LockedOutUntilUtc is DateTime t && t > DateTime.UtcNow;
    public DateTime? LockedOutUntil => _state.LockedOutUntilUtc?.ToLocalTime();

    public bool DoorUnlocked { get; private set; }
    public DateTime? DoorRelocksAt { get; private set; }
    public string LedColor { get; private set; } = "off";
    public string LedPattern { get; private set; } = "off";
    public DateTime? LedUntil { get; private set; }

    /// <summary>Certificates, for the details panel.</summary>
    // Certificates are loaded once and kept (re-loaded only when the stored value changes),
    // so a reconnecting reader does not create new key objects on every attempt.
    public X509Certificate2 FactoryIdentity => Cached(ref _cFactory, _state.FactoryIdentityPfxB64, withKey: true)!;
    public X509Certificate2 ManufacturerCa => Cached(ref _cMfr, _state.ManufacturerCaB64, withKey: false)!;
    public X509Certificate2? SiteIdentity => Cached(ref _cSiteId, _state.SiteIdentityPfxB64, withKey: true);
    public X509Certificate2? SiteRoot => Cached(ref _cRoot, _state.SiteRootB64, withKey: false);
    private (string? b64, X509Certificate2? cert) _cFactory, _cMfr, _cSiteId, _cRoot;
    private static X509Certificate2? Cached(ref (string? b64, X509Certificate2? cert) slot, string? b64, bool withKey)
    {
        if (b64 is null) return null;
        if (slot.b64 == b64 && slot.cert is not null) return slot.cert;
        var bytes = Convert.FromBase64String(b64);
        slot = (b64, withKey ? DemoPki.ImportWithKey(bytes) : new X509Certificate2(bytes));
        return slot.cert;
    }

    /// <summary>Secrets for the "Show secrets (demo only)" panel.</summary>
    public string SecretsText()
    {
        var lines = new List<string>
        {
            L.F("Setup code: {0}", SetupCode),
            L.F("Verifier w0: {0}", _state.W0Hex),
            L.F("Verifier L:  {0}", _state.LHex),
            L.F("Salt: {0}, iterations {1}", _state.SaltHex, _state.Iterations),
            L.T("Factory identity private key (PKCS#8): ") + KeyHex(FactoryIdentity),
        };
        if (SiteIdentity is X509Certificate2 s) lines.Add(L.T("Site identity private key (PKCS#8): ") + KeyHex(s));
        if (_sessionNonce is not null) lines.Add(L.T("Current session value: ") + Convert.ToHexString(_sessionNonce).ToLowerInvariant());
        return string.Join("\n", lines);
    }

    private static string KeyHex(X509Certificate2 c)
    {
        using var k = c.GetECDsaPrivateKey();
        return k is null ? "-" : Convert.ToHexString(DemoPki.ExportPrivateKeyPkcs8(k)).ToLowerInvariant();
    }

    // =========================================================================
    //  Factory identity: created once, as if at manufacture
    // =========================================================================

    /// <summary>Give this simulated reader a brand-new identity and setup code ("a new device out of the box").</summary>
    public void NewDevice()
    {
        bool wasRunning = _runCts is not null;
        Stop();
        lock (_lock) { _state = new ReaderState(); CreateFactoryIdentity(); _grants = NewVerifier(); Save(); }
        Info(L.T("A new simulated device was created: new device ID, factory identity and setup code."));
        if (wasRunning) Start();      // the "power comes back on"
        Changed();
    }

    private void CreateFactoryIdentity()
    {
        _state.DeviceId = Guid.NewGuid();
        _state.Serial = "SIM-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(3));
        // The factory: a manufacturer CA signs this device's identity certificate.
        // (In the demo every simulated device gets its own manufacturer CA; the ACU
        //  shows its fingerprint and accepts it for the demo.)
        var mfr = DemoPki.CreateRoot("HPSP Demo Manufacturer CA", 20);
        var idev = DemoPki.IssueFactoryIdentity(mfr, _state.DeviceId, _state.Serial);
        _state.ManufacturerCaB64 = Convert.ToBase64String(mfr.RawData);
        _state.FactoryIdentityPfxB64 = Convert.ToBase64String(DemoPki.ExportWithKey(idev));
        // The setup code, and the SPAKE2+ verifier made from it at the factory.
        _state.SetupCode = Engine.SetupCode.NewCode();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        var (w0, w1) = Spake2Plus.DeriveW0W1(_state.SetupCode, salt, _state.Iterations);
        _state.SaltHex = Convert.ToHexString(salt);
        _state.W0Hex = Convert.ToHexString(w0);
        _state.LHex = Convert.ToHexString(Spake2Plus.ComputeL(w1));
    }

    /// <summary>
    /// Factory reset: forget the site (certificate, trust, events) but keep the factory
    /// identity and setup code, exactly like pressing reset on a real reader.
    /// </summary>
    public void FactoryReset()
    {
        bool wasRunning = _runCts is not null;
        Stop();
        lock (_lock)
        {
            _state.SiteId = null; _state.SiteRootB64 = null; _state.EndpointHost = null; _state.SiteIdentityPfxB64 = null;
            _state.SignerCertsB64.Clear(); _state.RevokedSerialsHex.Clear(); _state.TrustEpoch = 0;
            _state.PendingEvents.Clear(); _state.FailedAttempts = 0; _state.LockedOutUntilUtc = null; _state.LockoutCount = 0;
            _grants = NewVerifier();
            Save();
        }
        SetDoor(false, "restart");
        Info(L.T("Factory reset: site removed. The reader is unpaired and keeps its factory identity and setup code."));
        if (wasRunning) Start();
        Changed();
    }

    // =========================================================================
    //  Running
    // =========================================================================

    /// <summary>Start the reader: report a boot event and, if paired, connect to the ACU.</summary>
    public void Start()
    {
        if (_runCts is not null) return;
        _runCts = new CancellationTokenSource();
        // Outputs are made secure as soon as the "firmware" runs (spec 5.15).
        SetDoor(false, null);
        AddEvent("boot", 1, new() { ["reason"] = "power_on", ["seq_base"] = _seqNext, ["fw_version"] = FwVersion });
        _ = Task.Run(() => SessionLoopAsync(_runCts.Token));
        Info(L.F("Reader started. Platform: {0}", PlatformInfo.Describe()));
        if (_startupNote is not null) { Warn(_startupNote); _startupNote = null; }
    }

    public void Stop()
    {
        _runCts?.Cancel();
        _runCts = null;
        DropSession(L.T("reader stopped"));
        ClosePairingWindow();
    }

    // =========================================================================
    //  Cards
    // =========================================================================

    /// <summary>Simulate a 26-bit card swipe.</summary>
    public void SwipeCard(int facility, int card)
    {
        bool[] bits = Wiegand26.ToBits(facility, card);
        byte[] raw = Wiegand26.Pack(bits);
        Info(L.F("Card swiped: FC {0}, card {1}. 26 bits: {2} = {3}", facility, card, Wiegand26.Describe(bits), Convert.ToHexString(raw).ToLowerInvariant()), "card");
        AddEvent("credential", 2, new()
        {
            ["cid"] = (long)ReaderCid, ["tech"] = "prox", ["bits"] = 26L, ["raw_hex"] = raw,
            ["fc"] = (long)facility, ["id"] = (long)card, ["secure_read"] = false,
        });
    }

    // =========================================================================
    //  Door strike and LED
    // =========================================================================

    private int _doorGeneration;

    private void SetDoor(bool unlocked, string? cause, uint durationMs = 0)
    {
        int gen;
        lock (_lock)
        {
            bool changed = DoorUnlocked != unlocked;
            DoorUnlocked = unlocked;
            DoorRelocksAt = unlocked && durationMs > 0 ? DateTime.Now.AddMilliseconds(durationMs) : null;
            gen = ++_doorGeneration;
            if (!changed && cause is not null && cause != "command") cause = null;
        }
        if (cause is not null)
            AddEvent("lock_state", 2, new() { ["cid"] = (long)StrikeCid, ["state"] = unlocked ? "unlocked" : "locked", ["cause"] = cause });
        if (unlocked && durationMs > 0)
        {
            // A timed unlock runs to its end, with or without a session (spec 5.15).
            _ = Task.Delay((int)durationMs).ContinueWith(_ =>
            {
                lock (_lock) if (gen != _doorGeneration || !DoorUnlocked) return;
                SetDoor(false, "timeout");
                Log(ActivityKind.Info, L.T("Door re-secured: the timed unlock ended."), "door");
            });
        }
        Changed();
    }

    private void SetLed(string color, string pattern, int? forMs)
    {
        LedColor = color; LedPattern = pattern;
        LedUntil = forMs is int ms && ms > 0 ? DateTime.Now.AddMilliseconds(ms) : null;
        Changed();
    }

    // =========================================================================
    //  Events: numbered, kept until acknowledged, replayed after a reconnect
    // =========================================================================

    private void AddEvent(string op, int priority, Dictionary<string, object?> data)
    {
        HpspMessage m;
        lock (_lock)
        {
            long seq = _seqNext++;
            if (_seqNext >= _state.SeqBlock + 256) _state.SeqBlock = _seqNext;      // reserve the next block of numbers
            m = HpspMessage.Evt(op, seq, Mono, NowIso(), data);
            _state.PendingEvents.Add(new StoredEvent { Seq = seq, Op = op, Priority = priority, CborB64 = Convert.ToBase64String(m.Encode()) });
            // Bounded buffer: drop the oldest lowest-priority event if full (spec 6.2).
            if (_state.PendingEvents.Count > 64)
            {
                var victim = _state.PendingEvents.Where(e => e.Priority < 3).OrderBy(e => e.Priority).ThenBy(e => e.Seq).FirstOrDefault();
                if (victim is not null) { _state.PendingEvents.Remove(victim); Warn(L.F("Event buffer full: dropped event seq {0} ({1}).", victim.Seq, victim.Op)); }
            }
            Save();
        }
        Changed();
        _ = SendEventIfConnectedAsync(m);
    }

    private void Acknowledge(long seq)
    {
        lock (_lock)
        {
            int before = _state.PendingEvents.Count;
            _state.PendingEvents.RemoveAll(e => e.Seq <= seq);
            if (_state.PendingEvents.Count != before) Save();
        }
        Changed();
    }

    // =========================================================================
    //  Helpers
    // =========================================================================

    private long Mono => _mono.ElapsedMilliseconds;
    private TimeSpan? _clockOffset;        // controller time minus local time, once known
    private DateTimeOffset? Now => _clockOffset is TimeSpan o ? DateTimeOffset.UtcNow + o : null;
    private string? NowIso() => Now?.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");

    private GrantVerifier NewVerifier()
    {
        var v = new GrantVerifier(_state.GrantBlock);
        v.SetSigners(TrustedSigners());
        return v;
    }

    /// <summary>
    /// The stored grant signers that still pass every check (issued by our site root for grant
    /// signing, in date, not revoked). Re-checked at every start, not just when received.
    /// </summary>
    private List<TrustedSigner> TrustedSigners()
    {
        var list = new List<TrustedSigner>();
        foreach (var b in _state.SignerCertsB64)
        {
            byte[] der = Convert.FromBase64String(b);
            if (SignerProblem(der, _state.RevokedSerialsHex) is not null) continue;
            using var c = new X509Certificate2(der);
            list.Add(new TrustedSigner(DemoPki.SpkiHash(c), c.PublicKey.ExportSubjectPublicKeyInfo(), false));
        }
        return list;
    }

    /// <summary>Why a grant-signer certificate must not be trusted, or null if it is fine.</summary>
    private string? SignerProblem(byte[] der, List<string> revokedSerials)
    {
        if (SiteRoot is not { } root) return "no site root";
        using var c = DemoPki.TryLoad(der);
        if (c is null) return "not a certificate";
        if (revokedSerials.Contains(c.SerialNumber.ToLowerInvariant())) return "certificate is revoked";
        return DemoPki.CheckChain(c, root, DemoPki.GrantSigning);
    }

    private void Save() { lock (_lock) _state.Save(_statePath); }
    private void Changed() => StateChanged?.Invoke();
    private void Log(ActivityKind k, string text, string channel = "session", string? detail = null, string? secret = null) =>
        Activity?.Invoke(new ActivityEntry { Kind = k, Summary = text, Channel = channel, Detail = detail, SecretDetail = secret });
    private void Info(string text, string channel = "session") => Log(ActivityKind.Info, text, channel);
    private void Warn(string text, string channel = "session") => Log(ActivityKind.Warning, text, channel);

    public void Dispose() { Stop(); }
}
