// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/ReaderState.cs
//  Purpose: What a simulated reader remembers between runs.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  A real reader keeps a few things in protected non-volatile memory: its
//  factory identity, its setup-code verifier, the site it belongs to, its site
//  certificate, the grant signers it trusts, and two counters. The simulated
//  reader keeps the same things in a JSON file in its data folder.
//
//  DEMO ONLY: private keys are stored in that file in plain form. A real
//  device keeps them in a secure element or protected memory, and never
//  lets them out.
// =============================================================================

using System.Text.Json;

namespace Hpsp.Core.Engine;

public sealed class ReaderState
{
    // ---- factory identity (set at "manufacture", kept through a factory reset) ----
    public Guid DeviceId { get; set; }
    public string Serial { get; set; } = "";
    /// <summary>The printed setup code. A real device stores only the verifier (W0, L), not the code;
    /// the demo keeps the code too so it can show it on screen, as the printed label would.</summary>
    public string SetupCode { get; set; } = "";
    public string SaltHex { get; set; } = "";
    public int Iterations { get; set; } = 100_000;
    public string W0Hex { get; set; } = "";
    public string LHex { get; set; } = "";
    public string ManufacturerCaB64 { get; set; } = "";     // public certificate only
    public string FactoryIdentityPfxB64 { get; set; } = ""; // IDevID with its private key (DEMO ONLY)

    // ---- pairing attempt limits (spec 5.6, "Limits") ----
    public int FailedAttempts { get; set; }
    public DateTime? LockedOutUntilUtc { get; set; }
    /// <summary>How many lock-outs so far; each one lasts twice as long (5 min, 10, 20, 40, then 60).</summary>
    public int LockoutCount { get; set; }

    // ---- site (set by pairing, cleared by a factory reset) ----
    public string? SiteId { get; set; }
    public string? SiteRootB64 { get; set; }
    public string? EndpointHost { get; set; }
    public int EndpointPort { get; set; } = 7500;
    public long TrustEpoch { get; set; }
    public string? SiteIdentityPfxB64 { get; set; }          // LDevID with its private key (DEMO ONLY)
    public List<string> SignerCertsB64 { get; set; } = new();
    public List<string> RevokedSerialsHex { get; set; } = new();

    // ---- counters kept in non-volatile memory (spec 5.8 and 6.2) ----
    public ulong GrantBlock { get; set; }
    public long SeqBlock { get; set; }

    // ---- events not yet acknowledged (critical ones MUST survive power loss) ----
    public List<StoredEvent> PendingEvents { get; set; } = new();

    public bool IsPaired => SiteIdentityPfxB64 is not null && SiteRootB64 is not null && EndpointHost is not null;

    public static ReaderState Load(string path) => File.Exists(path)
        ? JsonSerializer.Deserialize<ReaderState>(File.ReadAllText(path)) ?? new ReaderState()
        : new ReaderState();

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, path, overwrite: true);   // write-then-rename, so a crash never leaves half a file
    }
}

/// <summary>An event waiting for acknowledgment, kept as the exact CBOR that was (or will be) sent.</summary>
public sealed class StoredEvent
{
    public long Seq { get; set; }
    public string Op { get; set; } = "";
    public int Priority { get; set; }          // 0 low, 1 normal, 2 high, 3 critical
    public string CborB64 { get; set; } = "";
}
