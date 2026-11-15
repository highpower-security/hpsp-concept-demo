// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/AcuState.cs
//  Purpose: What the simulated ACU remembers: its site, its keys, the readers
//           it has paired, and the access list.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  "Create demo site" makes four things the ACU keeps:
//    - the site root certificate and key (the site's badge office),
//    - the ACU's own TLS certificate,
//    - the grant signer's certificate and key,
//    - a site ID and a trust epoch (a version number for the site's trust list).
//  It also remembers each paired reader and the last event number it has
//  safely stored from each, so a reconnecting reader resumes in the right place.
//
//  DEMO ONLY: all keys are kept in plain files. On a real site the root key is
//  kept offline and the grant signer key in a hardware security module, apart
//  from the ACU.
// =============================================================================

using System.Text.Json;

namespace Hpsp.Core.Engine;

public sealed class AcuState
{
    public string? SiteId { get; set; }
    public string SiteName { get; set; } = "HPSP Demo Site";
    public long TrustEpoch { get; set; } = 1;
    public string? RootPfxB64 { get; set; }
    public string? AcuPfxB64 { get; set; }
    public string? SignerPfxB64 { get; set; }
    /// <summary>The host names and addresses in the ACU certificate; readers must dial one of these.</summary>
    public List<string> AcuNames { get; set; } = new();
    /// <summary>The host name or address readers are told to dial (must be one of AcuNames).</summary>
    public string EndpointHost { get; set; } = "localhost";
    public int ListenPort { get; set; } = 7500;
    /// <summary>How many grants this site has signed (for display).</summary>
    public ulong GrantCounter { get; set; }
    public List<PairedReader> Readers { get; set; } = new();
    /// <summary>Manufacturer roots seen during pairing (demo: accepted on first use).</summary>
    public List<string> KnownManufacturersB64 { get; set; } = new();

    public bool HasSite => SiteId is not null && RootPfxB64 is not null && AcuPfxB64 is not null && SignerPfxB64 is not null;

    public static AcuState Load(string path) => File.Exists(path)
        ? JsonSerializer.Deserialize<AcuState>(File.ReadAllText(path)) ?? new AcuState() : new AcuState();

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, path, overwrite: true);
    }
}

public sealed class PairedReader
{
    public Guid DeviceId { get; set; }
    public string Name { get; set; } = "";
    public string Serial { get; set; } = "";
    public DateTime PairedUtc { get; set; }
    public string FactoryFingerprint { get; set; } = "";
    public string SiteCertFingerprint { get; set; } = "";
    public string SiteCertSerialHex { get; set; } = "";
    /// <summary>
    /// The last grant counter used for this reader. Kept per reader, so one reader reporting
    /// a strange grant_floor cannot disturb grants for any other reader.
    /// </summary>
    public ulong GrantCounter { get; set; }
    /// <summary>The highest event number stored from this reader (acknowledged).</summary>
    public long LastAckedSeq { get; set; }
    /// <summary>A removed reader is refused at hello and its certificate is listed as revoked.</summary>
    public bool Removed { get; set; }
}

/// <summary>One line in the access list.</summary>
public sealed class AccessEntry
{
    public int Facility { get; set; }
    public int Card { get; set; }
    public string Name { get; set; } = "";
    public bool Allowed { get; set; } = true;
    public string Notes { get; set; } = "";
}

/// <summary>The access list and its rules, saved as JSON next to the ACU state.</summary>
public sealed class AccessList
{
    public List<AccessEntry> Entries { get; set; } = new();
    /// <summary>What to do with a card that is not in the list.</summary>
    public bool AllowUnknownCards { get; set; }
    /// <summary>How long a granted timed unlock lasts.</summary>
    public int UnlockMs { get; set; } = 5000;

    public AccessEntry? Find(int facility, int card) => Entries.FirstOrDefault(e => e.Facility == facility && e.Card == card);

    public static AccessList Load(string path) => File.Exists(path)
        ? JsonSerializer.Deserialize<AccessList>(File.ReadAllText(path)) ?? new AccessList() : new AccessList();

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}
