// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/Activity.cs
//  Purpose: The entries shown in the activity windows of both apps.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  Every message sent or received, and every notable step (a TLS handshake, a
//  certificate check, an access decision), becomes one ActivityEntry. The
//  engines raise them; the windows show them. Entries keep the decoded message
//  and its raw bytes, so the window can show the specification's JSON notation
//  and the exact CBOR on the wire.
//
//  Some entries carry secrets (for example the pre-shared key made during
//  pairing). Those are kept in SecretDetail and only shown when the user turns
//  on "Show secrets (demo only)".
// =============================================================================

using Hpsp.Core.Cbor;
using Hpsp.Core.Protocol;
using Hpsp.Core.Localization;

namespace Hpsp.Core.Engine;

public enum ActivityKind
{
    Sent,       // a message we sent           (shown with  ->)
    Received,   // a message we received       (shown with  <-)
    Info,       // a step or state change
    Good,       // a success worth highlighting (access granted, pairing done)
    Warning,    // something unusual but handled
    Refused,    // a security refusal (bad grant, wrong code, bad certificate)
    Error,      // a failure
}

public sealed class ActivityEntry
{
    public DateTime Time { get; } = DateTime.Now;
    public ActivityKind Kind { get; init; }
    /// <summary>"session", "pairing", "tls", "door" ... for filtering.</summary>
    public string Channel { get; init; } = "session";
    /// <summary>Which reader this is about (ACU side), if any.</summary>
    public string? Peer { get; init; }
    public string Summary { get; init; } = "";
    public HpspMessage? Message { get; init; }
    public byte[]? Raw { get; init; }
    public string? Detail { get; init; }
    /// <summary>Extra text that contains secrets; shown only with "Show secrets" on.</summary>
    public string? SecretDetail { get; init; }
    public bool IsHeartbeat { get; init; }

    /// <summary>The full text for the detail pane.</summary>
    public string DetailText(bool showSecrets)
    {
        var parts = new List<string>();
        if (Message is not null) parts.Add(Message.ToJson(showSecrets));
        if (Detail is not null) parts.Add(Detail);
        if (SecretDetail is not null)
            parts.Add(showSecrets ? L.T("SECRETS (demo only - never shown on a real system):\n") + SecretDetail
                                  : L.T("(This step involves secrets. Turn on \"Show secrets\" to see them.)"));
        if (Raw is not null) parts.Add(L.F("CBOR on the wire ({0} bytes):\n", Raw.Length) + HexDump(Raw));
        return string.Join("\n\n", parts);
    }

    public static string HexDump(byte[] b)
    {
        var lines = new List<string>();
        for (int i = 0; i < b.Length; i += 16)
        {
            var chunk = b.Skip(i).Take(16).ToArray();
            lines.Add($"{i:x4}  {string.Join(" ", chunk.Select(x => x.ToString("x2"))),-47}  {new string(chunk.Select(x => x is >= 32 and < 127 ? (char)x : '.').ToArray())}");
        }
        return string.Join("\n", lines);
    }
}

/// <summary>One-line, human-readable summaries of messages for the activity list.</summary>
public static class MessageSummary
{
    public static string Of(HpspMessage m)
    {
        string head = m.Type switch
        {
            "cmd" => $"{m.Op} #{m.Id}",
            "rsp" => L.F("{0} reply to #{1}", m.Op, m.Re),
            "err" => L.F("{0} ERROR re #{1}: {2}", m.Op, m.Re, m.GetString("code")),
            "evt" => L.F("{0} event seq {1}", m.Op, m.Seq),
            "ack" => L.F("ack up to seq {0}", m.GetLong("seq")),
            "frag" => $"fragment {m.GetLong("offset")}/{m.GetLong("total")} of set {m.GetLong("fid")}",
            "pake" => L.F("pairing: {0}", m.Op),
            _ => m.Describe(),
        };
        string? extra = (m.Type, m.Op) switch
        {
            ("cmd", "hello") => L.F("device {0}, session value {1}", m.GetString("device_id"), Short(m.GetBytes("session_nonce_b64"))),
            ("rsp", "hello") => L.F("heartbeat {0} s, resume from seq {1}", m.GetLong("heartbeat_s"), m.GetLong("resume_from")),
            ("evt", "credential") => Credential(m),
            ("cmd", "unlock") => Unlock(m),
            ("rsp", "unlock") => $"door {m.GetLong("cid")} {m.GetString("state")}",
            ("evt", "lock_state") => $"door {m.GetLong("cid")} {m.GetString("state")} ({m.GetString("cause")})",
            ("cmd", "set_indicator") => $"LED {m.GetString("color") ?? ""} {m.GetString("pattern")}",
            ("evt", "security_event") => $"{m.GetString("kind")} {m.GetString("reason") ?? m.GetString("source") ?? ""}",
            ("cmd", "trust_update") => L.F("epoch {0}, {1} grant signer(s)", m.GetLong("epoch"), m.GetList("signers_b64")?.Count ?? 0),
            ("evt", "boot") => $"reason {m.GetString("reason")}",
            ("cmd", "enroll") => $"site {m.GetString("site_id")}",
            ("rsp", "cert_install") => $"state {m.GetString("state")}",
            ("pake", "pake_params") => $"device {m.GetString("device_id")}, {m.GetLong("iterations")} iterations",
            _ => null,
        };
        return extra is null ? head : head + ": " + extra;
    }

    private static string Credential(HpspMessage m)
    {
        var fc = m.GetLong("fc"); var id = m.GetLong("id");
        string raw = m.GetBytes("raw_hex") is byte[] r ? Convert.ToHexString(r).ToLowerInvariant() : "";
        return fc is null ? $"{m.GetString("tech")} {m.GetLong("bits")} bits {raw}" : $"FC {fc}, card {id} ({m.GetLong("bits")} bits, raw {raw})";
    }

    private static string Unlock(HpspMessage m)
    {
        var g = m.GetMap("grant");
        string counter = g?.GetValueOrDefault("counter") is long c ? "#" + c : "?";
        return $"door {m.GetLong("cid")}, {m.GetString("mode")} {m.GetLong("duration_ms")} ms, grant {counter}";
    }

    public static string Short(byte[]? b) => b is null ? "-" : Convert.ToHexString(b.Take(4).ToArray()).ToLowerInvariant() + "…";
}
