// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Cbor/JsonNotation.cs
//  Purpose: Show an HPSP message in the JSON notation used by the specification,
//           for the activity windows.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  The specification writes every example in JSON. To make the demo's activity
//  window match the document, this file turns a decoded CBOR message back into
//  that same notation. The one rule to know: a member whose name ends in "_hex"
//  holds bytes, shown as hexadecimal; a name ending in "_b64" holds bytes shown
//  as base64url. On the wire both are plain CBOR byte strings.
//
//  When "Show secrets" is off, members that hold secrets (for example a PIN)
//  are replaced by "<hidden>".
// =============================================================================

using System.Globalization;
using System.Text;

namespace Hpsp.Core.Cbor;

public static class JsonNotation
{
    /// <summary>Member names whose values are secret and hidden unless secrets are shown.</summary>
    private static readonly HashSet<string> SecretMembers = new(StringComparer.Ordinal) { "pin" };

    /// <summary>Render a message tree as indented JSON in the specification's notation.</summary>
    public static string Render(object? value, bool showSecrets = false)
    {
        var sb = new StringBuilder();
        Write(sb, null, value, 0, showSecrets);
        return sb.ToString();
    }

    private static void Write(StringBuilder sb, string? key, object? v, int indent, bool showSecrets)
    {
        string pad = new(' ', indent * 2);
        if (key is not null && SecretMembers.Contains(key) && !showSecrets) { sb.Append("\"<hidden>\""); return; }
        switch (v)
        {
            case null: sb.Append("null"); break;
            case string s: sb.Append(Quote(s)); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case byte[] bytes:
                // The member name says how to show the bytes.
                if (key is not null && key.EndsWith("_b64", StringComparison.Ordinal)) sb.Append(Quote(Encoding64.ToBase64Url(bytes)));
                else sb.Append(Quote(Convert.ToHexString(bytes).ToLowerInvariant()));
                break;
            case double d: sb.Append(d.ToString("R", CultureInfo.InvariantCulture)); break;
            case long or ulong or int or uint: sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); break;
            case IDictionary<string, object?> map:
                if (map.Count == 0) { sb.Append("{}"); break; }
                sb.Append("{\n");
                int i = 0;
                foreach (var kv in OrderForDisplay(map))
                {
                    sb.Append(pad).Append("  ").Append(Quote(kv.Key)).Append(": ");
                    Write(sb, kv.Key, kv.Value, indent + 1, showSecrets);
                    sb.Append(++i < map.Count ? ",\n" : "\n");
                }
                sb.Append(pad).Append('}');
                break;
            case System.Collections.IEnumerable list:
                var items = list.Cast<object?>().ToList();
                if (items.Count == 0) { sb.Append("[]"); break; }
                sb.Append('[');
                for (int k = 0; k < items.Count; k++)
                {
                    // Array elements inherit the member name, so a "chain_b64" array shows base64url.
                    Write(sb, key, items[k], indent + 1, showSecrets);
                    if (k < items.Count - 1) sb.Append(", ");
                }
                sb.Append(']');
                break;
            default: sb.Append(Quote(v.ToString() ?? "")); break;
        }
    }

    /// <summary>Show the envelope members in the same order as the specification's examples.</summary>
    private static IEnumerable<KeyValuePair<string, object?>> OrderForDisplay(IDictionary<string, object?> map)
    {
        string[] envelope = { "type", "op", "id", "re", "seq", "mono", "ts", "data" };
        foreach (var k in envelope) if (map.TryGetValue(k, out var v)) yield return new(k, v);
        foreach (var kv in map) if (Array.IndexOf(envelope, kv.Key) < 0) yield return kv;
    }

    private static string Quote(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }
}

/// <summary>Base64url helpers (RFC 4648 section 5, no padding), as the specification uses.</summary>
public static class Encoding64
{
    public static string ToBase64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string s)
    {
        string t = s.Replace('-', '+').Replace('_', '/');
        t += (t.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(t);
    }
}
