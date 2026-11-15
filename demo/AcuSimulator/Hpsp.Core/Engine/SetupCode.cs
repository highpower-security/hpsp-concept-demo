// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/SetupCode.cs
//  Purpose: The reader's setup code and its QR form (specification 5.6,
//           "Label and QR code").
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  Each reader has ONE secret code: 8 characters from a 32-symbol alphabet that
//  leaves out look-alikes (no 0/O or 1/I), printed as 4+4, e.g. "7KQ4-M9TW".
//
//  The QR code holds the same code in machine-readable form, plus the reader's
//  device ID and a 2-character check:
//
//      HPSP:1:<device uuid>:<setup code>:<check>
//
//  The check is the first 10 bits of SHA-256 of everything before the last
//  colon, written as two characters of the same alphabet. It catches a
//  misread before it wastes one of the five allowed attempts.
// =============================================================================

using System.Security.Cryptography;
using System.Text;
using Hpsp.Core.Localization;

namespace Hpsp.Core.Engine;

public static class SetupCode
{
    public const string Alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";   // 32 symbols, no 0 O 1 I

    /// <summary>A new random 8-character code (40 bits).</summary>
    public static string NewCode()
    {
        var sb = new StringBuilder(8);
        for (int i = 0; i < 8; i++) sb.Append(Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]);
        return sb.ToString();
    }

    /// <summary>"7KQ4M9TW" -> "7KQ4-M9TW" for display.</summary>
    public static string Pretty(string code) => code.Length == 8 ? code[..4] + "-" + code[4..] : code;

    /// <summary>Accept "7kq4-m9tw", "7KQ4 M9TW" etc.; returns the 8 symbols or null if invalid.</summary>
    public static string? Normalize(string input)
    {
        string c = new(input.ToUpperInvariant().Where(ch => ch != '-' && ch != ' ').ToArray());
        return c.Length == 8 && c.All(Alphabet.Contains) ? c : null;
    }

    public static string QrText(Guid deviceId, string code)
    {
        string body = $"HPSP:1:{deviceId:D}:{code}";
        return body + ":" + Check(body);
    }

    private static string Check(string body)
    {
        byte[] h = SHA256.HashData(Encoding.ASCII.GetBytes(body));
        int bits = (h[0] << 2) | (h[1] >> 6);           // first 10 bits
        return new string(new[] { Alphabet[bits >> 5], Alphabet[bits & 31] });
    }

    /// <summary>Parse QR text. Returns false if it is not an HPSP QR payload or the check fails.</summary>
    public static bool TryParseQr(string text, out Guid deviceId, out string code, out string error)
    {
        deviceId = Guid.Empty; code = ""; error = "";
        var p = text.Trim().Split(':');
        if (p.Length != 5 || p[0] != "HPSP" || p[1] != "1") { error = L.T("not an HPSP QR code"); return false; }
        if (!Guid.TryParse(p[2], out deviceId)) { error = L.T("bad device id"); return false; }
        var c = Normalize(p[3]);
        if (c is null) { error = L.T("bad setup code"); return false; }
        if (Check($"HPSP:1:{p[2]}:{p[3]}") != p[4].ToUpperInvariant()) { error = L.T("check characters do not match (misread?)"); return false; }
        code = c;
        return true;
    }
}
