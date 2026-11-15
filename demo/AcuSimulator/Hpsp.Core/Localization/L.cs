// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Localization/L.cs
//  Purpose: English / French text for both apps and the activity window.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  HOW IT WORKS
//  ------------
//  Every piece of text a person reads is written in English in the code and
//  passed through L.T("...") (plain text) or L.F("... {0} ...", value)
//  (text with values in it). In English the text is returned as is. In French
//  it is looked up in French.cs; anything not yet translated falls back to
//  English, so a missing entry never breaks the app.
//
//  What is NOT translated: protocol content - message names such as "hello"
//  or "unlock", JSON member names, error codes such as "replay", and the CBOR
//  bytes. Those are what actually travel on the wire, and they match the
//  specification.
//
//  To correct or add a French translation, edit French.cs only.
//  To find English text that has no French yet, run the test project: it
//  lists any missing entries.
// =============================================================================

using System.Collections.Concurrent;
using System.Globalization;

namespace Hpsp.Core.Localization;

public enum Language { English, French }

public static class L
{
    private static Language _current = Language.English;

    /// <summary>The language for new text. Changing it raises <see cref="Changed"/>.</summary>
    public static Language Current
    {
        get => _current;
        set { if (_current == value) return; _current = value; Changed?.Invoke(); }
    }

    /// <summary>Raised when the language changes, so windows can relabel themselves.</summary>
    public static event Action? Changed;

    /// <summary>English text used while the app ran that has no French entry (for translators).</summary>
    public static readonly ConcurrentDictionary<string, byte> Missing = new();

    /// <summary>The language Windows is set to: French if it is any French, otherwise English.</summary>
    public static Language FromSystem() =>
        CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "fr" ? Language.French : Language.English;

    public static string Code(Language l) => l == Language.French ? "fr" : "en";
    public static Language FromCode(string? code) => code == "fr" ? Language.French : Language.English;

    /// <summary>True if the text has a French entry (some words are the same in both languages).</summary>
    public static bool HasFrench(string english) => French.Text.ContainsKey(english);

    /// <summary>Translate plain text.</summary>
    public static string T(string english)
    {
        if (_current == Language.English) return english;
        if (French.Text.TryGetValue(english, out var fr)) return fr;
        Missing.TryAdd(english, 0);
        return english;
    }

    /// <summary>Translate text with {0}, {1}... placeholders, then fill them in.</summary>
    public static string F(string englishFormat, params object?[] args)
    {
        string f = T(englishFormat);
        try { return string.Format(_current == Language.French ? CultureInfo.GetCultureInfo("fr-FR") : CultureInfo.InvariantCulture, f, args); }
        catch (FormatException) { return string.Format(CultureInfo.InvariantCulture, englishFormat, args); }
    }
}
