// =============================================================================
//  HPSP Demo  -  Hpsp.Demo.Ui
//  File:    CommonUi.cs
//  Purpose: Small shared pieces: the red "secrets are visible" banner, the TLS
//           engine picker, the Language menu, saved window settings, and a
//           few helpers.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================

using System.Text.Json;
using Hpsp.Core.Localization;
using Hpsp.Core.Transport;

namespace Hpsp.Demo.Ui;

/// <summary>Settings a window remembers between runs (not protocol state).</summary>
public sealed class UiSettings
{
    public string Language { get; set; } = "";
    public string TlsEngine { get; set; } = "";
    public bool ChecklistVisible { get; set; } = true;

    public static UiSettings Load(string folder)
    {
        try { return JsonSerializer.Deserialize<UiSettings>(File.ReadAllText(Path.Combine(folder, "ui-settings.json"))) ?? new(); }
        catch { return new(); }
    }

    public void Save(string folder)
    {
        try { Directory.CreateDirectory(folder); File.WriteAllText(Path.Combine(folder, "ui-settings.json"), JsonSerializer.Serialize(this)); } catch { }
    }
}

/// <summary>A red bar across the top of the window while secrets are being shown.</summary>
public sealed class SecretsBanner : Label
{
    public SecretsBanner()
    {
        Dock = DockStyle.Top; Height = 26; TextAlign = ContentAlignment.MiddleCenter; Visible = false;
        BackColor = Color.FromArgb(200, 20, 20); ForeColor = Color.White; Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
        L.Changed += Relabel; Relabel();
    }
    public void Relabel() => Text = L.T("SECRETS VISIBLE (demo only). A real device never shows its keys or codes. Do not use these keys for anything else.");
    protected override void Dispose(bool disposing) { if (disposing) L.Changed -= Relabel; base.Dispose(disposing); }
}

/// <summary>
/// Makes a check box or radio button wrap its text onto several lines instead of
/// growing wider than the left-hand panel. (WinForms check boxes and radio buttons
/// never wrap when AutoSize is on: a long label made the panel scroll sideways.)
/// </summary>
public static class WrappingText
{
    public const int DefaultWidth = 330;

    public static T Apply<T>(T box, int width = DefaultWidth) where T : ButtonBase
    {
        box.AutoSize = false;
        box.TextAlign = ContentAlignment.TopLeft;
        if (box is CheckBox c) c.CheckAlign = ContentAlignment.TopLeft;
        if (box is RadioButton r) r.CheckAlign = ContentAlignment.TopLeft;
        void Fit()
        {
            // Room left for the text after the tick box and its gap.
            int textWidth = width - SystemInformation.MenuCheckSize.Width - 8;
            var size = TextRenderer.MeasureText(box.Text, box.Font, new Size(textWidth, 0), TextFormatFlags.WordBreak);
            box.Size = new Size(width, Math.Max(size.Height, box.Font.Height) + 6);
        }
        box.TextChanged += (_, _) => Fit();
        box.FontChanged += (_, _) => Fit();
        Fit();
        return box;
    }
}

/// <summary>
/// Choose which TLS 1.3 code the program uses for normal sessions:
///  - "Windows built-in (SChannel)": the TLS that comes with Windows 11. Not on Windows 10,
///    whose SChannel has no TLS 1.3, so that choice is grayed out there.
///  - "BouncyCastle": a TLS library inside the program. Works on Windows 10 and 11.
/// Pairing always uses BouncyCastle, because it needs TLS with a pre-shared key.
/// </summary>
public sealed class TlsEnginePicker : GroupBox
{
    private readonly RadioButton _win = WrappingText.Apply(new RadioButton()), _bc = WrappingText.Apply(new RadioButton());
    private readonly Button _test = new() { AutoSize = true };
    private readonly Label _note = new() { AutoSize = true, ForeColor = SystemColors.GrayText, MaximumSize = new Size(330, 0) };
    private readonly ToolTip _tip = new();
    private readonly bool _winOk;
    private readonly string _winWhy;
    public event Action<TlsEngineKind>? EngineChanged;

    public TlsEnginePicker(TlsEngineKind initial)
    {
        _winOk = Hpsp.Core.Transport.TlsEngine.WindowsEngineAvailable(out _winWhy);
        var flow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        flow.Controls.AddRange(new Control[] { _win, _bc, _test, _note });
        Controls.Add(flow);
        AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(6);
        _win.Enabled = _winOk;
        if (!_winOk) initial = TlsEngineKind.BouncyCastle;
        (initial == TlsEngineKind.Windows ? _win : _bc).Checked = true;
        _win.CheckedChanged += (_, _) => { if (_win.Checked) EngineChanged?.Invoke(TlsEngineKind.Windows); };
        _bc.CheckedChanged += (_, _) => { if (_bc.Checked) EngineChanged?.Invoke(TlsEngineKind.BouncyCastle); };
        _test.Click += async (_, _) =>
        {
            _test.Enabled = false;
            string? err = await Hpsp.Core.Transport.TlsEngine.SelfTestAsync(Engine);
            _test.Enabled = true;
            MessageBox.Show(FindForm(), err is null ? L.F("The {0} TLS engine works on this computer (TLS 1.3 handshake on this machine).", EngineName(Engine)) : L.F("The {0} TLS engine failed its self-test:\n\n{1}", EngineName(Engine), err),
                L.T("TLS engine self-test"), MessageBoxButtons.OK, err is null ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        };
        L.Changed += Relabel; Relabel();
    }

    public TlsEngineKind Engine => _win.Checked ? TlsEngineKind.Windows : TlsEngineKind.BouncyCastle;
    public static string EngineName(TlsEngineKind k) => k == TlsEngineKind.Windows ? L.T("Windows built-in") : "BouncyCastle";

    public void Relabel()
    {
        Text = L.T("TLS engine for sessions");
        _win.Text = L.T("Windows built-in (SChannel)");
        _bc.Text = L.T("BouncyCastle (post-quantum key exchange; works on Windows 10 too)");
        _test.Text = L.T("Test the selected engine");
        _note.Text = _winOk ? L.T("Pairing always uses BouncyCastle, because it needs TLS with a pre-shared key. BouncyCastle offers hybrid post-quantum key exchange (ML-KEM) first; Windows uses it only if its own TLS has been updated for it.")
                            : L.T("Windows built-in TLS is not available here: this version of Windows has no TLS 1.3. BouncyCastle is used instead.");
        _tip.SetToolTip(_win, _winOk ? L.T("The TLS 1.3 built into Windows 11.") : _winWhy);
    }

    protected override void Dispose(bool disposing) { if (disposing) L.Changed -= Relabel; base.Dispose(disposing); }
}

public static class UiHelpers
{
    /// <summary>The menu with English / Français. The choice is applied at once.</summary>
    public static ToolStripMenuItem LanguageMenu(Action<Language> chosen)
    {
        var menu = new ToolStripMenuItem();
        var en = new ToolStripMenuItem("English") { Tag = Language.English };
        var fr = new ToolStripMenuItem("Français") { Tag = Language.French };
        void Mark() { en.Checked = L.Current == Language.English; fr.Checked = L.Current == Language.French; menu.Text = L.T("&Language") + " / Langue"; }
        foreach (var i in new[] { en, fr }) i.Click += (_, _) => { L.Current = (Language)i.Tag!; chosen(L.Current); };
        menu.DropDownItems.AddRange(new ToolStripItem[] { en, fr });
        L.Changed += Mark; Mark();
        return menu;
    }

    /// <summary>Where a program keeps its files: %LOCALAPPDATA%\HPSP Demo\name, or --data folder.</summary>
    public static string DataFolder(string name, string[] args)
    {
        int i = Array.FindIndex(args, a => a.Equals("--data", StringComparison.OrdinalIgnoreCase));
        if (i >= 0 && i + 1 < args.Length) return Path.GetFullPath(args[i + 1]);
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HPSP Demo", name);
    }

    public static int? IntArg(string[] args, string name)
    {
        int i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length && int.TryParse(args[i + 1], out var v) ? v : null;
    }

    /// <summary>English unless the person has chosen French from the Language menu (the choice is saved).
    /// The computer's own language is deliberately not used: the demo always starts in English.</summary>
    public static void ApplyLanguage(UiSettings s) => L.Current = L.FromCode(s.Language);

    public static TlsEngineKind InitialEngine(UiSettings s) =>
        Enum.TryParse<TlsEngineKind>(s.TlsEngine, out var k) ? k
        : Hpsp.Core.Transport.TlsEngine.WindowsEngineAvailable(out _) ? TlsEngineKind.Windows : TlsEngineKind.BouncyCastle;

    /// <summary>A small titled box with a vertical flow of controls.</summary>
    public static (GroupBox box, FlowLayoutPanel flow) Group()
    {
        var box = new GroupBox { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(6, 4, 6, 6), Margin = new Padding(3, 3, 3, 6), MinimumSize = new Size(340, 0) };
        var flow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink };
        box.Controls.Add(flow);
        return (box, flow);
    }

    public static FlowLayoutPanel Row(params Control[] items)
    {
        var r = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = false, Margin = new Padding(0) };
        r.Controls.AddRange(items);
        return r;
    }

    public static Label Value(float size = 9f, bool bold = false) =>
        new() { AutoSize = true, Font = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular), MaximumSize = new Size(330, 0), Margin = new Padding(3, 2, 3, 2) };

    /// <summary>Show an unexpected error in plain words, with the details for a bug report.</summary>
    public static void ShowError(Exception e)
    {
        MessageBox.Show(L.F("Something went wrong, but the program can continue.\n\n{0}\n\nIf this keeps happening, please report it with this message.", Hpsp.Core.Security.DemoPki.Explain(e)),
            "HPSP Demo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    public static void ShowText(IWin32Window owner, string title, string text)
    {
        using var f = new Form { Text = title, Width = 820, Height = 520, StartPosition = FormStartPosition.CenterParent, ShowInTaskbar = false };
        var tb = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 9.5f), Text = text.Replace("\r\n", "\n").Replace("\n", "\r\n") };
        f.Controls.Add(tb);
        f.ShowDialog(owner);
    }

    public static string Countdown(DateTime? until)
    {
        if (until is not DateTime t) return "";
        var left = t - DateTime.Now;
        return left.TotalSeconds <= 0 ? "" : left.TotalMinutes >= 1 ? $"{(int)left.TotalMinutes}:{left.Seconds:00}" : $"{left.TotalSeconds:0.0} s";
    }
}
