// =============================================================================
//  HPSP Demo  -  Hpsp.Demo.Ui
//  File:    ActivityView.cs
//  Purpose: The activity window: every message sent and received, every
//           decision and refusal, with the full message and its CBOR bytes
//           for whichever line is selected.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  Reading the list:
//    ->  a message this program sent        <-  a message it received
//    green  success      orange  warning      red  security refusal / error
//  Heartbeats are hidden by default (they arrive every few seconds).
//  The engines raise events on background threads, so Add() hops onto the
//  window's thread before touching any control.
// =============================================================================

using Hpsp.Core.Engine;
using Hpsp.Core.Localization;

namespace Hpsp.Demo.Ui;

public sealed class ActivityView : UserControl
{
    private const int MaxEntries = 5000;
    private readonly List<ActivityEntry> _all = new();
    private readonly ListView _list = new() { View = View.Details, FullRowSelect = true, HideSelection = false, VirtualMode = true, Dock = DockStyle.Fill, Font = new Font("Segoe UI", 9f) };
    private readonly TextBox _detail = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 9f), BackColor = SystemColors.Window };
    private readonly CheckBox _hideHeartbeats = new() { Checked = true, AutoSize = true };
    private readonly CheckBox _pause = new() { Appearance = Appearance.Button, AutoSize = true };
    private readonly CheckBox _follow = new() { Checked = true, AutoSize = true };
    private readonly Button _clear = new() { AutoSize = true }, _save = new() { AutoSize = true };
    private readonly Label _title = new() { AutoSize = true, Font = new Font("Segoe UI", 10f, FontStyle.Bold), Padding = new Padding(0, 4, 8, 0) };
    private readonly List<ActivityEntry> _queuedWhilePaused = new();
    private List<ActivityEntry> _shown = new();
    private bool _showSecrets;

    public ActivityView()
    {
        _list.Columns.Add("", 70); _list.Columns.Add("", 26); _list.Columns.Add("", 70); _list.Columns.Add("", 90); _list.Columns.Add("", 700);
        _list.RetrieveVirtualItem += (_, e) => e.Item = MakeItem(_shown[e.ItemIndex]);
        _list.SelectedIndexChanged += (_, _) => ShowDetail();
        _hideHeartbeats.CheckedChanged += (_, _) => Rebuild();
        _pause.CheckedChanged += (_, _) => { if (!_pause.Checked) { _all.AddRange(_queuedWhilePaused); _queuedWhilePaused.Clear(); Trim(); Rebuild(); } Relabel(); };
        _clear.Click += (_, _) => { _all.Clear(); _queuedWhilePaused.Clear(); Rebuild(); _detail.Clear(); };
        _save.Click += (_, _) => SaveToFile();

        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(2) };
        bar.Controls.AddRange(new Control[] { _title, _hideHeartbeats, _follow, _pause, _clear, _save });
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 300 };
        split.Panel1.Controls.Add(_list);
        split.Panel2.Controls.Add(_detail);
        Controls.Add(split);
        Controls.Add(bar);
        Resize += (_, _) => { if (split.Height > 200) split.SplitterDistance = (int)(split.Height * 0.62); };
        L.Changed += Relabel;
        Relabel();
    }

    /// <summary>Show the secret parts of entries (keys, PSK) in the detail pane.</summary>
    public bool ShowSecrets { get => _showSecrets; set { _showSecrets = value; ShowDetail(); } }

    public void Relabel()
    {
        _title.Text = L.T("Activity");
        _list.Columns[0].Text = L.T("Time"); _list.Columns[1].Text = ""; _list.Columns[2].Text = L.T("Channel");
        _list.Columns[3].Text = L.T("Peer"); _list.Columns[4].Text = L.T("What happened");
        _hideHeartbeats.Text = L.T("Hide heartbeats and fragments");
        _follow.Text = L.T("Follow newest");
        _pause.Text = _pause.Checked ? L.F("Resume ({0} waiting)", _queuedWhilePaused.Count) : L.T("Pause");
        _clear.Text = L.T("Clear"); _save.Text = L.T("Save…");
        if (_detail.Text.Length == 0) _detail.Text = L.T("Select a line to see the full message (as JSON) and its CBOR bytes on the wire.");
    }

    /// <summary>Add an entry. Safe to call from any thread.</summary>
    public void Add(ActivityEntry e)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { try { BeginInvoke(() => Add(e)); } catch (InvalidOperationException) { } return; }
        if (_pause.Checked) { _queuedWhilePaused.Add(e); Relabel(); return; }
        _all.Add(e);
        if (Trim()) { Rebuild(); return; }
        if (!IsShown(e)) return;
        _shown.Add(e);
        _list.VirtualListSize = _shown.Count;
        if (_follow.Checked && _shown.Count > 0) _list.EnsureVisible(_shown.Count - 1);
    }

    private bool Trim()
    {
        if (_all.Count <= MaxEntries) return false;
        _all.RemoveRange(0, _all.Count - MaxEntries);
        return true;
    }

    private bool IsShown(ActivityEntry e) => !(_hideHeartbeats.Checked && e.IsHeartbeat);

    private void Rebuild()
    {
        _shown = _all.Where(IsShown).ToList();
        _list.VirtualListSize = _shown.Count;
        _list.Invalidate();
        if (_follow.Checked && _shown.Count > 0) _list.EnsureVisible(_shown.Count - 1);
    }

    private static ListViewItem MakeItem(ActivityEntry e)
    {
        string arrow = e.Kind switch { ActivityKind.Sent => "→", ActivityKind.Received => "←", ActivityKind.Refused => "✖", ActivityKind.Good => "✔", ActivityKind.Warning => "!", ActivityKind.Error => "✖", _ => "·" };
        string summary = e.Summary.StartsWith("-> ") || e.Summary.StartsWith("<- ") ? e.Summary[3..] : e.Summary;
        var item = new ListViewItem(new[] { e.Time.ToString("HH:mm:ss.f"), arrow, e.Channel, e.Peer ?? "", summary });
        item.ForeColor = KindColor(e.Kind);
        if (e.Kind is ActivityKind.Refused or ActivityKind.Error) item.BackColor = Color.FromArgb(255, 235, 235);
        else if (e.Kind == ActivityKind.Good) item.BackColor = Color.FromArgb(232, 248, 232);
        return item;
    }

    public static Color KindColor(ActivityKind k) => k switch
    {
        ActivityKind.Sent => Color.FromArgb(20, 70, 160),
        ActivityKind.Received => Color.FromArgb(90, 40, 140),
        ActivityKind.Good => Color.FromArgb(0, 110, 40),
        ActivityKind.Warning => Color.FromArgb(170, 95, 0),
        ActivityKind.Refused or ActivityKind.Error => Color.FromArgb(180, 0, 0),
        _ => SystemColors.ControlText,
    };

    private void ShowDetail()
    {
        if (_list.SelectedIndices.Count == 0 || _list.SelectedIndices[0] >= _shown.Count) return;
        var e = _shown[_list.SelectedIndices[0]];
        string head = $"{e.Time:yyyy-MM-dd HH:mm:ss.fff}   {e.Kind}   {e.Channel}{(e.Peer is null ? "" : "   " + e.Peer)}\r\n{e.Summary}";
        string body = e.DetailText(_showSecrets);
        _detail.Text = (head + (body.Length > 0 ? "\n\n" + body : "")).Replace("\r\n", "\n").Replace("\n", "\r\n");
    }

    private void SaveToFile()
    {
        using var dlg = new SaveFileDialog { Filter = L.T("Text files") + " (*.txt)|*.txt", FileName = $"hpsp-activity-{DateTime.Now:yyyyMMdd-HHmmss}.txt" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        using var w = new StreamWriter(dlg.FileName);
        foreach (var e in _all)
        {
            w.WriteLine($"{e.Time:HH:mm:ss.fff}  {e.Kind,-8} {e.Channel,-8} {e.Peer,-12} {e.Summary}");
            var d = e.DetailText(_showSecrets);
            if (d.Length > 0) foreach (var line in d.Split('\n')) w.WriteLine("        " + line);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) L.Changed -= Relabel;
        base.Dispose(disposing);
    }
}
