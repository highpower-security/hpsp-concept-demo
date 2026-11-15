// =============================================================================
//  HPSP Demo  -  Hpsp.Demo.Ui
//  File:    Checklist.cs
//  Purpose: The "Provisioning checklist" panel: a guided walk through
//           commissioning and first use. Steps tick themselves off when the
//           program sees they are done; each one explains, in plain words,
//           what is happening in the protocol and what to look for in the
//           activity window.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================

using Hpsp.Core.Localization;

namespace Hpsp.Demo.Ui;

/// <summary>One step. Title and Explain are English; they are translated when shown.</summary>
public sealed class ChecklistStep
{
    public required string Title { get; init; }
    public required string Explain { get; init; }
    /// <summary>Returns true once the program can see the step is done.</summary>
    public required Func<bool> IsDone { get; init; }
    /// <summary>For steps done on the OTHER app, the person can tick them by hand.</summary>
    public bool ManualTick { get; init; }
    internal bool Ticked;
    internal bool Done => Ticked || IsDone();
}

public sealed class ChecklistPanel : UserControl
{
    private readonly List<ChecklistStep> _steps = new();
    private readonly FlowLayoutPanel _flow = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(4) };
    private readonly Label _header = new() { Dock = DockStyle.Top, Font = new Font("Segoe UI", 11f, FontStyle.Bold), Height = 28, Padding = new Padding(4, 6, 0, 0) };
    private readonly Label _progress = new() { Dock = DockStyle.Top, Height = 20, Padding = new Padding(6, 0, 0, 0), ForeColor = SystemColors.GrayText };
    private readonly Button _reset = new() { Dock = DockStyle.Bottom, Height = 28 };
    private readonly List<(Panel box, Label tick, Label title, Label explain, CheckBox manual)> _rows = new();
    private int _lastWidth;

    public ChecklistPanel()
    {
        Controls.Add(_flow); Controls.Add(_progress); Controls.Add(_header); Controls.Add(_reset);
        _reset.Click += (_, _) => { foreach (var s in _steps) s.Ticked = false; Refresh(); };
        _flow.Resize += (_, _) => { if (Math.Abs(_flow.ClientSize.Width - _lastWidth) > 4) Build(); };
        L.Changed += Build;
        BackColor = Color.FromArgb(248, 249, 252);
    }

    public void SetSteps(IEnumerable<ChecklistStep> steps) { _steps.Clear(); _steps.AddRange(steps); Build(); }

    private void Build()
    {
        if (IsDisposed) return;
        _lastWidth = _flow.ClientSize.Width;
        int w = Math.Max(160, _flow.ClientSize.Width - 28);
        _header.Text = L.T("Provisioning checklist");
        _reset.Text = L.T("Start the checklist again");
        _flow.SuspendLayout();
        _flow.Controls.Clear(); _rows.Clear();
        int n = 1;
        foreach (var s in _steps)
        {
            var box = new Panel { Width = w, Padding = new Padding(4), Margin = new Padding(0, 0, 0, 6), BorderStyle = BorderStyle.FixedSingle };
            var tick = new Label { Text = "○", Font = new Font("Segoe UI Symbol", 13f), Location = new Point(4, 2), Size = new Size(26, 26) };
            var title = new Label { Text = $"{n++}. {L.T(s.Title)}", Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), Location = new Point(32, 5), MaximumSize = new Size(w - 40, 0), AutoSize = true };
            var explain = new Label { Text = L.T(s.Explain), Font = new Font("Segoe UI", 8.75f), Location = new Point(32, 0), MaximumSize = new Size(w - 40, 0), AutoSize = true, ForeColor = Color.FromArgb(60, 60, 70) };
            var manual = new CheckBox { Text = L.T("Done (ticked by hand)"), AutoSize = true, Visible = s.ManualTick, Font = new Font("Segoe UI", 8.25f) };
            var step = s;
            manual.CheckedChanged += (_, _) => { step.Ticked = manual.Checked; Refresh(); };
            box.Controls.AddRange(new Control[] { tick, title, explain, manual });
            // Lay out the box by hand: title, then explanation, then the manual tick box.
            explain.Top = title.Bottom + 3;
            manual.Location = new Point(32, explain.Bottom + 3);
            box.Height = (s.ManualTick ? manual.Bottom : explain.Bottom) + 8;
            _flow.Controls.Add(box);
            _rows.Add((box, tick, title, explain, manual));
        }
        _flow.ResumeLayout();
        Refresh();
    }

    /// <summary>Re-check every step (call it whenever the program's state changes).</summary>
    public override void Refresh()
    {
        if (_rows.Count != _steps.Count) return;
        bool currentMarked = false; int done = 0;
        for (int i = 0; i < _steps.Count; i++)
        {
            bool d;
            try { d = _steps[i].Done; } catch { d = false; }
            var r = _rows[i];
            if (r.manual.Checked != _steps[i].Ticked) r.manual.Checked = _steps[i].Ticked;
            if (d) done++;
            bool current = !d && !currentMarked;
            if (current) currentMarked = true;
            r.tick.Text = d ? "✔" : current ? "➜" : "○";
            r.tick.ForeColor = d ? Color.FromArgb(0, 130, 50) : current ? Color.FromArgb(20, 90, 200) : Color.Gray;
            r.box.BackColor = d ? Color.FromArgb(234, 247, 236) : current ? Color.FromArgb(232, 240, 255) : Color.White;
            r.explain.Visible = true;
            r.title.ForeColor = d ? Color.FromArgb(0, 100, 40) : SystemColors.ControlText;
        }
        _progress.Text = L.F("{0} of {1} steps done", done, _steps.Count);
        base.Refresh();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) L.Changed -= Build;
        base.Dispose(disposing);
    }
}
