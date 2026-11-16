// =============================================================================
//  HPSP Demo  -  ACU Simulator
//  File:    MainForm.cs
//  Purpose: The ACU's window. All protocol work happens in
//           Hpsp.Core.Engine.AcuEngine; this file shows its state and passes
//           on what the person does.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  WHAT THE PANELS ARE
//  -------------------
//   Site          the site's keys and certificates, and the listener for readers
//   TLS engine    which TLS 1.3 code to use for sessions
//   Access rules  what happens to cards that are not in the list, unlock time
//   Readers       paired readers, online or not; manual unlock; attack demos
//   Access list   the cards: facility code, card number, name, allowed or not
//   Activity      everything sent and received, and every decision
// =============================================================================

using System.ComponentModel;
using Hpsp.Core.Engine;
using Hpsp.Core.Localization;
using Hpsp.Demo.Ui;

namespace HpspAcuSimulator;

public sealed class MainForm : Form
{
    private readonly AcuEngine _engine;
    private readonly UiSettings _settings;
    private readonly string _folder;

    private readonly SecretsBanner _banner = new();
    private readonly ActivityView _activity = new() { Dock = DockStyle.Fill };
    private readonly ChecklistPanel _checklist = new() { Dock = DockStyle.Fill };
    private readonly TlsEnginePicker _tls;
    private readonly System.Windows.Forms.Timer _tick = new() { Interval = 300 };

    // ---- menu and status bar ----
    private readonly MenuStrip _menu = new();
    private readonly ToolStripMenuItem _mFile = new(), _mShowSecrets = new() { CheckOnClick = true }, _mViewSecrets = new(), _mFolder = new(), _mExit = new();
    private readonly ToolStripMenuItem _mView = new(), _mChecklist = new() { CheckOnClick = true }, _mHelp = new(), _mAbout = new();
    private readonly StatusStrip _status = new();
    private readonly ToolStripStatusLabel _sListen = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft }, _sEngine = new(), _sPlatform = new();

    // ---- site ----
    private readonly GroupBox _gSite; private readonly Label _lSite = UiHelpers.Value(9.5f, true), _lSiteInfo = UiHelpers.Value();
    private readonly Button _bCreate = new() { AutoSize = true }, _bListen = new() { AutoSize = true, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold) };

    // ---- access rules ----
    private readonly GroupBox _gRules; private readonly CheckBox _cUnknown = new() { AutoSize = true, MaximumSize = new Size(330, 0) };
    private readonly Label _lUnlock = UiHelpers.Value();
    private readonly NumericUpDown _nUnlock = new() { Minimum = 0.5m, Maximum = 60m, DecimalPlaces = 1, Increment = 0.5m, Width = 70 };

    // ---- device / secrets ----
    private readonly GroupBox _gDev; private readonly CheckBox _cSecrets = new() { AutoSize = true, MaximumSize = new Size(330, 0) }, _cUnknownMfr = new() { AutoSize = true, MaximumSize = new Size(330, 0) };
    private readonly Button _bViewSecrets = new() { AutoSize = true };

    // ---- readers ----
    private readonly Label _lReaders = new() { Dock = DockStyle.Top, Height = 24, Font = new Font("Segoe UI", 10f, FontStyle.Bold), Padding = new Padding(2, 4, 0, 0) };
    private readonly ListView _readers = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false, MultiSelect = false };
    private readonly Button _bAdd = new() { AutoSize = true, Font = new Font("Segoe UI", 9f, FontStyle.Bold) }, _bRemove = new() { AutoSize = true },
        _bUnlock = new() { AutoSize = true }, _bLock = new() { AutoSize = true }, _bAttack = new() { AutoSize = true };
    private readonly ContextMenuStrip _attackMenu = new();
    private string _readersSig = "";

    // ---- access list ----
    private readonly Label _lAccess = new() { Dock = DockStyle.Top, Height = 24, Font = new Font("Segoe UI", 10f, FontStyle.Bold), Padding = new Padding(2, 4, 0, 0) };
    private readonly DataGridView _grid = new() { Dock = DockStyle.Fill, AutoGenerateColumns = false, AllowUserToAddRows = true, RowHeadersWidth = 24, BackgroundColor = SystemColors.Window };
    private readonly Button _bAddLast = new() { AutoSize = true }, _bDelete = new() { AutoSize = true };
    private readonly Label _lLastCard = new() { AutoSize = true, Padding = new Padding(6, 6, 0, 0), ForeColor = SystemColors.GrayText };
    private BindingList<AccessEntry> _rows = null!;

    // ---- checklist bookkeeping ----
    private bool _sawGranted, _sawDenied, _attackSent;

    public MainForm(string folder)
    {
        _folder = folder;
        _settings = UiSettings.Load(folder);
        UiHelpers.ApplyLanguage(_settings);
        _engine = new AcuEngine(folder) { TlsEngine = UiHelpers.InitialEngine(_settings) };
        _tls = new TlsEnginePicker(_engine.TlsEngine);
        _engine.TlsEngine = _tls.Engine;

        Width = 1500; Height = 950; MinimumSize = new Size(1100, 700); StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9f);
        Icon = SystemIcons.Shield;

        // ---- left column ----
        (_gSite, var fSite) = UiHelpers.Group();
        fSite.Controls.AddRange(new Control[] { _lSite, _lSiteInfo, _bCreate, _bListen });
        (_gRules, var fRules) = UiHelpers.Group();
        fRules.Controls.AddRange(new Control[] { _cUnknown, UiHelpers.Row(_lUnlock, _nUnlock) });
        (_gDev, var fDev) = UiHelpers.Group();
        fDev.Controls.AddRange(new Control[] { _cSecrets, _bViewSecrets, _cUnknownMfr });
        var left = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(4) };
        left.Controls.AddRange(new Control[] { _gSite, _tls, _gRules, _gDev });

        // ---- readers panel ----
        foreach (var w in new[] { 150, 90, 130, 250, 60, 80, 70, 420 }) _readers.Columns.Add("", w);
        var readerButtons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(2) };
        readerButtons.Controls.AddRange(new Control[] { _bAdd, _bUnlock, _bLock, _bAttack, _bRemove });
        var readersPanel = new Panel { Dock = DockStyle.Fill };
        readersPanel.Controls.Add(_readers); readersPanel.Controls.Add(readerButtons); readersPanel.Controls.Add(_lReaders);

        // ---- access list panel ----
        _rows = new BindingList<AccessEntry>(_engine.Access.Entries);
        _grid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(AccessEntry.Facility), Width = 80 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(AccessEntry.Card), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(AccessEntry.Name), Width = 180 });
        _grid.Columns.Add(new DataGridViewCheckBoxColumn { DataPropertyName = nameof(AccessEntry.Allowed), Width = 70 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(AccessEntry.Notes), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _grid.DataSource = _rows;
        var accessButtons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(2) };
        accessButtons.Controls.AddRange(new Control[] { _bAddLast, _bDelete, _lLastCard });
        var accessPanel = new Panel { Dock = DockStyle.Fill };
        accessPanel.Controls.Add(_grid); accessPanel.Controls.Add(accessButtons); accessPanel.Controls.Add(_lAccess);

        var topSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        topSplit.Panel1.Controls.Add(readersPanel); topSplit.Panel2.Controls.Add(accessPanel);
        var centre = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        centre.Panel1.Controls.Add(topSplit); centre.Panel2.Controls.Add(_activity);
        var right = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel2 };
        right.Panel1.Controls.Add(centre); right.Panel2.Controls.Add(_checklist);
        var main = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
        main.Panel1.Controls.Add(left); main.Panel2.Controls.Add(right);
        Controls.Add(main); Controls.Add(_banner); Controls.Add(_status); Controls.Add(_menu);
        MainMenuStrip = _menu;
        Load += (_, _) =>
        {
            main.SplitterDistance = 385;
            right.SplitterDistance = Math.Max(400, right.Width - 330);
            right.Panel2Collapsed = !_settings.ChecklistVisible;
            centre.SplitterDistance = (int)(centre.Height * 0.48);
            topSplit.SplitterDistance = (int)(topSplit.Height * 0.45);
        };

        // ---- menu and status bar ----
        _mFile.DropDownItems.AddRange(new ToolStripItem[] { _mShowSecrets, _mViewSecrets, new ToolStripSeparator(), _mFolder, new ToolStripSeparator(), _mExit });
        _mView.DropDownItems.Add(_mChecklist);
        _mHelp.DropDownItems.Add(_mAbout);
        _menu.Items.AddRange(new ToolStripItem[] { _mFile, _mView, UiHelpers.LanguageMenu(l => { _settings.Language = L.Code(l); _settings.Save(_folder); }), _mHelp });
        _status.Items.AddRange(new ToolStripItem[] { _sListen, _sEngine, _sPlatform });
        _sPlatform.Text = Hpsp.Core.Transport.PlatformInfo.Describe();
        _mChecklist.Checked = _settings.ChecklistVisible;
        _mChecklist.CheckedChanged += (_, _) => { right.Panel2Collapsed = !_mChecklist.Checked; _settings.ChecklistVisible = _mChecklist.Checked; _settings.Save(_folder); };
        foreach (AttackKind k in Enum.GetValues<AttackKind>())
        {
            var item = new ToolStripMenuItem { Tag = k };
            item.Click += async (_, _) => await AttackAsync((AttackKind)item.Tag!);
            _attackMenu.Items.Add(item);
        }

        // ---- wiring ----
        _engine.Activity += e =>
        {
            if (e.Channel == "access" && e.Kind == ActivityKind.Good) _sawGranted = true;
            if (e.Channel == "access" && e.Kind == ActivityKind.Refused) _sawDenied = true;
            _activity.Add(e);
        };
        _engine.StateChanged += () => { if (IsHandleCreated) BeginInvoke(RefreshState); };
        _tls.EngineChanged += k =>
        {
            _engine.TlsEngine = k; _settings.TlsEngine = k.ToString(); _settings.Save(_folder);
            if (_engine.Listening) { _engine.Stop(); _engine.Start(); }   // the new engine applies to new connections
            RefreshState();
        };
        _mShowSecrets.CheckedChanged += (_, _) => SetSecrets(_mShowSecrets.Checked);
        _cSecrets.CheckedChanged += (_, _) => SetSecrets(_cSecrets.Checked);
        _mViewSecrets.Click += (_, _) => ViewSecrets();
        _bViewSecrets.Click += (_, _) => ViewSecrets();
        _mFolder.Click += (_, _) => { try { System.Diagnostics.Process.Start("explorer.exe", _folder); } catch { } };
        _mExit.Click += (_, _) => Close();
        _mAbout.Click += (_, _) => MessageBox.Show(this, L.T("HPSP ACU Simulator, version 0.6.0 (demo).\n\nA teaching demo of the High Performance Security Protocol: a simulated access control unit that pairs readers, keeps an access list, and sends signed grants to open doors over TLS 1.3.\n\nCopyright (c) 2026 Highpower Security Products LLC. Apache License 2.0.\nUses BouncyCastle (MIT licence)."), Text);
        _bCreate.Click += (_, _) => CreateSite();
        _bListen.Click += (_, _) => { if (_engine.Listening) _engine.Stop(); else _engine.Start(); RefreshState(); };
        _cUnknown.Checked = _engine.Access.AllowUnknownCards;
        _cUnknown.CheckedChanged += (_, _) => { _engine.Access.AllowUnknownCards = _cUnknown.Checked; _engine.SaveAccessList(); };
        _nUnlock.Value = Math.Clamp(_engine.Access.UnlockMs / 1000m, _nUnlock.Minimum, _nUnlock.Maximum);
        _nUnlock.ValueChanged += (_, _) => { _engine.Access.UnlockMs = (int)(_nUnlock.Value * 1000); _engine.SaveAccessList(); };
        _cUnknownMfr.Checked = _engine.AcceptUnknownManufacturers;
        _cUnknownMfr.CheckedChanged += (_, _) => _engine.AcceptUnknownManufacturers = _cUnknownMfr.Checked;
        _bAdd.Click += (_, _) => { using var d = new AddReaderDialog(_engine); d.ShowDialog(this); RefreshState(); };
        _bRemove.Click += (_, _) => RemoveReader();
        _bUnlock.Click += async (_, _) => await Try(async () => { if (SelectedSession() is { } s) await _engine.SendUnlockAsync(s, _engine.Access.UnlockMs, default, L.T("manual unlock")); });
        _bLock.Click += async (_, _) => await Try(async () => { if (SelectedSession() is { } s) await _engine.SendLockAsync(s); });
        _bAttack.Click += (_, _) => _attackMenu.Show(_bAttack, new Point(0, _bAttack.Height));
        _readers.SelectedIndexChanged += (_, _) => UpdateReaderButtons();
        _rows.ListChanged += (_, _) => _engine.SaveAccessList();
        _grid.CellValidating += ValidateCell;
        _grid.DataError += (_, e) => { e.ThrowException = false; e.Cancel = true; };
        _bAddLast.Click += (_, _) => AddLastCard();
        _bDelete.Click += (_, _) => { foreach (DataGridViewRow r in _grid.SelectedRows) if (!r.IsNewRow) _grid.Rows.Remove(r); };
        _tick.Tick += (_, _) => RefreshState();
        FormClosing += (_, _) => { _tick.Stop(); _engine.SaveAccessList(); _engine.Dispose(); };
        L.Changed += Relabel;

        _checklist.SetSteps(Steps());
        Relabel();
        if (_engine.HasSite) _engine.Start();
        _tick.Start();
    }

    // =========================================================================
    //  The provisioning checklist
    // =========================================================================

    private IEnumerable<ChecklistStep> Steps() => new[]
    {
        new ChecklistStep
        {
            Title = "Create the demo site",
            Explain = "Click \"Create demo site…\". The ACU makes the site root (which signs every certificate on the site), its own TLS certificate, and the grant signer, the separate key that signs every unlock. Tick \"Show secrets\" to look at the keys.",
            IsDone = () => _engine.HasSite,
        },
        new ChecklistStep
        {
            Title = "Start listening for readers",
            Explain = "Readers always call the ACU, never the other way round: the ACU listens on port 7500 (allow it through the Windows firewall if asked). Paired readers connect by themselves.",
            IsDone = () => _engine.Listening,
        },
        new ChecklistStep
        {
            Title = "Add cards to the access list",
            Explain = "Type a facility code (0-255), a card number (0-65535) and a name, and tick Allowed. Add one card that is allowed and one that is not, to see both outcomes. \"Add last card\" adds the card that was just swiped.",
            IsDone = () => _engine.Access.Entries.Count > 0,
        },
        new ChecklistStep
        {
            Title = "Press the reader's pairing button",
            Explain = "In the Reader Simulator, click \"Open pairing window\". A reader accepts pairing only for 10 minutes after its button is pressed, which proves someone is at the device.",
            IsDone = () => _engine.PairedReaders.Count > 0, ManualTick = true,
        },
        new ChecklistStep
        {
            Title = "Add the reader",
            Explain = "Click \"Add reader…\" and enter the reader's address, its pairing port and its setup code (or paste its QR text). SPAKE2+ proves both sides know the code without sending it; then, inside TLS, the ACU checks the reader's factory identity and gives it a site certificate.",
            IsDone = () => _engine.PairedReaders.Any(r => !r.Removed),
        },
        new ChecklistStep
        {
            Title = "Reader comes online",
            Explain = "The reader dials the ACU over TLS 1.3. Both sides show certificates from this site's root. The reader's hello carries a fresh session value; the ACU replies and sends trust_update with the grant signer's certificate.",
            IsDone = () => _engine.Sessions.Any(s => s.HelloDone),
        },
        new ChecklistStep
        {
            Title = "Swipe an allowed card",
            Explain = "Swipe a card from the list on the reader. The ACU finds it allowed, has the grant signer sign a grant for this reader, this session and a new counter, and sends unlock. The reader checks the signature and opens the door.",
            IsDone = () => _sawGranted,
        },
        new ChecklistStep
        {
            Title = "Swipe a refused card",
            Explain = "Swipe a card that is not allowed (or not in the list). No grant is made at all, so there is nothing the reader could act on; the ACU just flashes the reader's LED red.",
            IsDone = () => _sawDenied,
        },
        new ChecklistStep
        {
            Title = "Try an attack",
            Explain = "Select the online reader and use \"Attack demo\": replay an old grant, send an expired one, one for a previous session, a tampered one, or one from an untrusted key. The reader refuses each, keeps the door locked and reports a security event.",
            IsDone = () => _attackSent,
        },
    };

    // =========================================================================
    //  Actions
    // =========================================================================

    private void CreateSite()
    {
        using var d = new CreateSiteDialog(_engine.HasSite);
        if (d.ShowDialog(this) != DialogResult.OK) return;
        _engine.CreateSite(d.SiteName, d.Names, d.Endpoint, d.Port);
        _engine.Start();
        RefreshState();
    }

    private void RemoveReader()
    {
        if (_readers.SelectedItems.Count == 0 || _readers.SelectedItems[0].Tag is not Guid id) return;
        if (MessageBox.Show(this, L.T("Remove this reader? Its site certificate is revoked and it will be refused if it connects. To use it again, factory-reset it and pair it again."), L.T("Remove reader"), MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK) return;
        _engine.RemoveReader(id);
        RefreshState();
    }

    /// <summary>Run a button's action; if the reader went away meanwhile, say so instead of crashing.</summary>
    private async Task Try(Func<Task> action)
    {
        try { await action(); }
        catch (Exception e) when (e is InvalidOperationException or IOException or ObjectDisposedException) { MessageBox.Show(this, e.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    private async Task AttackAsync(AttackKind kind)
    {
        if (SelectedSession() is not { } s) { MessageBox.Show(this, L.T("Select a reader that is online first."), L.T("Attack demo")); return; }
        string? err;
        try { err = await _engine.AttackAsync(s, kind); }
        catch (Exception e) when (e is InvalidOperationException or IOException or ObjectDisposedException) { err = e.Message; }
        if (err is null) _attackSent = true;
        else MessageBox.Show(this, err, L.T("Attack demo"));
    }

    private void AddLastCard()
    {
        if (_engine.LastCard is not { } c) { MessageBox.Show(this, L.T("No card has been swiped yet."), L.T("Add last card")); return; }
        if (_engine.Access.Find(c.Facility, c.Card) is { } existing)
        {
            int i = _rows.IndexOf(existing);
            if (i >= 0) { _grid.ClearSelection(); _grid.Rows[i].Selected = true; _grid.CurrentCell = _grid.Rows[i].Cells[2]; }
            return;
        }
        _rows.Add(new AccessEntry { Facility = c.Facility, Card = c.Card, Name = "", Allowed = true, Notes = L.F("added from {0}", c.Reader) });
        _engine.SaveAccessList();
    }

    private void ValidateCell(object? sender, DataGridViewCellValidatingEventArgs e)
    {
        if (_grid.Rows[e.RowIndex].IsNewRow) return;
        int max = e.ColumnIndex switch { 0 => 255, 1 => 65535, _ => -1 };
        if (max < 0) return;
        if (!int.TryParse(Convert.ToString(e.FormattedValue), out int v) || v < 0 || v > max)
        {
            e.Cancel = true;
            _grid.Rows[e.RowIndex].ErrorText = L.F("Enter a whole number from 0 to {0}.", max);
        }
        else _grid.Rows[e.RowIndex].ErrorText = "";
    }

    private ReaderSession? SelectedSession()
    {
        if (_readers.SelectedItems.Count == 0 || _readers.SelectedItems[0].Tag is not Guid id) return null;
        return _engine.Sessions.FirstOrDefault(s => s.DeviceId == id && s.HelloDone);
    }

    private void SetSecrets(bool on)
    {
        if (_mShowSecrets.Checked != on) _mShowSecrets.Checked = on;
        if (_cSecrets.Checked != on) _cSecrets.Checked = on;
        _banner.Visible = on;
        _activity.ShowSecrets = on;
    }

    private void ViewSecrets()
    {
        // Viewing the keys always goes through the "show secrets" switch, so the red banner is
        // up whenever secrets are on screen. If it is off, offer to turn it on.
        if (!_cSecrets.Checked)
        {
            if (MessageBox.Show(this, L.T("Secrets are hidden. Turn on \"Show secrets\" to view them?\n\nThis also shows the secret values (keys, pairing values) in the activity window's details, and puts up the red banner."),
                    L.T("Show secrets"), MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            SetSecrets(true);
        }
        UiHelpers.ShowText(this, L.T("ACU secrets (demo only)"), _engine.SecretsText());
    }

    // =========================================================================
    //  Showing state
    // =========================================================================

    private void Relabel()
    {
        Text = L.T("HPSP ACU Simulator") + (_engine.HasSite ? $"  -  {_engine.SiteName}" : "");
        _mFile.Text = L.T("&File"); _mShowSecrets.Text = L.T("Show secrets (keys, pairing values) in this window - demo only"); _mViewSecrets.Text = L.T("View the ACU's secrets…");
        _mFolder.Text = L.T("Open the data folder"); _mExit.Text = L.T("E&xit");
        _mView.Text = L.T("&View"); _mChecklist.Text = L.T("Provisioning checklist"); _mHelp.Text = L.T("&Help"); _mAbout.Text = L.T("About");
        _gSite.Text = L.T("Site"); _bCreate.Text = L.T("Create demo site…");
        _gRules.Text = L.T("Access rules"); _cUnknown.Text = L.T("Allow cards that are not in the access list"); _lUnlock.Text = L.T("Unlock time (seconds):");
        _gDev.Text = L.T("Demo settings"); _cSecrets.Text = L.T("Show secrets (keys, pairing values) in this window - demo only"); _bViewSecrets.Text = L.T("View secrets…");
        _cUnknownMfr.Text = L.T("Accept readers from any manufacturer (demo; a real site checks a trusted list)");
        _lReaders.Text = L.T("Readers");
        string[] rc = { L.T("Name"), L.T("Status"), L.T("Address"), L.T("Device ID"), L.T("Events"), L.T("Door"), L.T("Grants"), "TLS" };
        for (int i = 0; i < rc.Length; i++) _readers.Columns[i].Text = rc[i];
        _bAdd.Text = L.T("Add reader…"); _bRemove.Text = L.T("Remove…"); _bUnlock.Text = L.T("Manual unlock"); _bLock.Text = L.T("Lock"); _bAttack.Text = L.T("Attack demo ▾");
        foreach (ToolStripMenuItem item in _attackMenu.Items) item.Text = AcuEngine.Describe((AttackKind)item.Tag!);
        _lAccess.Text = L.T("Access list");
        string[] gc = { L.T("Facility"), L.T("Card"), L.T("Name"), L.T("Allowed"), L.T("Notes") };
        for (int i = 0; i < gc.Length; i++) _grid.Columns[i].HeaderText = gc[i];
        _bAddLast.Text = L.T("Add last card"); _bDelete.Text = L.T("Delete selected");
        _readersSig = "";
        RefreshState();
    }

    private void RefreshState()
    {
        if (IsDisposed) return;
        var e = _engine;

        // Site
        if (e.HasSite)
        {
            _lSite.Text = e.SiteName; _lSite.ForeColor = SystemColors.ControlText;
            _lSiteInfo.Text = string.Join("\n", new[]
            {
                L.F("Site ID: {0}", e.SiteId),
                L.F("Root: {0}", e.SiteRoot is { } r ? Hpsp.Core.Security.DemoPki.Fingerprint(r) : "-"),
                L.F("Grant signer: {0}", e.SignerCertificate is { } g ? Hpsp.Core.Security.DemoPki.Fingerprint(g) : "-"),
                L.F("ACU certificate names: {0}", string.Join(", ", e.AcuNames)),
                L.F("Readers are told to dial: {0}:{1}", e.EndpointHost, e.ListenPort),
                L.F("Trust epoch: {0}    Grants signed: {1}", e.TrustEpoch, e.GrantCounter),
            });
            _bCreate.Text = L.T("Create a new demo site…");
        }
        else { _lSite.Text = L.T("No site yet"); _lSite.ForeColor = Color.FromArgb(170, 95, 0); _lSiteInfo.Text = L.T("Create a demo site to make the keys and certificates."); }
        _bListen.Enabled = e.HasSite;
        _bListen.Text = e.Listening ? L.T("Stop listening") : L.F("Start listening on port {0}", e.ListenPort);

        // Readers list: rebuilt only when something shown has changed.
        var sessions = e.Sessions.ToDictionary(s => s.DeviceId);
        var rows = e.PairedReaders.Select(r =>
        {
            sessions.TryGetValue(r.DeviceId, out var s);
            string status = r.Removed ? L.T("removed") : s is { HelloDone: true } ? L.T("online") : L.T("offline");
            return (r.DeviceId, Cells: new[] { r.Name, status, s?.Address ?? "", r.DeviceId.ToString(), s?.EventsReceived.ToString() ?? "", s?.DoorState ?? "", r.GrantCounter.ToString(), s?.Tls is { } t ? $"{t.Protocol} · {t.Cipher}" + (t.KeyExchange is null ? "" : " · " + t.KeyExchange) : "" }, Online: s is { HelloDone: true }, r.Removed);
        }).ToList();
        string sig = string.Join("|", rows.Select(x => string.Join(",", x.Cells)));
        if (sig != _readersSig)
        {
            _readersSig = sig;
            Guid? sel = _readers.SelectedItems.Count > 0 ? _readers.SelectedItems[0].Tag as Guid? : null;
            _readers.BeginUpdate();
            _readers.Items.Clear();
            foreach (var row in rows)
            {
                var item = new ListViewItem(row.Cells) { Tag = row.DeviceId };
                item.ForeColor = row.Removed ? SystemColors.GrayText : row.Online ? Color.FromArgb(0, 110, 40) : SystemColors.ControlText;
                _readers.Items.Add(item);
                if (row.DeviceId == sel) item.Selected = true;
            }
            if (_readers.SelectedItems.Count == 0 && _readers.Items.Count > 0) _readers.Items[^1].Selected = true;
            _readers.EndUpdate();
        }
        UpdateReaderButtons();

        _lLastCard.Text = e.LastCard is { } c ? L.F("Last card: FC {0}, card {1} at {2}", c.Facility, c.Card, c.Reader) : "";
        _sListen.Text = e.Listening ? L.F("Listening on port {0}. {1} reader(s) online.", e.ListenPort, e.Sessions.Count(s => s.HelloDone)) : L.T("Not listening");
        _sEngine.Text = L.F("TLS: {0}", TlsEnginePicker.EngineName(e.TlsEngine));
        _checklist.Refresh();
    }

    private void UpdateReaderButtons()
    {
        bool online = SelectedSession() is not null;
        _bUnlock.Enabled = _bLock.Enabled = _bAttack.Enabled = online;
        _bRemove.Enabled = _readers.SelectedItems.Count > 0 && !(_readers.SelectedItems[0].SubItems[1].Text == L.T("removed"));
        _bAdd.Enabled = _engine.HasSite;
    }
}
