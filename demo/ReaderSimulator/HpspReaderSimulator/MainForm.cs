// =============================================================================
//  HPSP Demo  -  Reader Simulator
//  File:    MainForm.cs
//  Purpose: The reader's window. All protocol work happens in
//           Hpsp.Core.Engine.ReaderEngine; this file only shows its state and
//           passes on button presses.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  WHAT THE PANELS ARE
//  -------------------
//   This reader     its identity and setup code, as printed on a real
//                   reader's label (and as a QR code)
//   Pairing         the "pairing button": opens a 10-minute window during
//                   which an ACU may pair with it
//   Connection      the session with the ACU, and a simulated network cable
//   TLS engine      which TLS 1.3 code to use for sessions
//   Card            type a facility code and card number, then "Swipe"
//   Door and LED    what the door strike and the LED are doing
//   Device          factory reset, new device, show secrets
// =============================================================================

using Hpsp.Core.Cards;
using Hpsp.Core.Engine;
using Hpsp.Core.Localization;
using Hpsp.Demo.Ui;
using QRCoder;

namespace HpspReaderSimulator;

public sealed class MainForm : Form
{
    private readonly ReaderEngine _engine;
    private readonly UiSettings _settings;
    private readonly string _folder;
    private readonly int _instance;

    // ---- shared pieces ----
    private readonly SecretsBanner _banner = new();
    private readonly ActivityView _activity = new() { Dock = DockStyle.Fill };
    private readonly ChecklistPanel _checklist = new() { Dock = DockStyle.Fill };
    private readonly TlsEnginePicker _tls;
    private readonly System.Windows.Forms.Timer _tick = new() { Interval = 200 };

    // ---- menu and status bar ----
    private readonly MenuStrip _menu = new();
    private readonly ToolStripMenuItem _mFile = new(), _mShowSecrets = new() { CheckOnClick = true }, _mViewSecrets = new(), _mFolder = new(), _mExit = new();
    private readonly ToolStripMenuItem _mView = new(), _mChecklist = new() { CheckOnClick = true };
    private readonly ToolStripMenuItem _mHelp = new(), _mAbout = new();
    private readonly StatusStrip _status = new();
    private readonly ToolStripStatusLabel _sConn = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft }, _sPlatform = new(), _sEngine = new();

    // ---- this reader ----
    private readonly GroupBox _gId; private readonly Label _lIdCaption = UiHelpers.Value(), _lId = UiHelpers.Value(), _lSerial = UiHelpers.Value();
    private readonly Label _lCodeCaption = UiHelpers.Value(), _lCode = new() { AutoSize = true, Font = new Font("Consolas", 20f, FontStyle.Bold), ForeColor = Color.FromArgb(20, 40, 110) };
    private readonly PictureBox _qr = new() { Size = new Size(150, 150), SizeMode = PictureBoxSizeMode.Zoom, BorderStyle = BorderStyle.FixedSingle };
    private readonly Button _bCopyQr = new() { AutoSize = true };
    private string _qrFor = "";

    // ---- pairing ----
    private readonly GroupBox _gPair; private readonly Label _lPair = UiHelpers.Value(9.5f, true), _lPairInfo = UiHelpers.Value();
    private readonly Button _bPair = new() { AutoSize = true, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold) };

    // ---- connection ----
    private readonly GroupBox _gConn; private readonly Label _lConn = UiHelpers.Value(9.5f, true), _lConnInfo = UiHelpers.Value();
    private readonly Button _bCable = new() { AutoSize = true };

    // ---- card ----
    private readonly GroupBox _gCard; private readonly Label _lFc = UiHelpers.Value(), _lCard = UiHelpers.Value(), _lBits = new() { AutoSize = true, Font = new Font("Consolas", 9f), MaximumSize = new Size(330, 0) };
    private readonly NumericUpDown _nFc = new() { Minimum = 0, Maximum = 255, Value = 142, Width = 70 }, _nCard = new() { Minimum = 0, Maximum = 65535, Value = 54321, Width = 90 };
    private readonly Button _bSwipe = new() { AutoSize = true, Font = new Font("Segoe UI", 11f, FontStyle.Bold), Padding = new Padding(10, 2, 10, 2) };

    // ---- door and LED ----
    private readonly GroupBox _gDoor;
    private readonly Label _door = new() { Size = new Size(200, 54), TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI", 12f, FontStyle.Bold), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };
    private readonly Panel _led = new() { Size = new Size(40, 40), Margin = new Padding(12, 7, 3, 3) };
    private readonly Label _lLed = UiHelpers.Value();

    // ---- device ----
    private readonly GroupBox _gDev; private readonly CheckBox _cSecrets = new() { AutoSize = true, MaximumSize = new Size(330, 0) };
    private readonly Button _bViewSecrets = new() { AutoSize = true }, _bReset = new() { AutoSize = true }, _bNew = new() { AutoSize = true };

    // ---- checklist bookkeeping (things the engine does not remember) ----
    private bool _swipedOnline, _sawUnlock, _cablePulledOnce, _cableTestDone;

    public MainForm(string folder, int pairingPort, int instance)
    {
        _folder = folder; _instance = instance;
        _settings = UiSettings.Load(folder);
        UiHelpers.ApplyLanguage(_settings);
        _engine = new ReaderEngine(folder) { PairingPort = pairingPort, TlsEngine = UiHelpers.InitialEngine(_settings) };
        _tls = new TlsEnginePicker(_engine.TlsEngine);
        _engine.TlsEngine = _tls.Engine;     // greyed-out Windows choice on Windows 10 falls back to BouncyCastle

        Width = 1400; Height = 900; MinimumSize = new Size(1000, 640); StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9f);
        Icon = SystemIcons.Shield;

        // ---- groups on the left ----
        (_gId, var fId) = UiHelpers.Group();
        fId.Controls.AddRange(new Control[] { _lIdCaption, _lId, _lSerial, _lCodeCaption, _lCode, _qr, _bCopyQr });
        (_gPair, var fPair) = UiHelpers.Group();
        fPair.Controls.AddRange(new Control[] { _lPair, _lPairInfo, _bPair });
        (_gConn, var fConn) = UiHelpers.Group();
        fConn.Controls.AddRange(new Control[] { _lConn, _lConnInfo, _bCable });
        (_gCard, var fCard) = UiHelpers.Group();
        fCard.Controls.AddRange(new Control[] { UiHelpers.Row(_lFc, _nFc, _lCard, _nCard), _lBits, _bSwipe });
        (_gDoor, var fDoor) = UiHelpers.Group();
        fDoor.Controls.AddRange(new Control[] { UiHelpers.Row(_door, _led), _lLed });
        (_gDev, var fDev) = UiHelpers.Group();
        fDev.Controls.AddRange(new Control[] { _cSecrets, UiHelpers.Row(_bViewSecrets), UiHelpers.Row(_bReset, _bNew) });

        var left = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(4) };
        left.Controls.AddRange(new Control[] { _gId, _gPair, _gConn, _gCard, _gDoor, _tls, _gDev });

        var right = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel2 };
        right.Panel1.Controls.Add(_activity);
        right.Panel2.Controls.Add(_checklist);
        var main = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
        main.Panel1.Controls.Add(left);
        main.Panel2.Controls.Add(right);
        Controls.Add(main);
        Controls.Add(_banner);
        Controls.Add(_status);
        Controls.Add(_menu);
        MainMenuStrip = _menu;
        Load += (_, _) =>
        {
            main.SplitterDistance = 385;
            right.SplitterDistance = Math.Max(300, right.Width - 330);
            right.Panel2Collapsed = !_settings.ChecklistVisible;
        };

        // ---- menu and status bar ----
        _mFile.DropDownItems.AddRange(new ToolStripItem[] { _mShowSecrets, _mViewSecrets, new ToolStripSeparator(), _mFolder, new ToolStripSeparator(), _mExit });
        _mView.DropDownItems.Add(_mChecklist);
        _mHelp.DropDownItems.Add(_mAbout);
        _menu.Items.AddRange(new ToolStripItem[] { _mFile, _mView, UiHelpers.LanguageMenu(l => { _settings.Language = L.Code(l); _settings.Save(_folder); }), _mHelp });
        _status.Items.AddRange(new ToolStripItem[] { _sConn, _sEngine, _sPlatform });
        _sPlatform.Text = Hpsp.Core.Transport.PlatformInfo.Describe();
        _mChecklist.Checked = _settings.ChecklistVisible;
        _mChecklist.CheckedChanged += (_, _) => { right.Panel2Collapsed = !_mChecklist.Checked; _settings.ChecklistVisible = _mChecklist.Checked; _settings.Save(_folder); };

        // ---- wiring ----
        _engine.Activity += _activity.Add;
        _engine.StateChanged += () => { if (IsHandleCreated) BeginInvoke(RefreshState); };
        _tls.EngineChanged += k => { _engine.TlsEngine = k; _settings.TlsEngine = k.ToString(); _settings.Save(_folder); RefreshState(); };
        _mShowSecrets.CheckedChanged += (_, _) => SetSecrets(_mShowSecrets.Checked);
        _cSecrets.CheckedChanged += (_, _) => SetSecrets(_cSecrets.Checked);
        _mViewSecrets.Click += (_, _) => ViewSecrets();
        _bViewSecrets.Click += (_, _) => ViewSecrets();
        _mFolder.Click += (_, _) => { try { System.Diagnostics.Process.Start("explorer.exe", _folder); } catch { } };
        _mExit.Click += (_, _) => Close();
        _mAbout.Click += (_, _) => MessageBox.Show(this, L.T("HPSP Reader Simulator, version 0.6.0 (demo).\n\nA teaching demo of the High Performance Security Protocol: a simulated card reader that pairs with an ACU, reports 26-bit card swipes over TLS 1.3, and opens its door only for a valid signed grant.\n\nCopyright (c) 2026 Highpower Security Products LLC. Apache License 2.0.\nUses BouncyCastle (MIT licence) and QRCoder (MIT licence)."), Text);
        _bCopyQr.Click += (_, _) => { Clipboard.SetText(_engine.QrText); _bCopyQr.Text = L.T("Copied"); };
        _bPair.Click += (_, _) => { if (_engine.PairingWindowOpen) _engine.ClosePairingWindow(); else _engine.OpenPairingWindow(); RefreshState(); };
        _bCable.Click += (_, _) =>
        {
            if (_engine.CablePulled) _engine.PlugCable();
            else { _engine.PullCable(); _cablePulledOnce = true; }
            RefreshState();
        };
        _nFc.ValueChanged += (_, _) => ShowBits();
        _nCard.ValueChanged += (_, _) => ShowBits();
        _bSwipe.Click += (_, _) =>
        {
            if (_engine.Connected) _swipedOnline = true;
            _engine.SwipeCard((int)_nFc.Value, (int)_nCard.Value);
        };
        _bReset.Click += (_, _) =>
        {
            if (MessageBox.Show(this, L.T("Factory reset removes this reader's site certificate and site settings. It keeps its factory identity and setup code, so it can be paired again.\n\nReset now?"), L.T("Factory reset"), MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK) return;
            _engine.FactoryReset(); ResetChecklistFlags(); RefreshState();
        };
        _bNew.Click += (_, _) =>
        {
            if (MessageBox.Show(this, L.T("Make this a brand-new simulated reader: new device ID, new factory identity and new setup code. The current one is forgotten (an ACU that paired it will no longer recognise it).\n\nContinue?"), L.T("New device"), MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK) return;
            _engine.NewDevice(); ResetChecklistFlags(); RefreshState();
        };
        _tick.Tick += (_, _) => RefreshState();
        FormClosing += (_, _) => { _tick.Stop(); _engine.Dispose(); };
        L.Changed += Relabel;

        _checklist.SetSteps(Steps());
        Relabel();
        ShowBits();
        _engine.Start();
        _tick.Start();
    }

    // =========================================================================
    //  The provisioning checklist
    // =========================================================================

    private IEnumerable<ChecklistStep> Steps() => new[]
    {
        new ChecklistStep
        {
            Title = "Note the setup code",
            Explain = "A real reader has its setup code printed on a label (often also as a QR code). The installer types it into the ACU, or scans it. The code itself never crosses the network: the two sides use it in SPAKE2+, which proves both know it without revealing it.",
            IsDone = () => _engine.PairingWindowOpen || _engine.IsPaired, ManualTick = true,
        },
        new ChecklistStep
        {
            Title = "Press the pairing button",
            Explain = "Click \"Open pairing window\". This stands for a button inside the reader's case: it proves someone is physically at the device. Only now does the reader listen for pairing (port shown in the Pairing panel), for 10 minutes. After 5 wrong codes it locks pairing for 5 minutes.",
            IsDone = () => _engine.PairingWindowOpen || _engine.IsPaired,
        },
        new ChecklistStep
        {
            Title = "Add the reader from the ACU",
            Explain = "In the ACU Simulator, click \"Add reader…\" and give this computer's address, the pairing port and the setup code (or paste the QR text). Watch the activity: pake_params and pake_share (SPAKE2+), then TLS with the shared key, then attest_request, enroll and cert_install.",
            IsDone = () => _engine.IsPaired,
        },
        new ChecklistStep
        {
            Title = "Reader connects to the ACU",
            Explain = "Once it has a site certificate the reader dials the ACU (port 7500) over TLS 1.3 with mutual certificates, and sends hello with a fresh 32-byte session value. Every grant for this session must include that value. The Connection panel shows the key exchange: SecP256r1MLKEM768 is hybrid post-quantum, so a recording of this session stays private even from a future quantum computer.",
            IsDone = () => _engine.Connected,
        },
        new ChecklistStep
        {
            Title = "Receive the trust list",
            Explain = "The ACU sends trust_update with the grant signer's certificate. From now on the reader opens its door only for grants signed by that key, for this reader, for this session, with a counter it has not seen before.",
            IsDone = () => _engine.SignerCount > 0,
        },
        new ChecklistStep
        {
            Title = "Swipe a card",
            Explain = "Enter a facility code and card number and click Swipe. The reader packs them as 26-bit H10301 Wiegand data and sends a credential event. The reader itself decides nothing: the ACU checks its access list.",
            IsDone = () => _swipedOnline,
        },
        new ChecklistStep
        {
            Title = "See the door open (or not)",
            Explain = "For an allowed card the ACU sends unlock with a signed grant and turns the LED green; the reader checks the grant and opens the door for the unlock time. For a refused card the LED flashes red and the door stays locked. Try both.",
            IsDone = () => _sawUnlock,
        },
        new ChecklistStep
        {
            Title = "Pull the network cable",
            Explain = "Click \"Pull network cable\", swipe a card while offline, then plug the cable back in. The reader keeps events until the ACU acknowledges them, so the offline swipe is replayed after reconnecting. (The ACU logs it but opens no door: the card read is too old.)",
            IsDone = () => _cableTestDone,
        },
    };

    private void ResetChecklistFlags() { _swipedOnline = _sawUnlock = _cablePulledOnce = _cableTestDone = false; }

    // =========================================================================
    //  Showing state
    // =========================================================================

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
        UiHelpers.ShowText(this, L.T("Reader secrets (demo only)"), _engine.SecretsText());
    }

    private void ShowBits()
    {
        bool[] bits = Wiegand26.ToBits((int)_nFc.Value, (int)_nCard.Value);
        _lBits.Text = L.F("26 bits (parity, facility, card, parity):\n{0}\nAs sent: {1}", Wiegand26.Describe(bits), Convert.ToHexString(Wiegand26.Pack(bits)).ToLowerInvariant());
    }

    private void Relabel()
    {
        Text = L.T("HPSP Reader Simulator") + (_instance > 1 ? $" #{_instance}" : "") + $"  -  {_engine.Serial}";
        _mFile.Text = L.T("&File"); _mShowSecrets.Text = L.T("Show secrets (keys, pairing values) in this window - demo only"); _mViewSecrets.Text = L.T("View this reader's secrets…");
        _mFolder.Text = L.T("Open the data folder"); _mExit.Text = L.T("E&xit");
        _mView.Text = L.T("&View"); _mChecklist.Text = L.T("Provisioning checklist");
        _mHelp.Text = L.T("&Help"); _mAbout.Text = L.T("About");
        _gId.Text = L.T("This reader"); _lIdCaption.Text = L.T("Device ID (from the factory):");
        _lCodeCaption.Text = L.T("Setup code (printed on the label):");
        _bCopyQr.Text = L.T("Copy QR text (to paste into the ACU)");
        _gPair.Text = L.T("Pairing"); _gConn.Text = L.T("Connection to the ACU");
        _gCard.Text = L.T("Card (26-bit H10301)"); _lFc.Text = L.T("Facility"); _lCard.Text = L.T("Card"); _bSwipe.Text = L.T("Swipe card");
        _gDoor.Text = L.T("Door and LED");
        _gDev.Text = L.T("Device"); _cSecrets.Text = L.T("Show secrets (keys, pairing values) in this window - demo only"); _bViewSecrets.Text = L.T("View secrets…");
        _bReset.Text = L.T("Factory reset…"); _bNew.Text = L.T("New device…");
        ShowBits();
        RefreshState();
    }

    private void RefreshState()
    {
        if (IsDisposed) return;
        var e = _engine;

        // This reader
        _lId.Text = e.DeviceId.ToString();
        _lSerial.Text = L.F("Serial number: {0}", e.Serial);
        _lCode.Text = e.SetupCode;
        if (_qrFor != e.QrText)
        {
            _qrFor = e.QrText;
            using var gen = new QRCodeGenerator();
            var png = new PngByteQRCode(gen.CreateQrCode(e.QrText, QRCodeGenerator.ECCLevel.M)).GetGraphic(6);
            var old = _qr.Image; _qr.Image = Image.FromStream(new MemoryStream(png)); old?.Dispose();
        }

        // Pairing
        if (e.IsPaired) { _lPair.Text = L.T("Paired"); _lPair.ForeColor = Color.FromArgb(0, 120, 40); _lPairInfo.Text = L.F("Site {0}\nACU address: {1}", e.SiteId, e.Endpoint); _bPair.Visible = false; }
        else if (e.LockedOut) { _lPair.Text = L.T("Pairing locked"); _lPair.ForeColor = Color.FromArgb(180, 0, 0); _lPairInfo.Text = L.F("Too many wrong setup codes. Try again at {0:T}.", e.LockedOutUntil); _bPair.Visible = false; }
        else if (e.PairingWindowOpen)
        {
            _lPair.Text = L.F("Pairing window open ({0} left)", UiHelpers.Countdown(e.PairingWindowUntil)); _lPair.ForeColor = Color.FromArgb(20, 90, 200);
            _lPairInfo.Text = L.F("Listening on port {0}. Add this reader from the ACU now. Wrong codes so far: {1} of {2}.", e.PairingPort, e.FailedAttempts, ReaderEngine.MaxFailedAttempts);
            _bPair.Visible = true; _bPair.Text = L.T("Close pairing window");
        }
        else
        {
            _lPair.Text = L.T("Not paired"); _lPair.ForeColor = SystemColors.ControlText;
            _lPairInfo.Text = L.F("Press the pairing button to let an ACU pair with this reader (pairing port {0}).", e.PairingPort) + (e.FailedAttempts > 0 ? "\n" + L.F("Wrong codes so far: {0} of {1}.", e.FailedAttempts, ReaderEngine.MaxFailedAttempts) : "");
            _bPair.Visible = true; _bPair.Text = L.T("Open pairing window (press the pairing button)");
        }

        // Connection
        if (e.CablePulled) { _lConn.Text = L.T("Network cable unplugged"); _lConn.ForeColor = Color.FromArgb(170, 95, 0); }
        else if (e.Connected) { _lConn.Text = L.T("Online"); _lConn.ForeColor = Color.FromArgb(0, 120, 40); }
        else { _lConn.Text = L.T("Offline"); _lConn.ForeColor = SystemColors.GrayText; }
        _lConnInfo.Text = string.Join("\n", new[]
        {
            L.F("Status: {0}", e.ConnectionStatus),
            e.Tls is { } t ? L.F("TLS: {0}, {1}", t.Protocol, t.Cipher) : null,
            e.Tls is { } t2 ? L.F("Key exchange: {0}", t2.KeyExchange ?? L.T("not reported by the Windows TLS engine")) : null,
            e.SessionNonce is { } n ? L.F("Session value: {0}", MessageSummary.Short(n)) : null,
            e.IsPaired ? L.F("Trust list: epoch {0}, {1} grant signer(s)", e.TrustEpoch, e.SignerCount) : null,
            L.F("Events waiting for acknowledgement: {0}", e.PendingEventCount),
            e.IsPaired ? L.F("Grant counter floor: {0}", e.GrantFloor) : null,
        }.Where(x => x is not null));
        _bCable.Text = e.CablePulled ? L.T("Plug the network cable back in") : L.T("Pull network cable (simulate an outage)");
        _bCable.Enabled = e.IsPaired;
        _bSwipe.Enabled = true;

        // Door and LED
        if (e.DoorUnlocked)
        {
            _sawUnlock = true;
            _door.BackColor = Color.FromArgb(0, 150, 60);
            string left = UiHelpers.Countdown(e.DoorRelocksAt);
            _door.Text = L.T("UNLOCKED") + (left.Length > 0 ? "\n" + left : "");
        }
        else { _door.BackColor = Color.FromArgb(170, 30, 30); _door.Text = L.T("LOCKED"); }
        bool ledOn = e.LedColor != "off" && (e.LedUntil is null || e.LedUntil > DateTime.Now);
        bool blinkPhase = e.LedPattern == "blink" && DateTime.Now.Millisecond % 400 >= 200;
        _led.BackColor = !ledOn || blinkPhase ? Color.FromArgb(60, 60, 60) : e.LedColor switch
        {
            "green" => Color.LimeGreen, "red" => Color.Red, "amber" or "yellow" => Color.Orange, "blue" => Color.DodgerBlue, "white" => Color.White, _ => Color.Gray,
        };
        _lLed.Text = ledOn ? L.F("LED: {0}, {1}", e.LedColor, e.LedPattern) : L.T("LED: off");

        // Cable test for the checklist: pulled, plugged in again, reconnected and caught up.
        if (_cablePulledOnce && !e.CablePulled && e.Connected && e.PendingEventCount == 0) _cableTestDone = true;

        _sConn.Text = e.IsPaired ? L.F("{0}   ACU {1}", _lConn.Text, e.Endpoint) : _lPair.Text;
        _sEngine.Text = L.F("TLS: {0}", TlsEnginePicker.EngineName(e.TlsEngine));
        _checklist.Refresh();
    }
}
