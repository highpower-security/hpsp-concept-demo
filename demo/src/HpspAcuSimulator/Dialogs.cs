// =============================================================================
//  HPSP Demo  -  ACU Simulator
//  File:    Dialogs.cs
//  Purpose: "Create demo site" and "Add reader" dialogs.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================

using Hpsp.Core.Engine;
using Hpsp.Core.Localization;
using Hpsp.Demo.Ui;

namespace HpspAcuSimulator;

/// <summary>
/// Create a site: its root certificate, the ACU's TLS certificate and the grant signer.
/// The ACU certificate lists the names and addresses readers may use to reach this
/// computer; readers check that the address they dial is one of them.
/// </summary>
internal sealed class CreateSiteDialog : Form
{
    private readonly TextBox _name = new() { Width = 320, Text = "HPSP Demo Site" };
    private readonly CheckedListBox _names = new() { Width = 320, Height = 120, CheckOnClick = true };
    private readonly ComboBox _endpoint = new() { Width = 320, DropDownStyle = ComboBoxStyle.DropDown };
    private readonly NumericUpDown _port = new() { Minimum = 1024, Maximum = 65535, Value = 7500, Width = 90 };

    public string SiteName => _name.Text.Trim().Length > 0 ? _name.Text.Trim() : "HPSP Demo Site";
    public IEnumerable<string> Names => _names.CheckedItems.Cast<string>();
    public string Endpoint => _endpoint.Text.Trim();
    public int Port => (int)_port.Value;

    public CreateSiteDialog(bool replacing)
    {
        Text = L.T("Create demo site"); FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(10); Font = new Font("Segoe UI", 9f);
        var names = AcuEngine.SuggestedNames();
        foreach (var n in names) _names.Items.Add(n, true);
        _endpoint.Items.AddRange(names.Cast<object>().ToArray());
        _endpoint.Text = names.FirstOrDefault(n => System.Net.IPAddress.TryParse(n, out var ip) && !System.Net.IPAddress.IsLoopback(ip)) ?? "localhost";

        var ok = new Button { Text = L.T("Create site"), DialogResult = DialogResult.OK, AutoSize = true };
        var cancel = new Button { Text = L.T("Cancel"), DialogResult = DialogResult.Cancel, AutoSize = true };
        AcceptButton = ok; CancelButton = cancel;
        var flow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        Label Txt(string s, bool warn = false) => new() { Text = s, AutoSize = true, MaximumSize = new Size(340, 0), ForeColor = warn ? Color.FromArgb(170, 60, 0) : SystemColors.ControlText, Margin = new Padding(3, 8, 3, 2) };
        if (replacing) flow.Controls.Add(Txt(L.T("This replaces the current site. Readers paired with it will not trust the new site: factory-reset them and pair them again."), true));
        flow.Controls.Add(Txt(L.T("Site name:"))); flow.Controls.Add(_name);
        flow.Controls.Add(Txt(L.T("Names and addresses in the ACU's certificate (a reader must dial one of these):"))); flow.Controls.Add(_names);
        flow.Controls.Add(Txt(L.T("Address readers are told to dial (readers on other computers need this computer's network address):"))); flow.Controls.Add(_endpoint);
        flow.Controls.Add(Txt(L.T("Port for reader sessions:"))); flow.Controls.Add(_port);
        flow.Controls.Add(Txt(L.T("Three key pairs are made: the site root (signs all certificates), the ACU's TLS identity and the grant signer (signs every unlock). On a real site the root is kept offline and the grant signer in a hardware security module.")));
        flow.Controls.Add(UiHelpers.Row(ok, cancel));
        Controls.Add(flow);
        ok.Click += (_, _) =>
        {
            if (Endpoint.Length == 0) { DialogResult = DialogResult.None; MessageBox.Show(this, L.T("Enter the address readers should dial."), Text); }
        };
    }
}

/// <summary>Pair a reader: its address, its pairing port and its setup code (or QR text).</summary>
internal sealed class AddReaderDialog : Form
{
    private readonly AcuEngine _acu;
    private readonly TextBox _host = new() { Width = 220, Text = "127.0.0.1" };
    private readonly NumericUpDown _port = new() { Minimum = 1, Maximum = 65535, Value = 7501, Width = 90 };
    private readonly TextBox _code = new() { Width = 320, Font = new Font("Consolas", 11f) };
    private readonly TextBox _name = new() { Width = 220 };
    private readonly Label _result = new() { AutoSize = true, MaximumSize = new Size(340, 0), Margin = new Padding(3, 8, 3, 3) };
    private readonly Button _pair = new() { AutoSize = true }, _close = new() { AutoSize = true, DialogResult = DialogResult.Cancel };
    public bool Paired { get; private set; }

    public AddReaderDialog(AcuEngine acu)
    {
        _acu = acu;
        Text = L.T("Add reader"); FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(10); Font = new Font("Segoe UI", 9f);
        _pair.Text = L.T("Pair"); _close.Text = L.T("Close");
        AcceptButton = _pair; CancelButton = _close;
        Label Txt(string s) => new() { Text = s, AutoSize = true, MaximumSize = new Size(340, 0), Margin = new Padding(3, 8, 3, 2) };
        var flow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        flow.Controls.Add(Txt(L.T("First press the pairing button on the reader (\"Open pairing window\" in the Reader Simulator). It then accepts pairing for 10 minutes.")));
        flow.Controls.Add(Txt(L.T("Reader address (127.0.0.1 if it runs on this computer):"))); flow.Controls.Add(_host);
        flow.Controls.Add(Txt(L.T("Reader pairing port (shown in its Pairing panel):"))); flow.Controls.Add(_port);
        flow.Controls.Add(Txt(L.T("Setup code from the reader's label, or the QR text (HPSP:1:…):"))); flow.Controls.Add(_code);
        flow.Controls.Add(Txt(L.T("Name for this reader (optional):"))); flow.Controls.Add(_name);
        flow.Controls.Add(_result);
        flow.Controls.Add(UiHelpers.Row(_pair, _close));
        Controls.Add(flow);
        _pair.Click += async (_, _) => await PairAsync();
    }

    private async Task PairAsync()
    {
        _pair.Enabled = false;
        _result.ForeColor = SystemColors.ControlText;
        _result.Text = L.T("Pairing… watch the activity window.");
        string? err = await _acu.AddReaderAsync(_host.Text.Trim(), (int)_port.Value, _code.Text, _name.Text);
        _pair.Enabled = true;
        if (err is null)
        {
            Paired = true;
            _result.ForeColor = Color.FromArgb(0, 120, 40);
            _result.Text = L.T("Paired. The reader now connects to this ACU by itself.");
            _pair.Enabled = false;
        }
        else { _result.ForeColor = Color.FromArgb(180, 0, 0); _result.Text = L.T("Pairing failed: ") + err; }
    }
}
