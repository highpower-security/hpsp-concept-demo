// =============================================================================
//  HPSP Demo  -  Reader Simulator
//  File:    Program.cs
//  Purpose: Start-up. Picks the data folder and pairing port, so several
//           simulated readers can run on one computer.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  Command line (all optional):
//    --data <folder>        where this reader keeps its identity and keys
//    --pairing-port <n>     TCP port for pairing (default 7501)
//
//  Starting the program a second time starts a SECOND reader automatically
//  (folder "Reader 2", pairing port 7511; a third uses "Reader 3" and 7521...).
// =============================================================================

using Hpsp.Demo.Ui;

namespace HpspReaderSimulator;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        string? fixedFolder = Array.Exists(args, a => a.Equals("--data", StringComparison.OrdinalIgnoreCase)) ? UiHelpers.DataFolder("Reader", args) : null;
        int? fixedPort = UiHelpers.IntArg(args, "--pairing-port");

        // One running copy per data folder. If "Reader" is in use, become "Reader 2", and so on.
        Mutex? mutex = null; string folder = ""; int port = 7501, instance = 1;
        for (; instance <= 9; instance++)
        {
            folder = fixedFolder ?? UiHelpers.DataFolder(instance == 1 ? "Reader" : $"Reader {instance}", Array.Empty<string>());
            port = fixedPort ?? 7501 + 10 * (instance - 1);
            mutex = new Mutex(true, "HPSP-Demo-Reader-" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(folder.ToLowerInvariant())))[..16], out bool created);
            if (created) break;
            mutex.Dispose(); mutex = null;
            if (fixedFolder is not null)
            {
                MessageBox.Show($"Another Reader Simulator is already using:\n{folder}", "HPSP Reader Simulator", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
        }
        if (mutex is null) { MessageBox.Show("Too many Reader Simulators are running.", "HPSP Reader Simulator"); return; }
        using (mutex)
            Application.Run(new MainForm(folder, port, instance));
    }
}
