// =============================================================================
//  HPSP Demo  -  ACU Simulator
//  File:    Program.cs
//  Purpose: Start-up.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  Command line (optional):
//    --data <folder>   where the ACU keeps its site, keys and access list
//                      (default: %LOCALAPPDATA%\HPSP Demo\ACU)
// =============================================================================

using Hpsp.Demo.Ui;

namespace HpspAcuSimulator;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        // A demo should explain a problem, not crash: show any unexpected error in plain words.
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => UiHelpers.ShowError(e.Exception);
        TaskScheduler.UnobservedTaskException += (_, e) => e.SetObserved();
        string folder = UiHelpers.DataFolder("ACU", args);
        // Only one ACU Simulator per data folder (they would fight over the same files and port).
        using var mutex = new Mutex(true, "HPSP-Demo-ACU-" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(folder.ToLowerInvariant())))[..16], out bool created);
        if (!created)
        {
            MessageBox.Show($"The ACU Simulator is already running for:\n{folder}", "HPSP ACU Simulator", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        Application.Run(new MainForm(folder));
    }
}
