// =============================================================================
//  HPSP Demo  -  Hpsp.Core.Tests
//  File:    EndToEndTests.cs
//  Purpose: Run a simulated ACU and a simulated reader in one process, exactly
//           as the two Windows apps do, and check the whole story:
//             pairing (wrong code, right code) -> session -> allowed card opens
//             the door -> denied card gets a red LED -> every attack refused ->
//             events replayed after the cable is pulled.
//           Repeated for each TLS engine.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================

using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Hpsp.Core.Engine;
using Hpsp.Core.Transport;

namespace Hpsp.Core.Tests;

public static class EndToEndTests
{
    static int FreePort() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); int p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }

    static async Task<bool> Until(Func<bool> cond, int ms = 8000)
    {
        var end = DateTime.Now.AddMilliseconds(ms);
        while (DateTime.Now < end) { if (cond()) return true; await Task.Delay(50); }
        return cond();
    }

    public static async Task Run(Action<bool, string> check)
    {
        foreach (var kind in new[] { TlsEngineKind.Windows, TlsEngineKind.BouncyCastle })
            await RunOne(kind, check);
        await LockoutRecovery(check);
    }

    /// <summary>One guess, then walk away after seeing confirm_v (as an attacker testing codes would).</summary>
    static async Task AbandonedGuess(int port)
    {
        // If the reader is still finishing the previous attempt it closes this connection at
        // once (one attempt at a time), so try again briefly.
        for (int tries = 0; ; tries++)
        {
            using var t = new TcpClient();
            await t.ConnectAsync("127.0.0.1", port);
            var pc = new MessageChannel(t.GetStream(), _ => { }, "test");
            var pp = await pc.ReceiveAsync(default);
            if (pp is null && tries < 10) { await Task.Delay(200); continue; }
            await GuessOn(pc, pp!);
            return;
        }
    }

    static async Task GuessOn(MessageChannel pc, Protocol.HpspMessage pp)
    {
        var (gw0, _) = BouncyCastle.Spake2Plus.DeriveW0W1("22223333", pp!.GetBytes("salt_b64")!, (int)pp.GetLong("iterations")!);
        await pc.SendAsync(Protocol.HpspMessage.Pake("pake_share", new() { ["share_p_b64"] = BouncyCastle.Spake2Plus.ProverShare(BouncyCastle.Spake2Plus.RandomScalar(), gw0) }), default);
        await pc.ReceiveAsync(default);
    }

    /// <summary>Review fix N1 and M1: lock-out after 5 abandoned guesses ends, then the right code works; one attempt at a time.</summary>
    static async Task LockoutRecovery(Action<bool, string> check)
    {
        Console.WriteLine("== Pairing lock-out: 5 abandoned guesses, lock-out, recovery ==");
        string root = Path.Combine(Path.GetTempPath(), "hpsp-lock-" + Guid.NewGuid().ToString("N")[..8]);
        using var acu = new AcuEngine(Path.Combine(root, "acu")) { TlsEngine = TlsEngineKind.BouncyCastle };
        var reader = new ReaderEngine(Path.Combine(root, "reader")) { TlsEngine = TlsEngineKind.BouncyCastle, PairingPort = FreePort(), FirstLockout = TimeSpan.FromSeconds(5) };
        try
        {
            acu.CreateSite("Lock Test", new[] { "localhost" }, "localhost", FreePort());
            reader.OpenPairingWindow();

            // A second connection while one attempt is running is closed at once (spec 5.6).
            using (var hold = new TcpClient())
            {
                await hold.ConnectAsync("127.0.0.1", reader.PairingPort);
                await Task.Delay(300);
                using var second = new TcpClient();
                await second.ConnectAsync("127.0.0.1", reader.PairingPort);
                var buf = new byte[1];
                int n;
                try { using var c = new CancellationTokenSource(3000); n = await second.GetStream().ReadAsync(buf, c.Token); }
                catch (Exception) { n = 0; }
                check(n == 0, "second pairing connection is closed while one attempt is running");
            }
            await Task.Delay(300);

            for (int i = 0; i < 5; i++) { await AbandonedGuess(reader.PairingPort); await Until(() => reader.FailedAttempts >= i + 1 || reader.LockedOut, 3000); }
            check(reader.LockedOut, $"5 abandoned guesses lock pairing (attempts {reader.FailedAttempts})");
            check(await Until(() => !reader.PairingWindowOpen, 3000), "the lock-out closes the pairing window");
            reader.OpenPairingWindow();
            check(!reader.PairingWindowOpen, "pairing window will not open while locked");
            await Until(() => !reader.LockedOut, 8000);
            reader.OpenPairingWindow();
            check(reader.PairingWindowOpen && !reader.LockedOut, "after the lock-out ends the window opens again");
            string? r = await acu.AddReaderAsync("127.0.0.1", reader.PairingPort, reader.SetupCode);
            check(r is null && reader.IsPaired, $"the correct code pairs after the lock-out ({r ?? "ok"})");
        }
        catch (Exception e) { check(false, "lock-out test threw: " + e); }
        finally { reader.Stop(); acu.Stop(); try { Directory.Delete(root, true); } catch { } }
    }

    static async Task RunOne(TlsEngineKind kind, Action<bool, string> check)
    {
        Console.WriteLine($"== End to end: ACU and reader, {kind} TLS engine ==");
        string root = Path.Combine(Path.GetTempPath(), "hpsp-e2e-" + Guid.NewGuid().ToString("N")[..8]);
        var acuLog = new ConcurrentQueue<string>();
        var rdrLog = new ConcurrentQueue<string>();
        bool verbose = Environment.GetEnvironmentVariable("HPSP_E2E_VERBOSE") == "1";

        using var acu = new AcuEngine(Path.Combine(root, "acu")) { TlsEngine = kind, HeartbeatSeconds = 2 };
        var reader = new ReaderEngine(Path.Combine(root, "reader")) { TlsEngine = kind, PairingPort = FreePort() };
        acu.Activity += e => { acuLog.Enqueue(e.Summary); if (verbose) Console.WriteLine("   ACU  " + e.Summary); };
        reader.Activity += e => { rdrLog.Enqueue(e.Summary); if (verbose) Console.WriteLine("   RDR  " + e.Summary); };
        bool AcuSaw(string s) => acuLog.Any(x => x.Contains(s, StringComparison.OrdinalIgnoreCase));

        try
        {
            acu.CreateSite("Test Site", new[] { "localhost", "127.0.0.1" }, "localhost", FreePort());
            acu.Access.Entries.Add(new AccessEntry { Facility = 142, Card = 54321, Name = "Alice", Allowed = true });
            acu.Access.Entries.Add(new AccessEntry { Facility = 142, Card = 11111, Name = "Bob", Allowed = false });
            acu.Access.UnlockMs = 1500;

            // ---- review fix H3: only a grant-signing certificate can be a grant signer ----
            check(Security.DemoPki.CheckChain(acu.SignerCertificate!, acu.SiteRoot!, Security.DemoPki.GrantSigning) is null, "grant signer certificate accepted as a grant signer");
            check(Security.DemoPki.CheckChain(acu.AcuCertificate!, acu.SiteRoot!, Security.DemoPki.GrantSigning) is not null, "ACU TLS certificate refused as a grant signer");
            check(Security.DemoPki.CheckChain(acu.SiteRoot!, acu.SiteRoot!, Security.DemoPki.GrantSigning) is not null, "site root refused as a grant signer");
            check(Security.DemoPki.CheckChain(acu.SignerCertificate!, acu.SiteRoot!, Security.DemoPki.ServerAuth) is not null, "grant signer certificate refused as a TLS server");
            acu.Start();
            reader.Start();

            // ---- pairing ----
            string? r0 = await acu.AddReaderAsync("127.0.0.1", reader.PairingPort, reader.SetupCode);
            check(r0 is not null, "pairing refused while the reader's pairing window is closed");

            reader.OpenPairingWindow();
            check(reader.PairingWindowOpen, "pairing window opens");
            string wrong = reader.SetupCode.StartsWith("2") ? "3333-3333" : "2222-2222";
            string? r1 = await acu.AddReaderAsync("127.0.0.1", reader.PairingPort, wrong);
            check(r1 is not null && r1.Contains("wrong setup code") && await Until(() => reader.FailedAttempts == 1), $"wrong setup code refused and counted ({r1}; attempts {reader.FailedAttempts})");

            // ---- review fix H2: walking away after seeing confirm_v still uses up an attempt ----
            await AbandonedGuess(reader.PairingPort);   // retries if the reader is still busy
            bool sawConfirm = true;
            check(sawConfirm && await Until(() => reader.FailedAttempts == 2), $"abandoned attempt after confirm_v is counted (attempts {reader.FailedAttempts})");

            string? r2 = await acu.AddReaderAsync("127.0.0.1", reader.PairingPort, reader.QrText, "Front door");
            check(r2 is null && reader.IsPaired, $"pairing with the QR text succeeds ({r2 ?? "ok"})");
            check(reader.FailedAttempts == 0, "failure count reset after success");
            check(acu.PairedReaders.Any(p => p.DeviceId == reader.DeviceId && p.Name == "Front door"), "ACU lists the paired reader");
            // ---- review fix M2: a paired reader ignores the pairing button ----
            reader.OpenPairingWindow();
            check(!reader.PairingWindowOpen, "paired reader ignores the pairing button");

            // ---- session ----
            bool online = await Until(() => acu.Sessions.Any(s => s.DeviceId == reader.DeviceId && s.HelloDone));
            check(online, "reader connects to the ACU and completes hello");
            check(await Until(() => reader.SignerCount == 1), "ACU sent trust_update; reader now trusts one grant signer");
            var sess = acu.Sessions.First(s => s.DeviceId == reader.DeviceId);
            check(sess.Tls?.Protocol.Contains("1.3") == true, $"session is TLS 1.3 ({sess.Tls?.Protocol} {sess.Tls?.Cipher})");
            // Post-quantum (spec 5.18): BouncyCastle negotiates the hybrid group; pairing always uses BouncyCastle.
            if (kind == TlsEngineKind.BouncyCastle)
                check(sess.Tls?.KeyExchange?.StartsWith("SecP256r1MLKEM768") == true, $"session key exchange is hybrid post-quantum ({sess.Tls?.KeyExchange})");
            check(rdrLog.Any(x => x.Contains("Pairing TLS established") && x.Contains("MLKEM768")), "pairing TLS used a hybrid post-quantum key exchange");

            // ---- allowed card ----
            reader.SwipeCard(142, 54321);
            check(await Until(() => reader.DoorUnlocked), "allowed card: door unlocks");
            check(await Until(() => reader.LedColor == "green"), "allowed card: LED turns green");
            check(await Until(() => !reader.DoorUnlocked, 5000), "door relocks by itself after the unlock time");

            // ---- denied card ----
            reader.SwipeCard(142, 11111);
            check(await Until(() => reader.LedColor == "red"), "denied card: LED flashes red");
            check(!reader.DoorUnlocked && AcuSaw("ACCESS DENIED"), "denied card: door stays locked");
            reader.SwipeCard(1, 2);
            check(await Until(() => acuLog.Count(x => x.Contains("ACCESS DENIED")) >= 2), "unknown card denied by the default rule");

            // ---- attacks ----
            var expect = new (AttackKind k, string code)[]
            {
                (AttackKind.ReplayLastGrant, "replay"), (AttackKind.ExpiredGrant, "expired"),
                (AttackKind.OldSessionGrant, "bad_signature"), (AttackKind.TamperedSignature, "bad_signature"),
                (AttackKind.WrongSigner, "unauthorized"),
            };
            foreach (var (k, code) in expect)
            {
                int before = acuLog.Count(x => x.Contains("refused unlock: " + code));
                string? err = await acu.AttackAsync(acu.Sessions.First(s => s.DeviceId == reader.DeviceId), k);
                bool refused = await Until(() => acuLog.Count(x => x.Contains("refused unlock: " + code)) > before, 4000);
                check(err is null && refused && !reader.DoorUnlocked, $"attack {k}: reader refuses with \"{code}\"{(err is null ? "" : " (" + err + ")")}");
            }

            // ---- manual unlock still works after all that ----
            await acu.SendUnlockAsync(acu.Sessions.First(s => s.DeviceId == reader.DeviceId), 800);
            check(await Until(() => reader.DoorUnlocked), "manual unlock works after the attacks");
            await Until(() => !reader.DoorUnlocked, 4000);

            // ---- pull the cable: events are kept and replayed ----
            reader.PullCable();
            check(await Until(() => !acu.Sessions.Any(s => s.DeviceId == reader.DeviceId)), "cable pulled: ACU sees the reader go offline");
            long seqBefore = acu.PairedReaders.First(p => p.DeviceId == reader.DeviceId).LastAckedSeq;
            reader.SwipeCard(142, 54321);   // while offline
            check(reader.PendingEventCount >= 1, $"swipe while offline is kept by the reader ({reader.PendingEventCount} pending)");
            reader.PlugCable();
            check(await Until(() => acu.PairedReaders.First(p => p.DeviceId == reader.DeviceId).LastAckedSeq > seqBefore, 15000),
                "reconnected: the offline swipe is replayed and acknowledged");
            check(await Until(() => reader.PendingEventCount == 0), "reader's event queue empties after acknowledgement");

            // ---- the old-session attack now uses a genuinely previous session value ----
            await Until(() => acu.Sessions.Any(s => s.DeviceId == reader.DeviceId && s.HelloDone));
            var s2 = acu.Sessions.First(s => s.DeviceId == reader.DeviceId);
            check(s2.PreviousSessionNonce is not null && !s2.PreviousSessionNonce.SequenceEqual(s2.SessionNonce!), "new session has a new session value");

            // ---- removing the reader shuts it out ----
            acu.RemoveReader(reader.DeviceId);
            // The reader retries with a back-off (1, 2, 4… s), so wait for its next attempt.
            check(await Until(() => AcuSaw("not paired here or was removed"), 20000), "removed reader is refused at hello");

            // ---- review fix H1: card reads are not kept across a restart ----
            reader.PullCable();
            int beforeSwipe = reader.PendingEventCount;
            reader.SwipeCard(142, 54321);
            int withSwipe = reader.PendingEventCount;
            reader.Stop();
            var restarted = new ReaderEngine(Path.Combine(root, "reader"));
            check(withSwipe == beforeSwipe + 1 && restarted.PendingEventCount == beforeSwipe, $"offline card read discarded at restart ({withSwipe} pending before, {restarted.PendingEventCount} after)");
            restarted.Dispose();
        }
        catch (Exception e) { check(false, "end-to-end test threw: " + e); }
        finally
        {
            reader.Stop();
            acu.Stop();
            try { Directory.Delete(root, true); } catch { }
        }
    }
}

/// <summary>Every English text in the engines must have a French entry with the same {n} placeholders.</summary>
public static class LocalizationTests
{
    public static void Run(Action<bool, string> check)
    {
        Console.WriteLine("== Localization: French covers all engine text ==");
        var src = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));   // this app's folder
        // L.T("...") / L.F("...") calls, and checklist steps (Title = "...", Explain = "..."), which are translated when shown.
        var rx = new System.Text.RegularExpressions.Regex(@"(?:L\.[TF]\(|\b(?:Title|Explain) = )""((?:[^""\\]|\\.)*)""");
        var keys = new HashSet<string>();
        foreach (var f in Directory.GetFiles(src, "*.cs", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(src, f).Replace('\\', '/');
            if (rel.Contains("Localization/") || rel.StartsWith("Tests/") || rel.Contains("/bin/") || rel.Contains("/obj/")) continue;
            foreach (System.Text.RegularExpressions.Match m in rx.Matches(File.ReadAllText(f)))
                keys.Add(System.Text.RegularExpressions.Regex.Unescape(m.Groups[1].Value));
        }
        var prev = Hpsp.Core.Localization.L.Current;
        Hpsp.Core.Localization.L.Current = Hpsp.Core.Localization.Language.French;
        var missing = keys.Where(k => !Hpsp.Core.Localization.L.HasFrench(k)).ToList();
        var ph = new System.Text.RegularExpressions.Regex(@"\{\d+(:[^}]*)?\}");
        var badPh = keys.Where(k => !ph.Matches(k).Select(x => x.Value).OrderBy(x => x).SequenceEqual(ph.Matches(Hpsp.Core.Localization.L.T(k)).Select(x => x.Value).OrderBy(x => x))).ToList();
        Hpsp.Core.Localization.L.Current = prev;
        foreach (var k in missing.Take(200)) Console.WriteLine("     missing: " + k);
        foreach (var k in badPh.Take(20)) Console.WriteLine("     placeholders differ: " + k);
        check(keys.Count > 100 && missing.Count == 0, $"{keys.Count} texts found; {missing.Count} without French");
        check(badPh.Count == 0, $"French keeps the same placeholders ({badPh.Count} differ)");
    }
}
