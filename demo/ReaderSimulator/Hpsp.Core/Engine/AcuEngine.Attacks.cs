// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Engine/AcuEngine.Attacks.cs
//  Purpose: Demonstrations of attacks that HPSP is designed to stop.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  Each button sends the reader an unlock that an attacker might try. The
//  reader must refuse every one of them and keep the door locked. The activity
//  windows show the refusal and its reason on both sides.
//
//    Replay           send the last grant again           -> "replay"
//    Expired          a grant that expired 2 minutes ago  -> "expired"
//    Old session      a grant for the reader's PREVIOUS   -> "bad_signature"
//                     session value
//    Tampered         a valid grant with one bit flipped  -> "bad_signature"
//    Wrong signer     signed by a key the site never       -> "unauthorized"
//                     trusted (for example, a stolen ACU
//                     trying to sign its own grants)
//
//  These exist only so people can watch the protection work.
// =============================================================================

using System.Security.Cryptography;
using Hpsp.Core.Protocol;
using Hpsp.Core.Security;
using Hpsp.Core.Localization;

namespace Hpsp.Core.Engine;

public enum AttackKind { ReplayLastGrant, ExpiredGrant, OldSessionGrant, TamperedSignature, WrongSigner }

public sealed partial class AcuEngine
{
    public static string Describe(AttackKind a) => a switch
    {
        AttackKind.ReplayLastGrant => L.T("Replay the last grant (expected: replay)"),
        AttackKind.ExpiredGrant => L.T("Grant that expired 2 minutes ago (expected: expired)"),
        AttackKind.OldSessionGrant => L.T("Grant for the reader's previous session (expected: bad_signature)"),
        AttackKind.TamperedSignature => L.T("Valid grant with one bit flipped (expected: bad_signature)"),
        AttackKind.WrongSigner => L.T("Grant signed by an untrusted key (expected: unauthorized)"),
        _ => a.ToString(),
    };

    public async Task<string?> AttackAsync(ReaderSession s, AttackKind kind)
    {
        if (s.Channel is null || !s.HelloDone) return L.T("the reader is not online");
        Dictionary<string, object?> data;
        uint dur = (uint)Access.UnlockMs;
        Dictionary<string, object?> Unlock(Grant g) => new()
        { ["cid"] = (long)ReaderEngine.StrikeCid, ["mode"] = "timed", ["duration_ms"] = (long)dur, ["grant"] = g.ToMap() };

        switch (kind)
        {
            case AttackKind.ReplayLastGrant:
                if (s.LastUnlockData is null) return L.T("no grant has been sent to this reader in this session yet: swipe an allowed card or use Manual unlock first");
                data = s.LastUnlockData;
                break;
            case AttackKind.ExpiredGrant:
                data = Unlock(SignGrant(s, s.SessionNonce!, dur, DateTimeOffset.UtcNow.AddMinutes(-2)));
                break;
            case AttackKind.OldSessionGrant:
                byte[] old = s.PreviousSessionNonce ?? RandomNumberGenerator.GetBytes(32);
                if (s.PreviousSessionNonce is null) Log(ActivityKind.Info, L.T("No previous session recorded for this reader; using a made-up session value instead."), "attack", peer: s.Name);
                data = Unlock(SignGrant(s, old, dur, DateTimeOffset.UtcNow.AddSeconds(30)));
                break;
            case AttackKind.TamperedSignature:
                var g = SignGrant(s, s.SessionNonce!, dur, DateTimeOffset.UtcNow.AddSeconds(30));
                var sig = (byte[])g.Signature.Clone(); sig[17] ^= 0x01;
                data = Unlock(g with { Signature = sig });
                break;
            case AttackKind.WrongSigner:
                using (var rogue = ECDsa.Create(ECCurve.NamedCurves.nistP256))
                    data = Unlock(SignGrant(s, s.SessionNonce!, dur, DateTimeOffset.UtcNow.AddSeconds(30), rogue));
                break;
            default: return L.T("unknown attack");
        }
        Log(ActivityKind.Warning, L.F("ATTACK DEMO on {0}: {1}", s.Name, Describe(kind)), "attack", peer: s.Name);
        await s.Channel.SendAsync(HpspMessage.Cmd("unlock", s.NextId++, data), default, L.T("attack demo"));
        return null;
    }
}
