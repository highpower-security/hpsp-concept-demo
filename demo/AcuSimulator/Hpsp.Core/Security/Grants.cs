// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Security/Grants.cs
//  Purpose: Signed unlock grants: building, signing (ACU side) and checking
//           (reader side). Specification section 5.8, "Signed unlock grants".
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  A grant is a signed permission slip: "open door 2 on this device, for 5
//  seconds, before 20:04:41". The ACU asks a separate signing key (the grant
//  signer) to sign it, and the reader checks the signature itself before it
//  releases the door.
//
//  The signature covers a fixed 84-byte string that the READER rebuilds from
//  its own knowledge, so nothing in the message can steer what gets checked:
//
//      offset size  contents
//        0    12    "HPSP2-GRANT" followed by a zero byte  (layout version 2)
//       12    16    the reader's own device UUID
//       28    32    the session value the reader sent in this session's hello
//       60     8    counter            (big-endian)
//       68     2    component id (cid) (big-endian; 0xFFFF = whole device)
//       70     1    action code        (1 timed unlock, 2 latched unlock, ...)
//       71     1    parameter          (turnstile direction for action 3, else 0)
//       72     4    duration in ms     (big-endian)
//       76     8    expiry, seconds since 1970 (big-endian)
//
//  Because the device UUID and the session value are part of the string, a
//  grant made for one reader, or for an earlier connection, can never verify.
//  The counter must always go up, so a grant cannot be used twice.
// =============================================================================

using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Hpsp.Core.Security;

/// <summary>Action codes from the specification's action table.</summary>
public static class GrantAction
{
    public const byte TimedUnlock = 1;
    public const byte LatchedUnlock = 2;
    public const byte OperatorOpen = 3;
    public const byte ResetAuthorize = 4;
    public const byte FactoryReset = 5;
}

/// <summary>The grant object carried inside an unlock command.</summary>
public sealed record Grant(byte[] SignerId, ulong Counter, ulong Expires, byte[] Signature)
{
    public Dictionary<string, object?> ToMap() => new()
    {
        ["signer_hex"] = SignerId,      // 32 bytes: SHA-256 of the signer's public key info
        ["counter"] = (long)Counter,
        ["expires"] = (long)Expires,    // integer seconds, so the reader never parses text here
        ["sig_b64"] = Signature,        // 64 bytes: r || s
    };

    /// <summary>Read a grant from a decoded map; null if anything is missing or the wrong type.</summary>
    public static Grant? FromMap(Dictionary<string, object?>? m)
    {
        if (m is null) return null;
        if (m.GetValueOrDefault("signer_hex") is not byte[] id || m.GetValueOrDefault("counter") is not long c
            || m.GetValueOrDefault("expires") is not long e || m.GetValueOrDefault("sig_b64") is not byte[] sig) return null;
        if (c < 0 || e < 0) return null;
        return new Grant(id, (ulong)c, (ulong)e, sig);
    }
}

public static class GrantInput
{
    public const int Length = 84;
    private static readonly byte[] Context = "HPSP2-GRANT\0"u8.ToArray();

    /// <summary>Build the 84-byte string that is signed and verified.</summary>
    public static byte[] Build(Guid deviceId, byte[] sessionNonce, ulong counter, ushort cid,
                               byte action, byte param, uint durationMs, ulong expires)
    {
        if (sessionNonce.Length != 32) throw new ArgumentException("session value must be 32 bytes");
        var b = new byte[Length];
        Context.CopyTo(b, 0);
        UuidBytes(deviceId).CopyTo(b, 12);
        sessionNonce.CopyTo(b, 28);
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(60), counter);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(68), cid);
        b[70] = action;
        b[71] = param;
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(72), durationMs);
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(76), expires);
        return b;
    }

    /// <summary>
    /// A UUID as its 16 bytes in the usual (RFC 9562, big-endian) order.
    /// Note: .NET's Guid.ToByteArray() uses a different, mixed-endian order, so we
    /// convert via the text form to be sure we match every other implementation.
    /// </summary>
    public static byte[] UuidBytes(Guid g) => Convert.FromHexString(g.ToString("N"));
}

// -----------------------------------------------------------------------------
//  ACU side: signing
// -----------------------------------------------------------------------------

/// <summary>The grant signer. In a real site this key lives in an HSM, apart from the ACU.</summary>
public sealed class GrantSigner
{
    private readonly ECDsa _key;
    /// <summary>SHA-256 of the signer's SubjectPublicKeyInfo; readers look signers up by this.</summary>
    public byte[] SignerId { get; }

    public GrantSigner(ECDsa key)
    {
        _key = key;
        SignerId = SHA256.HashData(key.ExportSubjectPublicKeyInfo());
    }

    /// <summary>Sign a grant. The result has a "low-S" signature, as the specification recommends.</summary>
    public Grant Sign(Guid deviceId, byte[] sessionNonce, ulong counter, ushort cid, byte action, byte param, uint durationMs, ulong expires)
    {
        byte[] input = GrantInput.Build(deviceId, sessionNonce, counter, cid, action, param, durationMs, expires);
        byte[] sig = _key.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new Grant(SignerId, counter, expires, LowS(sig));
    }

    /// <summary>
    /// ECDSA signatures (r, s) and (r, n - s) are both valid. We always send the
    /// smaller s so every implementation sees one canonical form.
    /// </summary>
    internal static byte[] LowS(byte[] sig)
    {
        var n = BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", System.Globalization.NumberStyles.HexNumber);
        var s = new BigInteger(sig.AsSpan(32, 32), isUnsigned: true, isBigEndian: true);
        if (s > n / 2)
        {
            s = n - s;
            var sb = s.ToByteArray(isUnsigned: true, isBigEndian: true);
            var outSig = (byte[])sig.Clone();
            Array.Clear(outSig, 32, 32);
            sb.CopyTo(outSig, 64 - sb.Length);
            return outSig;
        }
        return sig;
    }
}

// -----------------------------------------------------------------------------
//  Reader side: checking
// -----------------------------------------------------------------------------

/// <summary>The result of a grant check, named after the error codes in Annex B.</summary>
public enum GrantResult { Ok, Forbidden, Unauthorized, Replay, Expired, BadSignature, BadRequest }

/// <summary>A signer the reader trusts, learned from the site in a trust update.</summary>
public sealed record TrustedSigner(byte[] SignerId, byte[] PublicKeySpki, bool RecoveryOnly);

/// <summary>
/// The reader's grant checker. It keeps the highest counter accepted, and a
/// "floor" set at start-up so that counters used before a reboot can never be
/// accepted again (specification 5.8, counter storage).
/// </summary>
public sealed class GrantVerifier
{
    public const uint CounterBlock = 64;      // counters are reserved in non-volatile memory 64 at a time
    public const int ClockAllowanceS = 5;     // a device MAY accept a grant up to 5 s after expiry

    private readonly List<TrustedSigner> _signers = new();
    public ulong LastCounter { get; private set; }
    public ulong Floor { get; private set; }
    public ulong ReservedBlock { get; private set; }

    /// <summary>Called at start-up with the block last written to non-volatile memory.</summary>
    public GrantVerifier(ulong storedBlock)
    {
        ReservedBlock = storedBlock;
        Floor = storedBlock + CounterBlock;   // nothing below this can be fresh after a reboot
    }

    public IReadOnlyList<TrustedSigner> Signers => _signers;
    public void SetSigners(IEnumerable<TrustedSigner> s) { _signers.Clear(); _signers.AddRange(s); }

    /// <summary>
    /// Check a grant in the order the specification gives. The session check (is this
    /// the primary controller?) is the caller's. <paramref name="nowSeconds"/> is null
    /// when the reader has no trusted time, in which case expiry cannot be checked and
    /// the session value and counter carry the protection.
    /// </summary>
    /// <param name="mustPersistBlock">Set when the caller must save <see cref="ReservedBlock"/> before acting.</param>
    public GrantResult Check(Grant g, Guid deviceId, byte[] sessionNonce, ushort cid, byte action, byte param,
                             uint durationMs, ulong? nowSeconds, out bool mustPersistBlock)
    {
        mustPersistBlock = false;
        if (g.SignerId.Length != 32 || g.Signature.Length != 64) return GrantResult.BadRequest;

        // 1. Is the signer one this site trusts? (Signer ids are public, so a plain search is fine.)
        var signer = _signers.FirstOrDefault(s => s.SignerId.AsSpan().SequenceEqual(g.SignerId));
        if (signer is null) return GrantResult.Unauthorized;
        if (signer.RecoveryOnly && action != GrantAction.ResetAuthorize && action != GrantAction.FactoryReset)
            return GrantResult.Unauthorized;

        // 2. Is the counter new? It must beat every grant accepted since start-up and the boot floor.
        if (g.Counter <= LastCounter || g.Counter < Floor) return GrantResult.Replay;

        // 3. Has it expired? Only checked when the reader holds time from an authenticated controller.
        if (nowSeconds is ulong now && now > g.Expires + ClockAllowanceS) return GrantResult.Expired;

        // 4. Rebuild the signed string from OUR identity and OUR session value, then verify.
        byte[] input = GrantInput.Build(deviceId, sessionNonce, g.Counter, cid, action, param, durationMs, g.Expires);
        using var pub = ECDsa.Create();
        pub.ImportSubjectPublicKeyInfo(signer.PublicKeySpki, out _);
        if (!pub.VerifyData(input, g.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            return GrantResult.BadSignature;

        // 5. Accept: remember the counter, and reserve a new block of counters when we cross into one.
        LastCounter = g.Counter;
        ulong block = g.Counter - g.Counter % CounterBlock;
        if (block > ReservedBlock || ReservedBlock == 0) { ReservedBlock = block; mustPersistBlock = true; }
        return GrantResult.Ok;
    }

    /// <summary>The error code to send for a failed check (Annex B).</summary>
    public static string ErrorCode(GrantResult r) => r switch
    {
        GrantResult.Forbidden => "forbidden",
        GrantResult.Unauthorized => "unauthorized",
        GrantResult.Replay => "replay",
        GrantResult.Expired => "expired",
        GrantResult.BadSignature => "bad_signature",
        _ => "bad_request",
    };
}
