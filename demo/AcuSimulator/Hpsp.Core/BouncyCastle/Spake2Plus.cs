// #############################################################################
// #                                                                           #
// #   BOUNCYCASTLE CODE - START                                               #
// #                                                                           #
// #   This file uses the BouncyCastle cryptography library (MIT licence,      #
// #   https://www.bouncycastle.org/csharp/) for elliptic-curve point          #
// #   arithmetic. .NET's built-in ECDsa / ECDiffieHellman classes cannot      #
// #   multiply arbitrary points, which SPAKE2+ needs (for example w0 * M).    #
// #                                                                           #
// #   BouncyCastle is used ONLY in the files in this "BouncyCastle" folder,   #
// #   and only for pairing (commissioning). Normal sessions use .NET's        #
// #   own TLS unless the BouncyCastle TLS engine is selected.                 #
// #                                                                           #
// #############################################################################
//
//  HPSP Demo  -  Hpsp.Core
//  File:    BouncyCastle/Spake2Plus.cs
//  Purpose: SPAKE2+ (RFC 9383), ciphersuite P256-SHA256-HKDF-SHA256-HMAC-SHA256,
//           as used by HPSP commissioning (specification 5.6.1).
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
//
//  IN PLAIN TERMS
//  --------------
//  SPAKE2+ lets two sides prove they both know a short code (the reader's
//  8-character setup code) WITHOUT sending the code. Each side mixes the code
//  into a random-looking point on the elliptic curve and sends it. If both used
//  the same code they end up with the same secret key, and each proves that to
//  the other with a short confirmation value. Someone listening learns nothing
//  they can use to test guesses offline.
//
//  The "+" means the device does not even store the code: it stores a
//  "verifier" (w0 and L = w1*G) made at the factory. A thief who reads the
//  verifier out of the device still cannot pretend to be the controller.
//
//  Roles:   the ACU is the PROVER  (it knows the code, typed by the installer)
//           the reader is the VERIFIER (it holds w0 and L)
//
//  Message flow (the "pake" messages on TCP 7501):
//      reader -> ACU   pake_params   (device_id, salt, iterations)
//      ACU -> reader   pake_share    (shareP = x*G + w0*M)
//      reader -> ACU   pake_share    (shareV = y*G + w0*N, confirmV)
//      ACU -> reader   pake_confirm  (confirmP)
//  Then both sides hold K_shared, from which the pre-shared key for TLS is made.
//
//  DEMO NOTE: BouncyCastle's general point arithmetic is not guaranteed to run
//  in constant time. A real device needs a constant-time implementation.
//  This code reproduces the RFC 9383 test vector exactly (see the tests).
// =============================================================================

using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math.EC;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Hpsp.Core.BouncyCastle;

/// <summary>Values both sides end with after a successful exchange.</summary>
public sealed record Spake2PlusKeys(byte[] KMain, byte[] KConfirmP, byte[] KConfirmV, byte[] KShared, byte[] ConfirmP, byte[] ConfirmV);

public static class Spake2Plus
{
    // ---- the P-256 curve and the two fixed SPAKE2+ points M and N (RFC 9383 section 4) ----
    private static readonly X9ECParameters P256 = ECNamedCurveTable.GetByName("P-256");
    private static readonly ECPoint G = P256.G;
    private static readonly BcBigInteger Order = P256.N;
    private static readonly ECPoint M = Decode(Convert.FromHexString("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"));
    private static readonly ECPoint N = Decode(Convert.FromHexString("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"));

    // ---- HPSP's choices (specification 5.6.1) ----
    public static readonly byte[] HpspContext = Encoding.ASCII.GetBytes("HPSP-1 commissioning");
    public static readonly byte[] HpspProverId = Encoding.ASCII.GetBytes("HPSP-controller");
    public static readonly byte[] PskInfo = Encoding.ASCII.GetBytes("HPSP-1 commissioning psk");

    /// <summary>
    /// Stretch the setup code into w0 and w1: PBKDF2-HMAC-SHA256, 80 bytes; w0 is the
    /// first 40, w1 the last 40, each reduced modulo the curve order (RFC 9383, 3.2).
    /// The salt and iteration count come from the device, so guessing is slow.
    /// </summary>
    public static (byte[] W0, byte[] W1) DeriveW0W1(string setupCode, byte[] salt, int iterations)
    {
        byte[] ws = Rfc2898DeriveBytes.Pbkdf2(Encoding.ASCII.GetBytes(setupCode.ToUpperInvariant()), salt, iterations, HashAlgorithmName.SHA256, 80);
        return (Reduce(ws.AsSpan(0, 40)), Reduce(ws.AsSpan(40, 40)));
    }

    /// <summary>L = w1 * G, stored by the device instead of w1 (the "verifier").</summary>
    public static byte[] ComputeL(byte[] w1) => Enc(G.Multiply(Int(w1)));

    /// <summary>A random scalar in [1, n-1].</summary>
    public static byte[] RandomScalar()
    {
        while (true)
        {
            var k = new BcBigInteger(1, RandomNumberGenerator.GetBytes(32));
            if (k.SignValue > 0 && k.CompareTo(Order) < 0) return Fixed32(k);
        }
    }

    // -------------------------------------------------------------------------
    //  Prover (ACU)
    // -------------------------------------------------------------------------

    /// <summary>shareP = x*G + w0*M</summary>
    public static byte[] ProverShare(byte[] x, byte[] w0) => Enc(G.Multiply(Int(x)).Add(M.Multiply(Int(w0))));

    /// <summary>The prover's side once shareV arrives. Throws if shareV is not a valid point.</summary>
    public static Spake2PlusKeys ProverFinish(byte[] context, byte[] idP, byte[] idV, byte[] w0, byte[] w1, byte[] x, byte[] shareP, byte[] shareV)
    {
        ECPoint Y = DecodeChecked(shareV);
        ECPoint T = Y.Subtract(N.Multiply(Int(w0)));          // remove the code's contribution
        ECPoint Z = T.Multiply(Int(x)).Normalize();            // cofactor h = 1 for P-256
        ECPoint V = T.Multiply(Int(w1)).Normalize();
        return Finish(context, idP, idV, w0, shareP, shareV, Z, V);
    }

    // -------------------------------------------------------------------------
    //  Verifier (reader)
    // -------------------------------------------------------------------------

    /// <summary>shareV = y*G + w0*N</summary>
    public static byte[] VerifierShare(byte[] y, byte[] w0) => Enc(G.Multiply(Int(y)).Add(N.Multiply(Int(w0))));

    /// <summary>The verifier's side once shareP arrives. Throws if shareP is not a valid point.</summary>
    public static Spake2PlusKeys VerifierFinish(byte[] context, byte[] idP, byte[] idV, byte[] w0, byte[] L, byte[] y, byte[] shareP, byte[] shareV)
    {
        ECPoint X = DecodeChecked(shareP);
        ECPoint Z = X.Subtract(M.Multiply(Int(w0))).Multiply(Int(y)).Normalize();
        ECPoint V = Decode(L).Multiply(Int(y)).Normalize();
        return Finish(context, idP, idV, w0, shareP, shareV, Z, V);
    }

    // -------------------------------------------------------------------------
    //  Shared steps: transcript, keys and confirmations (RFC 9383 section 3.4)
    // -------------------------------------------------------------------------

    private static Spake2PlusKeys Finish(byte[] context, byte[] idP, byte[] idV, byte[] w0, byte[] shareP, byte[] shareV, ECPoint Z, ECPoint V)
    {
        if (Z.IsInfinity || V.IsInfinity) throw new CryptographicException("SPAKE2+: invalid shared point");
        // TT = each field with an 8-byte little-endian length in front, in this order.
        using var tt = new MemoryStream();
        foreach (var f in new[] { context, idP, idV, Enc(M), Enc(N), shareP, shareV, Enc(Z), Enc(V), Fixed32(Int(w0)) })
        {
            tt.Write(BitConverter.IsLittleEndian ? BitConverter.GetBytes((ulong)f.Length) : BitConverter.GetBytes((ulong)f.Length).Reverse().ToArray());
            tt.Write(f);
        }
        byte[] kMain = SHA256.HashData(tt.ToArray());
        byte[] ck = HKDF.DeriveKey(HashAlgorithmName.SHA256, kMain, 64, Array.Empty<byte>(), "ConfirmationKeys"u8.ToArray());
        byte[] kcP = ck[..32], kcV = ck[32..];
        byte[] kShared = HKDF.DeriveKey(HashAlgorithmName.SHA256, kMain, 32, Array.Empty<byte>(), "SharedKey"u8.ToArray());
        byte[] confirmP = HMACSHA256.HashData(kcP, shareV);   // prover confirms the verifier's share
        byte[] confirmV = HMACSHA256.HashData(kcV, shareP);   // verifier confirms the prover's share
        return new Spake2PlusKeys(kMain, kcP, kcV, kShared, confirmP, confirmV);
    }

    /// <summary>The pre-shared key for the pairing TLS session: HKDF-Expand(K_shared, "HPSP-1 commissioning psk", 32).</summary>
    public static byte[] DerivePsk(byte[] kShared) => HKDF.Expand(HashAlgorithmName.SHA256, kShared, 32, PskInfo);

    /// <summary>Compare two confirmation values without leaking timing.</summary>
    public static bool ConfirmEquals(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);

    // ---- helpers ----
    private static ECPoint Decode(byte[] b) => P256.Curve.DecodePoint(b);

    /// <summary>Decode a received share and reject anything that is not a proper point (spec: MUST check).</summary>
    private static ECPoint DecodeChecked(byte[] b)
    {
        if (b.Length != 65 || b[0] != 0x04) throw new CryptographicException("SPAKE2+: share must be an uncompressed P-256 point");
        ECPoint p;
        try { p = Decode(b); } catch (Exception e) { throw new CryptographicException("SPAKE2+: share is not on the curve", e); }
        if (p.IsInfinity || !p.IsValid()) throw new CryptographicException("SPAKE2+: share is not a valid point");
        return p;
    }

    private static byte[] Enc(ECPoint p) => p.Normalize().GetEncoded(false);
    private static BcBigInteger Int(byte[] b) => new(1, b);
    private static byte[] Reduce(ReadOnlySpan<byte> b) => Fixed32(new BcBigInteger(1, b.ToArray()).Mod(Order));
    private static byte[] Fixed32(BcBigInteger v)
    {
        byte[] raw = v.ToByteArrayUnsigned();
        var o = new byte[32];
        raw.CopyTo(o, 32 - raw.Length);
        return o;
    }
}

// #############################################################################
// #   BOUNCYCASTLE CODE - END                                                 #
// #############################################################################
