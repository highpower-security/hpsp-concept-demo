// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    BouncyCastle/PostQuantumGroups.cs
//  Purpose: Which TLS 1.3 key-exchange groups the BouncyCastle engine offers,
//           including the hybrid post-quantum groups (specification 5.18.1).
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
// #############################################################################
// #   BOUNCYCASTLE CODE - START
// #   Everything in this file uses the BouncyCastle library (MIT license).
// #############################################################################
//
//  IN PLAIN TERMS
//  --------------
//  In TLS 1.3 the two sides agree a fresh secret for every connection (the key
//  exchange). Classically this is elliptic-curve Diffie-Hellman (ECDH). A future
//  quantum computer could break ECDH, and someone who records traffic today could
//  then decrypt it later ("harvest now, decrypt later").
//
//  A HYBRID group does two key exchanges at once and mixes the results:
//    SecP256r1MLKEM768 = ECDH on P-256  +  ML-KEM-768 (FIPS 203, post-quantum)
//    X25519MLKEM768    = ECDH on X25519 +  ML-KEM-768
//  The connection stays secret as long as EITHER half is unbroken, so it can only
//  be stronger than ECDH alone. These groups are defined in RFC 10024.
//
//  This engine offers the hybrid groups first and plain secp256r1 last, so it
//  still talks to older peers (for example a Windows or OpenSSL TLS stack without
//  ML-KEM): TLS 1.3 then simply agrees on secp256r1. The activity window shows
//  which group each connection actually used.
// =============================================================================

using Hpsp.Core.Localization;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace Hpsp.Core.BouncyCastle;

public static class PostQuantumGroups
{
    /// <summary>Our preference order: hybrid post-quantum first, classical fallback last.</summary>
    public static readonly int[] Preference =
    {
        NamedGroup.SecP256r1MLKEM768,   // the HPSP group (pairs with the P-256 certificates)
        NamedGroup.X25519MLKEM768,      // the hybrid most other TLS stacks offer first
        NamedGroup.secp256r1,           // classical fallback, mandatory in HPSP
    };

    /// <summary>The groups from <see cref="Preference"/> that this BouncyCastle build can actually do.</summary>
    /// <remarks>
    /// BouncyCastle's HasNamedGroup answers only for single groups. A hybrid group is available
    /// when both of its halves are (for SecP256r1MLKEM768: secp256r1 and MLKEM768).
    /// </remarks>
    public static int[] Supported(TlsCrypto crypto) => Preference.Where(g => Available(crypto, g)).ToArray();

    private static bool Available(TlsCrypto crypto, int g) =>
        NamedGroup.RefersToASpecificHybrid(g)
            ? crypto.HasNamedGroup(NamedGroup.GetHybridFirst(g)) && crypto.HasNamedGroup(NamedGroup.GetHybridSecond(g))
            : crypto.HasNamedGroup(g);

    /// <summary>True for a hybrid post-quantum group.</summary>
    public static bool IsHybrid(int group) =>
        group is NamedGroup.SecP256r1MLKEM768 or NamedGroup.X25519MLKEM768 or NamedGroup.SecP384r1MLKEM1024;

    /// <summary>A readable name, marking hybrid groups as post-quantum.</summary>
    public static string Describe(int group) =>
        (NamedGroup.GetName(group) ?? "0x" + group.ToString("x4")) + (IsHybrid(group) ? " (" + L.T("hybrid post-quantum") + ")" : " (" + L.T("classical") + ")");
}

// #############################################################################
// #   BOUNCYCASTLE CODE - END
// #############################################################################
