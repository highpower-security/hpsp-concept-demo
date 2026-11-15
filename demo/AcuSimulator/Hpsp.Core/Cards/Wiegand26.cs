// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Cards/Wiegand26.cs
//  Purpose: The 26-bit H10301 card format, the most common proximity card format.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  A 26-bit card carries a facility code (0-255, usually one per building or
//  customer) and a card number (0-65535). The 26 bits are laid out as:
//
//      bit  0       even parity over bits 1-12
//      bits 1-8     facility code (8 bits)
//      bits 9-24    card number   (16 bits)
//      bit  25      odd parity over bits 13-24
//
//  HPSP sends the raw bits in a credential event as "raw_hex", left-aligned and
//  padded with zero bits to whole bytes, with "bits" = 26. The reader also sends
//  the decoded "fc" and "id" so the ACU need not decode it, but the raw bits are
//  always there so a controller can apply any card format it knows.
//
//  Example from the specification: facility 142, card 54321 -> raw c76a18c0.
// =============================================================================

namespace Hpsp.Core.Cards;

public static class Wiegand26
{
    /// <summary>Encode facility code and card number as the 26 bits, MSB first.</summary>
    public static bool[] ToBits(int facility, int card)
    {
        if (facility is < 0 or > 255) throw new ArgumentOutOfRangeException(nameof(facility), "0 to 255");
        if (card is < 0 or > 65535) throw new ArgumentOutOfRangeException(nameof(card), "0 to 65535");
        var bits = new bool[26];
        for (int i = 0; i < 8; i++) bits[1 + i] = ((facility >> (7 - i)) & 1) == 1;
        for (int i = 0; i < 16; i++) bits[9 + i] = ((card >> (15 - i)) & 1) == 1;
        // Even parity: bit 0 makes the count of ones in bits 0-12 even.
        bits[0] = bits.Skip(1).Take(12).Count(b => b) % 2 == 1;
        // Odd parity: bit 25 makes the count of ones in bits 13-25 odd.
        bits[25] = bits.Skip(13).Take(12).Count(b => b) % 2 == 0;
        return bits;
    }

    /// <summary>Pack bits left-aligned into bytes (26 bits -> 4 bytes), as HPSP's raw_hex.</summary>
    public static byte[] Pack(bool[] bits)
    {
        var b = new byte[(bits.Length + 7) / 8];
        for (int i = 0; i < bits.Length; i++) if (bits[i]) b[i / 8] |= (byte)(0x80 >> (i % 8));
        return b;
    }

    public static byte[] ToRaw(int facility, int card) => Pack(ToBits(facility, card));

    /// <summary>Decode raw bits; returns false if the bit count or either parity bit is wrong.</summary>
    public static bool TryDecode(byte[] raw, int bitCount, out int facility, out int card)
    {
        facility = card = 0;
        if (bitCount != 26 || raw.Length < 4) return false;
        bool Bit(int i) => (raw[i / 8] & (0x80 >> (i % 8))) != 0;
        int evenOnes = Enumerable.Range(0, 13).Count(Bit);
        int oddOnes = Enumerable.Range(13, 13).Count(Bit);
        if (evenOnes % 2 != 0 || oddOnes % 2 != 1) return false;
        for (int i = 0; i < 8; i++) facility = (facility << 1) | (Bit(1 + i) ? 1 : 0);
        for (int i = 0; i < 16; i++) card = (card << 1) | (Bit(9 + i) ? 1 : 0);
        return true;
    }

    /// <summary>The bits as text, with the parity bits set apart: "1 10001110 1101010000110001 0".</summary>
    public static string Describe(bool[] bits)
    {
        string s(int from, int n) => string.Concat(bits.Skip(from).Take(n).Select(b => b ? '1' : '0'));
        return $"{s(0, 1)} {s(1, 8)} {s(9, 16)} {s(25, 1)}";
    }
}
