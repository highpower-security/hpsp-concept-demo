// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Cbor/HpspCbor.cs
//  Purpose: Encode and decode HPSP messages in CBOR, following the HPSP CBOR
//           profile (specification section 6.7, "The CBOR profile").
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  HPSP messages are written in the specification as JSON so people can read
//  them, but they travel on the wire as CBOR: a compact binary form of the same
//  data. This file converts between CBOR bytes and a simple in-memory "tree":
//
//      CBOR map         <->  Dictionary<string, object?>
//      CBOR array       <->  List<object?>
//      text string      <->  string
//      byte string      <->  byte[]
//      integer          <->  long (or ulong for very large positive values)
//      true / false     <->  bool
//      float            <->  double   (only for sensor readings)
//
//  The HPSP profile is stricter than CBOR in general. A receiver MUST reject:
//  indefinite lengths, tags, null and undefined, non-text map keys, duplicate
//  keys, nesting deeper than 6, maps with more than 24 members, and text that
//  is not valid UTF-8. These rules keep parsers small and predictable, which
//  matters on a microcontroller and makes fuzzing easier.
//
//  Senders write "deterministic" CBOR (RFC 8949 section 4.2.1): the shortest
//  form for every number and map keys sorted by their encoded bytes. For the
//  short text keys HPSP uses, that means shorter keys first, then A-Z order.
// =============================================================================

using System.Formats.Cbor;
using System.Text;

namespace Hpsp.Core.Cbor;

/// <summary>Thrown when bytes do not form a valid HPSP CBOR message.</summary>
public sealed class HpspCborException : Exception
{
    public HpspCborException(string message) : base(message) { }
}

/// <summary>CBOR encoding and decoding for the HPSP profile.</summary>
public static class HpspCbor
{
    public const int MaxDepth = 6;          // spec 5.12: maximum nesting depth
    public const int MaxMembers = 24;       // spec 5.12: maximum members in a map
    public const int MaxTextBytes = 255;    // 128 in general, 255 for endpoint host names

    // -------------------------------------------------------------------------
    //  Encoding
    // -------------------------------------------------------------------------

    /// <summary>Encode a message tree as deterministic CBOR.</summary>
    public static byte[] Encode(object? value)
    {
        // Ctap2Canonical gives the RFC 8949 "core deterministic" ordering for the
        // keys we use (shortest-form integers, definite lengths, sorted keys).
        var w = new CborWriter(CborConformanceMode.Ctap2Canonical, convertIndefiniteLengthEncodings: false);
        Write(w, value, 0);
        return w.Encode();
    }

    private static void Write(CborWriter w, object? v, int depth)
    {
        if (depth > MaxDepth) throw new HpspCborException("nesting deeper than " + MaxDepth);
        switch (v)
        {
            case null:
                // The HPSP profile has no null. An absent member means "not applicable".
                throw new HpspCborException("null is not allowed in HPSP messages");
            case string s: w.WriteTextString(s); break;
            case byte[] b: w.WriteByteString(b); break;
            case bool b: w.WriteBoolean(b); break;
            case int i: w.WriteInt64(i); break;
            case long l: w.WriteInt64(l); break;
            case uint ui: w.WriteUInt64(ui); break;
            case ulong ul: w.WriteUInt64(ul); break;
            case ushort us: w.WriteUInt64(us); break;
            case byte by: w.WriteUInt64(by); break;
            case double d: w.WriteDouble(d); break;
            case IDictionary<string, object?> map:
                if (map.Count > MaxMembers) throw new HpspCborException("map has more than " + MaxMembers + " members");
                w.WriteStartMap(map.Count);
                // CborWriter in a canonical mode sorts the keys for us.
                foreach (var kv in map)
                {
                    w.WriteTextString(kv.Key);
                    Write(w, kv.Value, depth + 1);
                }
                w.WriteEndMap();
                break;
            case System.Collections.IEnumerable list:
                var items = list.Cast<object?>().ToList();
                w.WriteStartArray(items.Count);
                foreach (var item in items) Write(w, item, depth + 1);
                w.WriteEndArray();
                break;
            default:
                throw new HpspCborException("cannot encode a value of type " + v.GetType().Name);
        }
    }

    // -------------------------------------------------------------------------
    //  Decoding (with the profile checks)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Decode one HPSP message. The bytes must be exactly one CBOR map that obeys
    /// the profile; anything else throws <see cref="HpspCborException"/>.
    /// </summary>
    public static Dictionary<string, object?> DecodeMessage(ReadOnlyMemory<byte> bytes)
    {
        CborReader r;
        try
        {
            // Strict mode rejects duplicate map keys and invalid UTF-8 for us.
            r = new CborReader(bytes, CborConformanceMode.Strict, allowMultipleRootLevelValues: false);
            if (r.PeekState() != CborReaderState.StartMap) throw new HpspCborException("a message must be a CBOR map");
            var result = (Dictionary<string, object?>)Read(r, 0)!;
            if (r.BytesRemaining != 0) throw new HpspCborException("trailing bytes after the message");
            return result;
        }
        catch (HpspCborException) { throw; }
        catch (Exception e) when (e is CborContentException or InvalidOperationException or FormatException or OverflowException)
        {
            throw new HpspCborException("malformed CBOR: " + e.Message);
        }
    }

    private static object? Read(CborReader r, int depth)
    {
        if (depth > MaxDepth) throw new HpspCborException("nesting deeper than " + MaxDepth);
        switch (r.PeekState())
        {
            case CborReaderState.UnsignedInteger:
                {
                    ulong u = r.ReadUInt64();
                    return u <= long.MaxValue ? (object)(long)u : u;
                }
            case CborReaderState.NegativeInteger:
                return r.ReadInt64();
            case CborReaderState.TextString:
                {
                    string s = r.ReadTextString();
                    if (Encoding.UTF8.GetByteCount(s) > MaxTextBytes) throw new HpspCborException("text longer than " + MaxTextBytes + " bytes");
                    return s;
                }
            case CborReaderState.ByteString:
                return r.ReadByteString();
            case CborReaderState.Boolean:
                return r.ReadBoolean();
            case CborReaderState.HalfPrecisionFloat:
            case CborReaderState.SinglePrecisionFloat:
            case CborReaderState.DoublePrecisionFloat:
                {
                    // Floats are allowed only for sensor readings; receivers accept all three sizes.
                    double d = r.ReadDouble();
                    if (double.IsNaN(d) || double.IsInfinity(d)) throw new HpspCborException("NaN and infinity are not allowed");
                    return d;
                }
            case CborReaderState.StartArray:
                {
                    int? n = r.ReadStartArray();
                    if (n is null) throw new HpspCborException("indefinite-length arrays are not allowed");
                    var list = new List<object?>(n.Value);
                    for (int i = 0; i < n.Value; i++) list.Add(Read(r, depth + 1));
                    r.ReadEndArray();
                    return list;
                }
            case CborReaderState.StartMap:
                {
                    int? n = r.ReadStartMap();
                    if (n is null) throw new HpspCborException("indefinite-length maps are not allowed");
                    if (n.Value > MaxMembers) throw new HpspCborException("map has more than " + MaxMembers + " members");
                    var map = new Dictionary<string, object?>(n.Value);
                    for (int i = 0; i < n.Value; i++)
                    {
                        if (r.PeekState() != CborReaderState.TextString) throw new HpspCborException("map keys must be text");
                        string key = r.ReadTextString();
                        if (Encoding.UTF8.GetByteCount(key) > MaxTextBytes) throw new HpspCborException("map key longer than " + MaxTextBytes + " bytes");
                        map[key] = Read(r, depth + 1);
                    }
                    r.ReadEndMap();
                    return map;
                }
            case CborReaderState.Tag:
                throw new HpspCborException("CBOR tags are not used in HPSP");
            case CborReaderState.Null:
            case CborReaderState.Undefined:
                throw new HpspCborException("null and undefined are not allowed");
            default:
                throw new HpspCborException("unsupported CBOR item: " + r.PeekState());
        }
    }
}
