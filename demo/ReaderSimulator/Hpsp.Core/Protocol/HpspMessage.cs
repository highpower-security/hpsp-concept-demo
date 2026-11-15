// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Protocol/HpspMessage.cs
//  Purpose: The HPSP message envelope (specification section 6.1).
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  IN PLAIN TERMS
//  --------------
//  Every HPSP message is a small labelled package:
//
//      type   what kind of message: cmd, rsp, err, evt, ack, frag or pake
//      op     what it is about, for example "unlock" or "credential"
//      id     a number the sender puts on a command, so the reply can be matched
//      re     on a reply or error: the id of the command it answers
//      seq    on an event: its sequence number (1, 2, 3 ...), for reliable delivery
//      mono   on an event: the device's monotonic clock in milliseconds
//      ts     on an event: wall-clock time, when the device knows it
//      data   the contents, a map whose members depend on the operation
//
//  This class is a thin, typed wrapper around the decoded CBOR map so the rest
//  of the code can write  msg.Op  instead of  map["op"].
// =============================================================================

using Hpsp.Core.Cbor;

namespace Hpsp.Core.Protocol;

public sealed class HpspMessage
{
    public string Type { get; init; } = "";
    public string? Op { get; init; }
    public long? Id { get; init; }
    public long? Re { get; init; }
    public long? Seq { get; init; }
    public long? Mono { get; init; }
    public string? Ts { get; init; }
    public Dictionary<string, object?> Data { get; init; } = new();

    // ---- convenience constructors ------------------------------------------

    public static HpspMessage Cmd(string op, long id, Dictionary<string, object?>? data = null) =>
        new() { Type = "cmd", Op = op, Id = id, Data = data ?? new() };

    public static HpspMessage Rsp(string op, long re, Dictionary<string, object?>? data = null) =>
        new() { Type = "rsp", Op = op, Re = re, Data = data ?? new() };

    /// <summary>An error reply. <paramref name="code"/> is one of the codes in Annex B.</summary>
    public static HpspMessage Err(string op, long? re, string code, string? message = null)
    {
        var d = new Dictionary<string, object?> { ["code"] = code };
        if (message is not null) d["message"] = message;
        return new() { Type = "err", Op = op, Re = re, Data = d };
    }

    public static HpspMessage Evt(string op, long seq, long mono, string? ts, Dictionary<string, object?> data) =>
        new() { Type = "evt", Op = op, Seq = seq, Mono = mono, Ts = ts, Data = data };

    public static HpspMessage Ack(long seq) =>
        new() { Type = "ack", Data = new() { ["seq"] = seq } };

    public static HpspMessage Pake(string op, Dictionary<string, object?>? data = null) =>
        new() { Type = "pake", Op = op, Data = data ?? new() };

    // ---- conversion to and from the CBOR map ---------------------------------

    /// <summary>Build the CBOR map for this message. Absent members are simply left out.</summary>
    public Dictionary<string, object?> ToMap()
    {
        var m = new Dictionary<string, object?> { ["type"] = Type };
        if (Op is not null) m["op"] = Op;
        if (Id is not null) m["id"] = Id.Value;
        if (Re is not null) m["re"] = Re.Value;
        if (Seq is not null) m["seq"] = Seq.Value;
        if (Mono is not null) m["mono"] = Mono.Value;
        if (Ts is not null) m["ts"] = Ts;
        if (Data.Count > 0) m["data"] = Data;
        return m;
    }

    public byte[] Encode() => HpspCbor.Encode(ToMap());

    /// <summary>Decode and check the envelope. Throws <see cref="HpspCborException"/> if invalid.</summary>
    public static HpspMessage Decode(ReadOnlyMemory<byte> bytes)
    {
        var m = HpspCbor.DecodeMessage(bytes);
        if (!m.TryGetValue("type", out var t) || t is not string type) throw new HpspCborException("message has no type");
        return new HpspMessage
        {
            Type = type,
            Op = m.GetValueOrDefault("op") as string,
            Id = m.GetValueOrDefault("id") as long?,
            Re = m.GetValueOrDefault("re") as long?,
            Seq = m.GetValueOrDefault("seq") as long?,
            Mono = m.GetValueOrDefault("mono") as long?,
            Ts = m.GetValueOrDefault("ts") as string,
            // "data", when present, must be a map (a message with some other kind of data is malformed).
            Data = m.GetValueOrDefault("data") switch
            {
                null => new(),
                Dictionary<string, object?> d => d,
                _ => throw new Cbor.HpspCborException("\"data\" must be a map"),
            },
        };
    }

    // ---- typed accessors for data members --------------------------------------
    //  They return null when a member is missing or has the wrong type, so callers
    //  can answer "bad_request" instead of crashing on malformed input.

    public long? GetLong(string key) => Data.GetValueOrDefault(key) as long?;
    public string? GetString(string key) => Data.GetValueOrDefault(key) as string;
    public byte[]? GetBytes(string key) => Data.GetValueOrDefault(key) as byte[];
    public bool? GetBool(string key) => Data.GetValueOrDefault(key) as bool?;
    public Dictionary<string, object?>? GetMap(string key) => Data.GetValueOrDefault(key) as Dictionary<string, object?>;
    public List<object?>? GetList(string key) => Data.GetValueOrDefault(key) as List<object?>;

    /// <summary>A one-line description for the activity window.</summary>
    public string Describe() => Type + (Op is null ? "" : " " + Op)
        + (Id is null ? "" : " #" + Id) + (Re is null ? "" : " re #" + Re) + (Seq is null ? "" : " seq " + Seq);

    /// <summary>The whole message in the specification's JSON notation.</summary>
    public string ToJson(bool showSecrets = false) => JsonNotation.Render(ToMap(), showSecrets);
}
