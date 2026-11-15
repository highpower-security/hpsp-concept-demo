// =============================================================================
//  HPSP Demo  -  Hpsp.Core.Tests
//  File:    Program.cs
//  Purpose: Headless tests for the core library. They run on Windows, macOS
//           and Linux with "dotnet run" and need no user interface.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  The test data in TestData/ is exported from the specification's own source,
//  so these tests check the code against the document, not against itself:
//    spec_examples.json  every example message in the specification
//    spec_vectors.json   the Annex E test vectors (grant and commissioning)
// =============================================================================

using System.Text.Json;
using Hpsp.Core.Tests;

int failures = 0, checks = 0;
void Check(bool ok, string what)
{
    checks++;
    if (!ok) failures++;
    Console.ForegroundColor = ok ? ConsoleColor.Green : ConsoleColor.Red;
    Console.Write(ok ? "PASS " : "FAIL ");
    Console.ResetColor();
    Console.WriteLine(what);
}

var dir = Path.Combine(AppContext.BaseDirectory, "TestData");
var vectors = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "spec_vectors.json"))).RootElement;
var examples = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "spec_examples.json"))).RootElement;

Console.WriteLine("== CBOR and message examples ==");
CoreTests.Cbor(examples, Check);
Console.WriteLine("== Grants (Annex E) ==");
CoreTests.Grants(vectors, Check);
Console.WriteLine("== 26-bit cards ==");
CoreTests.Wiegand(Check);
Console.WriteLine("== SPAKE2+ (RFC 9383 and Annex E) ==");
CoreTests.Spake(vectors, Check);
Console.WriteLine("== Pairing TLS (BouncyCastle, pre-shared key) ==");
await CoreTests.PairingTlsTest(Check);
Console.WriteLine("== Session TLS 1.3 with the demo certificates ==");
await CoreTests.SessionTlsTest(Check, useBouncyCastle: false);
await EngineTests.Run(Check);
Hpsp.Core.Tests.LocalizationTests.Run(Check);
await Hpsp.Core.Tests.EndToEndTests.Run(Check);
foreach (var extra in CoreTests.Extra) await extra(Check);

Console.WriteLine();
Console.WriteLine($"{checks} checks, {failures} failed");
return failures == 0 ? 0 : 1;
