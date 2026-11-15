# HPSP ACU Simulator: source code

`HpspAcuSimulator.exe`: the access control unit (controller), for the HPSP demo. Everything needed to build this program is in this folder.

| Folder | What it is |
|---|---|
| `HpspAcuSimulator/` | This program's window (Windows Forms). Thin: it shows the engine's state and passes on button presses. |
| `Hpsp.Core/` | The HPSP protocol: CBOR, framing, TLS (Windows and BouncyCastle), SPAKE2+ pairing, grants, and the ACU and reader engines. No user interface. |
| `Hpsp.Demo.Ui/` | Window pieces shared by both demo programs: the activity window, the provisioning checklist, the TLS engine picker. |
| `Tests/Hpsp.Core.Tests/` | Headless tests: the specification's examples and vectors, and full ACU-and-reader runs on both TLS engines. |
| `AcuSimulator.sln` | The solution with all four projects. |

**Shared code.** `Hpsp.Core`, `Hpsp.Demo.Ui` and `Tests` are identical copies of the same folders in the other program's folder (`../AcuSimulator` and `../ReaderSimulator`), so each program builds on its own. If you change one copy, copy the change to the other; `../build/check-copies.sh` (also run by the GitHub build) reports any difference.

## Build and run (Windows, .NET 8 SDK)

```
dotnet run --project HpspAcuSimulator                  # start the program
dotnet run --project Tests/Hpsp.Core.Tests     # run the tests (about 2 minutes)
```

Or open `AcuSimulator.sln` in Visual Studio 2022. To make the single-file `.exe` for x64 and Arm64, see `../build/publish.ps1`.

How the code fits together: [../ARCHITECTURE.md](../ARCHITECTURE.md). How to use the programs: [../../RUNNING.md](../../RUNNING.md).
