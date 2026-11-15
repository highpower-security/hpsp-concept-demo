# Running the HPSP demo

*[Version française : RUNNING.fr.md](RUNNING.fr.md)*

The demo is two Windows programs that talk to each other using the HPSP protocol:

| Program | File name | What it is |
|---|---|---|
| **ACU Simulator** | `HpspAcuSimulator.exe` | The access control unit (the controller). It holds the site's keys and the access list, pairs readers, and decides whether a card opens the door. |
| **Reader Simulator** | `HpspReaderSimulator.exe` | A card reader with a door strike and an LED. You type a 26-bit card number and "swipe" it. |

Each one is a single `.exe` file. There is nothing to install, and you don't need .NET.

## 1. Pick the right download

The ready-made programs are on this repository's **Releases** page. Each build comes as two zip files, named `HPSP-Demo-<version>-build<n>-<kind of PC>.zip`, for example `HPSP-Demo-0.5.0-build2-win-arm64.zip`. A higher build number is newer. Choose the zip that matches your PC's processor:

| Your PC | Download |
|---|---|
| Ordinary Intel or AMD PC (most PCs) | the `…-win-x64.zip` |
| Arm PC: Windows on a Mac with Apple silicon (Parallels, VMware Fusion), Surface Pro X / Pro 11, Snapdragon laptops | the `…-win-arm64.zip` |

To check, open **Settings → System → About** and look at *System type*. "x64-based processor" means the x64 download, and "ARM-based processor" means the Arm64 download. (The x64 version also runs on Arm PCs, more slowly, under emulation. The status bar then says "x64 emulated".)

Supported: **Windows 11** and **Windows 10**. On Windows 10, the "Windows built-in" TLS option is greyed out because Windows 10 has no TLS 1.3. The programs use the BouncyCastle option instead, and it works the same.

## 2. First start: two Windows prompts

The programs are not code-signed (this is a demo), so Windows asks twice the first time:

1. **"Windows protected your PC"** (SmartScreen). Click **More info**, then **Run anyway**.
   If the file came from the internet, you can instead right-click the `.exe`, choose **Properties**, tick **Unblock**, then click **OK**.
2. **Windows Defender Firewall** asks whether the program may use the network. Allow **Private networks**. The ACU listens on TCP port **7500**. The reader listens on port **7501**, but only while its pairing window is open.
   If both programs run on the same computer, the firewall doesn't matter. It's needed only when the reader and the ACU are on different computers.

## 3. Start them: ACU first, then the reader

1. Start **`HpspAcuSimulator.exe`**.
2. Start **`HpspReaderSimulator.exe`**. Start it again for a second reader: the second copy becomes "Reader #2", with its own identity and pairing port 7511 (a third uses 7521, and so on).

Both windows have a **Provisioning checklist** panel on the right. Each step ticks itself off when you've done it, and it explains what is happening in the protocol. The **Language / Langue** menu switches between English and French.

## 4. The walkthrough (about five minutes)

**In the ACU Simulator**

1. Click **Create demo site…** and accept the defaults. This makes the site's root certificate, the ACU's TLS certificate and the grant signer. If the reader will run on another computer, pick this computer's network address under *Address readers are told to dial*.
2. The ACU starts **listening on port 7500**.
3. In the **Access list**, add two cards. For example:
   - Facility **142**, card **54321**, name *Alice*, **Allowed** ticked
   - Facility **142**, card **11111**, name *Bob*, **Allowed** not ticked

**In the Reader Simulator**

4. Note the **setup code** (for example `7KQ4-M9TW`). It is printed on a real reader's label.
5. Click **Open pairing window (press the pairing button)**. The reader now accepts pairing for 10 minutes.

**Back in the ACU Simulator**

6. Click **Add reader…** and enter:
   - address `127.0.0.1` (or the reader computer's address),
   - pairing port `7501`,
   - the setup code. Instead of the code you can paste the QR text from the reader's **Copy QR text** button.

   Then click **Pair**. The activity windows show SPAKE2+ (`pake_…`), then TLS with the shared key, then `attest_request`, `enroll` and `cert_install`.
7. The reader connects by itself. It shows **Online**, and the ACU sends it the grant signer's certificate (`trust_update`).

**Swipe cards**

8. In the reader, enter facility **142** and card **54321**, and click **Swipe card**. The ACU sends a signed `unlock`. The reader checks the grant, the door turns green (**UNLOCKED**) for the unlock time, and the LED turns green.
9. Swipe card **11111**. It is refused: the ACU makes no grant at all, and the LED flashes red.

**Things to try**

- **Attack demo** (ACU, with the reader selected): replay the last grant, send an expired grant, one for the reader's previous session, a tampered one, or one signed by an untrusted key. The reader refuses each one and the door stays locked.
- **Pull network cable** (reader): swipe a card while offline, then plug the cable back in. The swipe is delivered late, so the ACU logs it but opens no door: the card read is too old.
- **Wrong setup code**: after 5 wrong codes the reader locks pairing for 5 minutes (each further lock-out lasts twice as long, up to an hour).
- **Show secrets (demo only)**: shows the keys, the SPAKE2+ values and the pre-shared key in the activity window's detail pane. A real device never shows these.
- Click any line in the activity window to see the whole message as JSON, plus its CBOR bytes on the wire.

## 5. Where things are kept, and starting over

Each program keeps its keys and settings in `%LOCALAPPDATA%\HPSP Demo\` (folders `ACU`, `Reader`, `Reader 2`…). **File → Open the data folder** opens it. These are demo keys kept in plain files. Never reuse them.

- To pair a reader with a different site, use **Factory reset…** in the reader. It keeps the reader's factory identity and setup code.
- To make a completely new reader, use **New device…**.
- To start everything from scratch, close both programs and delete the `HPSP Demo` folder.

Optional command-line switches: `--data <folder>` for both programs, and `--pairing-port <n>` for the reader.

## 6. Building from source instead

You need the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) on Windows. Then:

Each program has its own source folder, which builds on its own:

```
cd demo\AcuSimulator
dotnet run --project HpspAcuSimulator
cd ..\ReaderSimulator
dotnet run --project HpspReaderSimulator
dotnet run --project Tests\Hpsp.Core.Tests      # the automated tests
```

To make the single-file `.exe` files and the zips, use `demo\build\publish.ps1 -Build <n>` (Windows) or `demo/build/publish.sh <n>` (Linux/macOS), where `<n>` is the build number.
