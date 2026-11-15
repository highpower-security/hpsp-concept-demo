# Third-party components

The demo and the C reference use the following components. Each keeps its own licence.

## Demo (`demo/`)

| Component | Version | Used for | Licence |
|---|---|---|---|
| [BouncyCastle.Cryptography](https://www.bouncycastle.org/csharp/) | 2.7.0 | TLS 1.3 with a pre-shared key (pairing), the optional BouncyCastle TLS engine for sessions, and elliptic-curve arithmetic for SPAKE2+. All BouncyCastle code is in `demo/src/Hpsp.Core/BouncyCastle/`, between `BOUNCYCASTLE CODE - START` and `END` banners. | MIT |
| [QRCoder](https://github.com/codebude/QRCoder) | 1.6.0 | Drawing the reader's setup QR code (Reader Simulator only) | MIT |
| [System.Formats.Cbor](https://www.nuget.org/packages/System.Formats.Cbor) | 9.0.24 | CBOR encoding and decoding | MIT (.NET Foundation) |
| .NET 8 runtime and Windows Forms | 8.0 | Included in the self-contained `.exe` files | MIT (.NET Foundation) |

### BouncyCastle licence (MIT)

> Copyright (c) 2000-2024 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sub license, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### QRCoder licence (MIT)

> Copyright (c) 2013-2018 Raffael Herrmann
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## C reference (`c-reference/`)

| Component | Used for | Licence |
|---|---|---|
| [p256-m](https://github.com/mpg/p256-m), vendored in `c-reference/third_party/p256-m/` | ECDSA P-256 signature verification | Apache-2.0 |
| Python packages `cbor2`, `cryptography`, `ecdsa` (tools only, not shipped) | The controller simulator and the vector tools | MIT, Apache-2.0/BSD, MIT |
