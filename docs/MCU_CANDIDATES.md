# HPSP microcontroller candidate research

As of 19 November 2026. Companion to the HPSP 0.6 draft, section 11 (implementation classes). Nothing here has been run against HPSP; timings are other people's benchmarks. Prices are Digi-Key listings and move daily.

## Summary

Start every HPSP device on a Cortex-M33 at 100 MHz or more with 256 KB of RAM or more, a hardware random generator and a public-key accelerator. Parts below that line can run HPSP on paper but leave no room for a second session, an update slot or a later feature.

- **Reader:** NXP MCX A5 (M33, up to 240 MHz, 640 KB RAM, built-in 10BASE-T1S) once it ships. Today, an STM32U5 or STM32H5 with a Microchip LAN8651 or LAN8670 single-pair chip.
- **Door hub:** STM32H573 (M33, 250 MHz, 640 KB RAM, 2 MB flash, Ethernet MAC, AES and PKA).
- **ACU:** a Linux-class processor (NXP i.MX 9 family, ST STM32MP2). Renesas RX74M if the ACU must stay on an RTOS.
- **Software stack:** wolfSSL. It lists both hybrid groups HPSP names (SecP256r1MLKEM768 and X25519MLKEM768). Mbed TLS does not yet.

## What HPSP asks of a microcontroller

| Need | Floor | Recommended |
| --- | --- | --- |
| Core | Cortex-M4, or M33 with DSP | Cortex-M33 |
| Clock | 48 MHz (64 MHz advised) | 100 MHz or more |
| RAM | 96 KB, one session | 256 KB or more |
| Flash | 512 KB, or 256 KB plus external for the second image | 1 MB, or 512 KB plus external |
| Public-key | Assembly-optimized P-256 | On-chip accelerator or assembly |
| Other | True random generator, read-out protection, watchdog | TrustZone, or a secure element on the board |

One signature check takes about 20 to 100 ms on the recommended class, about 75 ms at 48 MHz with assembly, and 0.4 to 0.7 s at 48 MHz with compact C. A Cortex-M0+ takes roughly 2 to 5 s, so those parts are out. The goal is a 600 ms unlock.

The hybrid key exchange adds memory more than time. wolfSSL measured ML-KEM-768 at 6.5 ms (key generation), 6.6 ms (encapsulate) and 8.3 ms (decapsulate) on a 168 MHz Cortex-M4 with no hardware crypto.

## Three device classes

| Role | What it does | Part class | Why |
| --- | --- | --- | --- |
| Reader | One session to the hub, verifies grants | Class S: M33, 256 KB RAM | Cost and size matter; it only verifies |
| Door hub | Several readers, relays, event buffer in flash | Class M: M33 or M7 at 100 MHz or more, 512 KB RAM or more | More sessions, larger event queue |
| ACU | Signs grants, keeps the access list | Class L: Linux-class, or a fast M7-class MCU | Signing and key storage dominate |

wolfSSL measured ML-DSA-44 signing at 60 ms and verification at 22 ms on the same Cortex-M4, so a reader verifying grants is cheap and an ACU signing many is not.

## Candidates by vendor

**ST.** The [STM32H563 and H573](https://www.st.com/en/microcontrollers-microprocessors/stm32h563-573.html) are Cortex-M33 parts at up to 250 MHz with 1 to 2 MB of flash, 640 KB of SRAM, TrustZone and an Ethernet MAC; the H573 adds AES, PKA and OTFDEC. ST's [X-CUBE-PQC](https://www.st.com/en/embedded-software/x-cube-pqc.html) covers ML-KEM and ML-DSA. The [STM32G5](https://www.cnx-software.com/2026/11/10/280-mhz-stmicro-stm32g5-cortex-m33-mixed-signal-mcu-targets-digital-power-and-motor-control-applications/) is too small (60 or 112 KB of RAM) and post-quantum only in software; reports disagree on whether hardware PQC arrives now or with a 2027 dual-core G5D.

**NXP.** The [MCX A5](https://www.nxp.com/company/about-nxp/newsroom/NW-NXP-SIMPLIFIES-INDUSTRIAL-MCX-A5-MCU) pairs a Cortex-M33 (up to 240 MHz, up to 2 MB flash, 640 KB RAM) with an integrated 10BASE-T1S digital PHY, a post-quantum hardware root of trust and a PSA Level 3 target. It is sampling; NXP lists it as preproduction. It supports Zephyr and the MCUXpresso SDK. The i.MX 9 processors add an EdgeLock secure enclave with PQC support and run Linux (not opened).

**Microchip.** The [LAN8651](https://microchip.com/en-us/product/lan8651) is a 10BASE-T1S MAC-PHY with an SPI host interface, so an MCU without an Ethernet MAC can join a single-pair bus. Microchip's [gateway reference design](https://www.microchip.com/en-us/about/media-center/blog/2026/extending-secure-ethernet-connectivity-to-the-cloud) uses a PIC32CK SG (M33, TrustZone, hardware security module).

**Renesas.** The RX74M and RX74N (announced 22 October 2026) have a 600 MHz core, Gigabit TSN Ethernet and a security block that Renesas says supports PQC (search results only).

**Texas Instruments.** The [MSPM33C321A](https://www.ti.com.cn/cn/lit/pdf/sprt807) is an M33 at up to 160 MHz with 1 MB flash and 256 KB RAM. Its SDK has software ML-DSA-87; no Ethernet is listed, so it needs an SPI MAC-PHY.

**Espressif.** An [esp-pqc measurement](https://developer.espressif.com/blog/2026/10/esp32-post-quantum-cryptography/) shows a hybrid TLS 1.3 handshake (X25519MLKEM768, ML-DSA-65 certificates) of about 300 ms on an ESP32-C5, in software. Prototype only.

**Not recommended:** Nordic nRF54L15 (PQC experimental, no Ethernet), Infineon PSOC Control C3 and Silicon Labs Series 3 (no Ethernet or PQC evidence).

## Side by side

| Part | Core, clock | RAM | Flash | Wired link | PQC support | Fit |
| --- | --- | --- | --- | --- | --- | --- |
| NXP MCX A5 | M33, up to 240 MHz | up to 640 KB | up to 2 MB | 10BASE-T1S built in | Hardware root of trust; sampling | Reader, best match |
| ST STM32H573 | M33, 250 MHz | 640 KB | 2 MB | 10/100 MAC (add PHY) | X-CUBE-PQC software; AES and PKA | Door hub |
| ST STM32H563 | M33, 250 MHz | 640 KB | 1 to 2 MB | 10/100 MAC (add PHY) | X-CUBE-PQC software | Hub, lower cost |
| ST STM32G5 | M33, 280 MHz | 60 or 112 KB | up to 512 KB | none listed | Software only today | Too small |
| Microchip PIC32CK SG | M33 | not confirmed | not confirmed | via LAN8651 (SPI) | Not confirmed | Check datasheet |
| Renesas RX74M/N | RXv3e, 600 MHz | not confirmed | not confirmed | Gigabit TSN | RSIP "supports PQC" | Possible ACU, unverified |
| TI MSPM33C321A | M33, 160 MHz | 256 KB | 1 MB | none listed | Software ML-DSA-87 | Marginal; needs MAC-PHY |
| Espressif ESP32-C5/S31 | RISC-V | not checked | not checked | S31: Gigabit MAC | Software, 300 ms handshake | Prototype only |
| Nordic nRF54L15 | M33, 128 MHz | not checked | not checked | none | Experimental | No |

The fit column is a judgment against the section 11 floor, not a vendor claim.

Price check (Digi-Key, per part at 1,000 units): [STM32H563VGT6](https://www.digikey.com/en/products/detail/stmicroelectronics/STM32H563VGT6TR/22519698) about $4.07; [STM32H563RGV6](https://www.digikey.fi/en/products/detail/stmicroelectronics/STM32H563RGV6/21349093) about €3.25; [STM32H573VIT6](https://www.digikey.be/en/products/detail/stmicroelectronics/STM32H573VIT6/21348909) about $5.20; STM32G5 about $1.03 at 10,000.

## Recommendations by role

1. **Reader, single-pair cable:** NXP MCX A5. Prototype on an STM32H573 with a LAN8670 or LAN8651 and move over when parts ship.
2. **Reader, Ethernet cable:** STM32H563. Same core and RAM as the hub, about $1 cheaper per part at 1,000 units.
3. **Door hub:** STM32H573 (250 MHz, 640 KB RAM, 2 MB flash for two images, a MAC, AES and PKA).
4. **ACU:** a Linux-class processor (NXP i.MX 93 or 95, ST STM32MP2) running wolfSSL or OpenSSL with ML-DSA-44 signing. A bare-metal MCU such as the RX74M only after verifying its memory.
5. **Secure element (DAL-2):** ATECC608, SE050, OPTIGA Trust M or STSAFE-A on I2C; each adds 50 to 100 ms per signature in the handshake.
6. **TLS library:** wolfSSL 5.8.0 or later lists SecP256r1MLKEM768 and X25519MLKEM768; [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.pdf) defines both. Mbed TLS's [roadmap](https://mbed-tls.readthedocs.io/en/latest/roadmap/) shows ML-KEM only as "Future" and has no hybrid TLS entry.

## What to verify before choosing

- Run the real code. Measure handshake time, one grant check, peak RAM and image size on a dev board.
- [wolfSSL's memory study](https://www.wolfssl.com/optimizing-post-quantum-algorithm-memory-usage-on-embedded-systems/) ran on a Raspberry Pi 5: ML-KEM-768 about 29 to 45 KB of stack plus heap, ML-DSA-44 about 30 to 66 KB, no code size. Expect the same order on an MCU.
- The [wolfSSL STM32 benchmark](https://www.wolfssl.com/updated-post-quantum-benchmarks-for-ml-kem-and-ml-dsa-on-stm32/) used a NUCLEO-F439ZI at 168 MHz with assembly and no hardware crypto; its page names two different boards.
- PQC hardware claims (MCX A5, STM32G5, RX74M) are weeks old. Ask each vendor which algorithms the accelerator runs and whether the TLS stack can use it.
- 10BASE-T1S is multidrop over about 25 m; 10BASE-T1L (long reach) is not covered here.

Not opened (search results only): Renesas RX74M/N announcement, NXP i.MX 9 security pages, Nordic crypto support list, ST wiki on Mbed TLS with the STM32 PKA, wolfSSL 5.8.0 hybrid-groups post.
