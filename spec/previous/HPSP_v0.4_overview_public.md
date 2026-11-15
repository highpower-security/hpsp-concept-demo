# HPSP v0.4: Public Review Overview

*Draft proposal for comment. Published by Highpower Security Products LLC. Not a standard and not ready for products. Author: Dan DeMerchant.*

## 1. Introduction

The High Performance Security Protocol (HPSP) is a proposed protocol for connecting card readers, locks, sensors and other door hardware to access controllers over Ethernet, including single-pair Ethernet that can reuse much of today's two-wire cabling. It is designed to sit beside OSDP, the established protocol for readers on RS-485, and to address the needs that appear when this work moves onto IP networks. The full working draft sets out the design in detail, including its open questions.

## 2. Core Architecture

HPSP is built around a few deliberate choices:

* **Persistent, authenticated sessions.** Each device opens one encrypted connection to its controller (TLS 1.3, with certificates on both sides) and keeps it open. Devices dial out and do not listen for connections in normal operation.
* **Event-driven operation.** Devices report card reads, door changes and alarms as they happen rather than waiting to be polled. Events are numbered, acknowledged and replayed after a reconnection, so a short cable fault does not lose them.
* **Separate authority to unlock.** Releasing a door requires a signed grant tied to that device and that connection, issued by a key held apart from the network-facing parts of the system.
* **A component model.** A device describes its parts (readers, inputs, outputs, indicators) once, and the same small set of operations works for every product.
* **Topologies.** Point-to-point single-pair links (10BASE-T1L, 100BASE-T1), short shared segments at the door (10BASE-T1S), and ordinary switched Ethernet.
* **Small-processor friendly.** One curve, one hash and one cipher, bounded messages and a compact binary encoding (CBOR), so the device side can run on a mid-range microcontroller. Access decisions remain the controller's job.

## 3. How HPSP Relates to OSDP

OSDP is a simple, proven protocol with a large installed base and an international standard behind it (IEC 60839-11-5), and it will remain in service for many years. HPSP aims to address areas where moving to IP makes a different design worthwhile. The comparisons below refer to OSDP v2.2 as published; OSDP products and later revisions, including the Secure Channel 2 work, may differ.

* **Bandwidth and firmware updates.** OSDP runs at 9,600 to 230,400 baud on a shared, polled bus. HPSP links run at 10 Mb/s or more. Our planning estimates suggest reader firmware updates could take seconds rather than tens of seconds or minutes; this has yet to be measured.
* **Interoperability.** Both protocols use capability discovery and allow manufacturer extensions. HPSP keeps extensions named and visible in a device's capability descriptor, and proposes a public conformance suite.
* **Key management at scale.** OSDP uses a per-reader AES key set by the control panel. HPSP uses per-device certificates, commissioning with a setup code, automatic renewal and revocation, which we expect to simplify large installations.
* **Diagnostics.** In addition to tamper and power reporting, HPSP defines typed errors, security events and, on point-to-point links, cable diagnostics and signal margin reported to the controller.

OSDP remains the better fit for very small processors, existing RS-485 wiring and sites that need a certified, standardised solution today. HPSP proposes a gateway so that OSDP readers can be used alongside it.

## 4. Security Considerations

HPSP is built on widely reviewed standards rather than new cryptography: TLS 1.3 with AES-GCM and ephemeral key agreement, ECDSA P-256 signatures, and SPAKE2+ for commissioning. Implementations are required to use constant-time cryptographic code and mutual authentication before any data is exchanged. The design has not yet had an independent security review, and the draft lists the questions on which comment is most wanted.

## 5. Next Steps

* Define a transport abstraction so the message layer can be tested apart from TLS and TCP.
* Build reference device and controller implementations and benchmark dense reader installations.
* Measure firmware update times and microcontroller resource use against the estimates in the draft.
* Gather stakeholder feedback on the HPSP and OSDP comparison.
* Arrange an independent security review.

*OSDP is a protocol of the Security Industry Association (SIA). PKOC is a specification of the Physical Security Interoperability Alliance (PSIA). Other names are the property of their owners; their mention does not imply endorsement.*
