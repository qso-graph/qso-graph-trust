QSO Graph Trust (QGT): sign logs for ARRL's Logbook of The World
Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS)

QGT is free software: you can redistribute it and/or modify it under the terms of the GNU General
Public License, version 3 only, as published by the Free Software Foundation. It is distributed in the
hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See LICENSE for the full text.

QGT is not made, endorsed or supported by the American Radio Relay League (ARRL). "Logbook of The
World", "LoTW", "TrustedQSL" and "TQSL" are ARRL's names, used only to say what QGT works with.

QGT is written to interoperate with TrustedQSL (TQSL), by ARRL and The TrustedQSL Developers
(https://sourceforge.net/projects/trustedqsl/), whose contributors its AUTHORS.txt lists as WA1GON,
K1MK, KE3Z, K1MU, KC2YWE and AA6YQ. TrustedQSL is Copyright (C) 2001-2015 American Radio Relay
League, Inc., portions (C) 2003-2026 The TrustedQSL Developers, and licensed under ARRL's BSD-style
terms. QGT is not ported from TQSL's code. It carries two things of TrustedQSL's, both ARRL's: the TQSL
configuration (data/tqsl-config/config.xml, and the tables generated from it) and ARRL's root and CA
certificates as TQSL embeds them (crates/qso-graph-trust/src/lotw/arrl.rs). Each carries ARRL's
copyright notice and licence terms as they require: data/tqsl-config/LICENSE.txt, and its unchanged
copy crates/qso-graph-trust/LICENSE-ARRL.md, which ships with the library.

The crates QGT depends on are not part of this repository and are used under each one's own licence,
as each crate's manifest and licence files state. Cargo.lock names each one and where it came from.
