// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! LoTW's own certificates, the trust QG Trust pins: a callsign certificate is trusted only if it
//! chains to [`ROOT`], never to a root a file brings with it.
//!
//! Both are ARRL's public certificates as TQSL 2.8.7 embeds them (`src/location.cpp`, `rootcertpem`
//! and `cacertpem`, at commit d9e01726e54887f8241e86e789c5b91f02043ebd), the same anchor TQSL loads.
//! TrustedQSL is Copyright (C) 2001-2015 American Radio Relay League, Inc., portions (C) 2003-2026 The
//! TrustedQSL Developers; what is copied here is redistributed under ARRL's terms in LICENSE-ARRL.md
//! at this crate's root, whose notice and disclaimer this file carries by reference.
//! Their dates have passed (the root's on 2025-06-06, the CA's on 2023-06-19) and TQSL accepts an
//! expired root or CA in a chain, so QG Trust does too; the callsign certificate itself must be in
//! force when it signs. If ARRL issues under a root not here, importing such a certificate is refused
//! naming the root, and the root is added here.

/// "Logbook of the World Root CA", American Radio Relay League; SHA-256 2E:35:F9:6E:F1:86:26:DC:90:1A:2C:F3:1B:FB:56:DA:FA:DC:70:30:D7:33:D9:B3:07:D0:DB:8E:87:C7:9A:0F.
pub const ROOT: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIHZzCCBU+gAwIBAgIJAIP/DUvt4MtDMA0GCSqGSIb3DQEBDQUAMIHSMQswCQYD\n\
VQQGEwJVUzELMAkGA1UECAwCQ1QxEjAQBgNVBAcMCU5ld2luZ3RvbjEkMCIGA1UE\n\
CgwbQW1lcmljYW4gUmFkaW8gUmVsYXkgTGVhZ3VlMR0wGwYDVQQLDBRMb2dib29r\n\
IG9mIHRoZSBXb3JsZDElMCMGA1UEAwwcTG9nYm9vayBvZiB0aGUgV29ybGQgUm9v\n\
dCBDQTEYMBYGCgmSJomT8ixkARkWCGFycmwub3JnMRwwGgYJKoZIhvcNAQkBFg1s\n\
b3R3QGFycmwub3JnMB4XDTE1MDYwOTE1MzQyOFoXDTI1MDYwNjE1MzQyOFowgdIx\n\
CzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDVDESMBAGA1UEBwwJTmV3aW5ndG9uMSQw\n\
IgYDVQQKDBtBbWVyaWNhbiBSYWRpbyBSZWxheSBMZWFndWUxHTAbBgNVBAsMFExv\n\
Z2Jvb2sgb2YgdGhlIFdvcmxkMSUwIwYDVQQDDBxMb2dib29rIG9mIHRoZSBXb3Js\n\
ZCBSb290IENBMRgwFgYKCZImiZPyLGQBGRYIYXJybC5vcmcxHDAaBgkqhkiG9w0B\n\
CQEWDWxvdHdAYXJybC5vcmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC\n\
AQDSV3CQz8/crg7uxPj/i3R8qs8vFqGOl3gWk4/BcKnJaYSf3I59cY3SlNxJhQmc\n\
zfAwOErOGW9C5gGInJJvpCLIkKZnHAeFhaNNn09/PaAPM0YrhTZMjUsHedhz9ObR\n\
UcZl7LEMhih9ctd3iPBf8FckG8MvgBJcMdMB1TrJfu8PekgRZtGKIG61tJc1tGYc\n\
RimmSaG3i4R0ZdiToj+tOifjbElDaLKTVnIn4YALSmA0RsB+UmPRZ/qMhI9663TM\n\
NsJfurcQL6TXg+EIHNnGlGa62y4cjNIPJdTI7Pk4rsL+WT4n7bZR+AWUVMXT6IYa\n\
ZvisOxmUM1qX9pYrcXf8OsWITE2GRRNMQZP+jVHQ3d4tl7JDNrNPziY1Oz9PLtud\n\
56ajJLf7smebsyza6e6NhZNgOhsSfbwu25fSc3b5xynI0TSwkz//J4szr8sfwkVJ\n\
whWoNG9GSONSHqnTQEaGVVarVpQUO9ZeuzOo3nZkSp7HH/aaf2akNGlwEqkqytn7\n\
HiYQKwbA54Vs+VRIX71TktF9KEdy6p03hVSfs9zqWuBLKdAX2een0IDTK9e8mdNF\n\
/9s4A5Q0mxASBrY9fe+FV347MLNctxDbaqeMcUsMBiyaihtTWmtZzC4zhBuccVW1\n\
u+YO26uodyGJ2ID7SQSyZDhiopWZLug//mhpTvvu8OZeewIDAQABo4IBPDCCATgw\n\
HQYDVR0OBBYEFMf8ysJzxa/LW/U6YH2anBrvwI2TMIIBBwYDVR0jBIH/MIH8gBTH\n\
/MrCc8Wvy1v1OmB9mpwa78CNk6GB2KSB1TCB0jELMAkGA1UEBhMCVVMxCzAJBgNV\n\
BAgMAkNUMRIwEAYDVQQHDAlOZXdpbmd0b24xJDAiBgNVBAoMG0FtZXJpY2FuIFJh\n\
ZGlvIFJlbGF5IExlYWd1ZTEdMBsGA1UECwwUTG9nYm9vayBvZiB0aGUgV29ybGQx\n\
JTAjBgNVBAMMHExvZ2Jvb2sgb2YgdGhlIFdvcmxkIFJvb3QgQ0ExGDAWBgoJkiaJ\n\
k/IsZAEZFghhcnJsLm9yZzEcMBoGCSqGSIb3DQEJARYNbG90d0BhcnJsLm9yZ4IJ\n\
AIP/DUvt4MtDMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQENBQADggIBACtCtzn8\n\
41EpI7W55nNMIBcqBrzs2fil61aOt7b6BHk+KpFWonsKMcCsnT4W6yye+lG7aKf9\n\
eGjrxaSd8vHDKiYwr5fp2ahqmDyROtYyJgSJpurQUA+pB5lrIip2IuVNu3g92x7o\n\
CeGgGNU99/2WK0JXPVIAmTY4MO8B6wZ/ZVgB+QLfFEvMBWSiosnwfgT2cGynqCpz\n\
n5Q9SOFDAd83IjaOuuEssfLaRB1o3/UAS/wXgVLm5h+VjWLQ3176YPx/j6Ik+XAg\n\
QAQKLSyGhlZzVeRwPzCXKsAdPqIG7EUSLgqv2I9XyPS6zsI+UVw3WvJO3D6pEN77\n\
l6bqqvPWLjnZV4jV9PF3lenA0kChe+y+gTTejXNWyew8y0TTl4NOJPWjXsvKTQox\n\
oLY+0MhsyGzVSb2/HFs/B8/G9Fp+fiPOE8iv7sHs1ONhiAy4E2UgbPBG6OSXKP0Q\n\
hYyOMmcrBVAtTkq6DXugr0e2VBhs2wHlX3hVhlwNIGBA3Xrlji1Hx3gQjS0JZa1D\n\
ZCnX6/oGCbS6pio5/TyI0b1vArTMY1Sk/LFF7KjgfXGcxGO0i55HBqQhM3O68q/c\n\
vbT46W7TQ5zZUgFBeMltaxc2z3UsTiM02nF4K4hmsfD8Equh2fA5msc+p5PuaOJR\n\
4vVAjEWroIfchuU2z2ynrs3ZxrkZjJ+x72jD\n\
-----END CERTIFICATE-----\n\
";

/// "Logbook of the World Production CA", issued by the root; SHA-256 A6:89:D0:B4:ED:C4:F1:AF:DD:2C:62:C5:01:C8:13:6E:1F:35:4C:9D:7D:ED:06:4D:91:C9:D6:2A:F8:BD:EC:93.
pub const PRODUCTION_CA: &str = "\
-----BEGIN CERTIFICATE-----\n\
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\n\
euRFuHg4j85bSZ3Nd+cvb09Fdr5xeJtHsCIn4g==\n\
-----END CERTIFICATE-----\n\
";
