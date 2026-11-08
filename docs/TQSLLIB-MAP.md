<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# tqsllib's functions and QG Trust

Every function and variable tqsllib 2.8.7 offers a program that links it, and what QG Trust has for
each: the Rust it calls, or the `qg-trust` command, with the test that proves it; or why it needs
none. QG Trust is its own design, so most of tqsllib's calls have no one-to-one counterpart: what
LoTW receives is the same, and how QG Trust gets there is its own. This map is for anyone who knows
tqsllib's interface and wants QG Trust's way of doing the same thing. What QG Trust does as a
whole, feature by feature, is in [FEATURE-PARITY.md](FEATURE-PARITY.md).

**What is counted.** tqsllib's public interface is the five headers its `src/CMakeLists.txt` installs
(`HEADERS_TO_INSTALL`): `tqsllib.h`, `tqslerrno.h`, `cabrillo.h`, `adif.h` and `tqslconvert.h`, at
tqsllib 2.8.7 (commit `d9e01726e54887f8241e86e789c5b91f02043ebd`). A program can reach what those
headers declare with `DLLEXPORT` (functions) and `DLLEXPORTDATA` (variables), comments aside. That
is 209 function declarations and 11 variables, 220 in all; five functions are declared twice in
`tqsllib.h` (`tqsl_getNumLocationField`, `tqsl_getLocationFieldDataLabelSize`,
`tqsl_getLocationFieldDataLabel`, `tqsl_getLocationFieldDataGABBISize` and
`tqsl_getLocationFieldDataGABBI`), so there are **204 functions and 11 variables, 215 names**, each
listed once below in header order. `tqslerrno.h` declares error numbers only.

| | Names | QG Trust has it, with a test | Not needed | Not applicable |
|---|---|---|---|---|
| Functions | 204 | 117 | 51 | 36 |
| Variables | 11 | 4 | 2 | 5 |
| **All** | **215** | **121** | **53** | **41** |

**Not needed** means QG Trust leaves it out on purpose or for later, with the reason; the decisions
are FEATURE-PARITY.md's. **Not applicable** means the call manages something QG Trust does not have:
global state, memory a caller frees by hand, C buffers, or the pages of TQSL's location wizard.
A path marked *internal* is inside the library, not part of its public interface. Tests are named
by their file under `crates/` and their function.

`scripts/tqsllib-map.py --check` keeps this map honest: the names must be these 215 in this order
(pinned by their SHA-256, and compared with the headers themselves when it is given tqsllib's
source with `--tqsl-src`), and every Rust path, `qg-trust` command and test named here must exist.

<!-- tqsllib-map:begin -->
## `tqsllib.h`: exported variables

| tqsllib | What it does | QG Trust | Test |
|---|---|---|---|
| `tQSL_BaseDir` | The folder tqsllib keeps its files in | `qso_graph_trust::store::default_dir`, `qso_graph_trust::store::Store::open` (the folder is an argument) | `qso-graph-trust/src/store/tests.rs::platform_default_folder_uses_the_shared_service_path` |
| `tQSL_RsrcDir` | The folder its configuration (`config.xml`) is read from | Not needed: ARRL's configuration is generated into the library when it is built (`scripts/gen-lotw-tables.py`); nothing is read at run time |  |
| `tQSL_Error` | The last error's code | Not applicable: no global state; each call returns its own error value (`qso_graph_trust::store::StoreError` and the others) |  |
| `tQSL_ADIF_Error` | The last ADIF reading error | Not applicable: no global state; each call returns its own error value (`qso_graph_trust::records::RecordError`) |  |
| `tQSL_Cabrillo_Error` | The last Cabrillo reading error | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tQSL_ErrorFile` | The file the last error concerns | Not applicable: no global state; each call returns its own error value; the command line names the file in its message |  |
| `tQSL_CustomError` | Text for the last error | Not applicable: no global state; each call returns its own error value |  |
| `tQSL_Errno` | The system error behind the last error | Not applicable: no global state; each call returns its own error value, which carries the system's error where there is one |  |
| `tQSL_ImportCall` | The call of the certificate last imported | `qso_graph_trust::import::ImportedCertificate::id`, returned by `qso_graph_trust::store::Store::import_pkcs12` and `qso_graph_trust::store::Store::import_tq6`, names the certificate imported; its `qso_graph_trust::certificate::Certificate::callsign` is the call | `qso-graph-trust/src/store/tests/import.rs::default_pkcs12_imports_for_both_corpus_key_password_cases_and_signs` `qso-graph-trust/src/store/tests/import.rs::tq6_attaches_a_matching_pending_request_and_otherwise_loads_keyless` |
| `tQSL_ImportSerial` | The serial of the certificate last imported | `qso_graph_trust::import::ImportedCertificate::id` names the certificate imported; its `qso_graph_trust::certificate::Certificate::serial` is the serial | `qso-graph-trust/src/store/tests/import.rs::default_pkcs12_imports_for_both_corpus_key_password_cases_and_signs` `qso-graph-trust/src/certificate.rs::serials_are_read_whole_and_never_negative` |
| `tQSL_DiagFile` | The open diagnostic log | `qg-trust -t` (the command line's diagnostic log); the library writes none | `qso-graph-trust-cli/src/cli/tests.rs::t_writes_a_diagnostic_log_with_no_password_or_key_in_it` |

## `tqsllib.h`: functions

| tqsllib | What it does | QG Trust | Test |
|---|---|---|---|
| `tqsl_init` | Set up the library's global state | Not needed: QG Trust has no global state; a `Store` is opened on its own and ARRL's tables are compiled in |  |
| `tqsl_setDirectory` | Choose the folder tqsllib keeps its files in | `qso_graph_trust::store::Store::open` | `qso-graph-trust/src/store/tests.rs::first_use_creates_a_nested_directory_and_accepts_later_writes` `qso-graph-trust/src/store/tests.rs::platform_default_folder_uses_the_shared_service_path` |
| `tqsl_getErrorString` | The last error, in words | Each error type's `Display`, e.g. `qso_graph_trust::store::StoreError` | `qso-graph-trust/src/records.rs::malformed_input_is_refused_and_says_where` `qso-graph-trust/src/xml.rs::errors_say_where` |
| `tqsl_getErrorString_v` | An error code, in words | Each error type's `Display`, e.g. `qso_graph_trust::signed_log::LogError` | `qso-graph-trust/src/records.rs::malformed_input_is_refused_and_says_where` `qso-graph-trust-cli/src/cli/tests.rs::a_qso_lotw_would_refuse_is_left_out_and_the_rest_signed` |
| `tqsl_encodeBase64` | Base64-encode data | `qso_graph_trust::signing::tqsl_base64`, `qso_graph_trust::certificate::Certificate::tcert_base64` | `qso-graph-trust/src/signing.rs::base64_is_wrapped_as_tqsllib_wraps_it` `qso-graph-trust/tests/differential.rs::the_signed_log_is_tqsllibs` |
| `tqsl_decodeBase64` | Decode base64 | Not needed: base64 is decoded inside the readers that need it (keys, `.tbk`, `.tq6`); a caller never handles it |  |
| `tqsl_initDate` | A date from text | `qso_graph_trust::qso::Date::from_iso`, `qso_graph_trust::qso::Date::from_adif` | `qso-graph-trust/src/qso.rs::dates_and_times_are_checked` |
| `tqsl_initTime` | A time from text | `qso_graph_trust::qso::Time::from_adif` | `qso-graph-trust/src/qso.rs::dates_and_times_are_checked` |
| `tqsl_compareDates` | Compare two dates | `qso_graph_trust::qso::Date` is ordered (`Ord`) | `qso-graph-trust-cli/src/cli/tests.rs::a_date_range_leaves_out_the_qsos_outside_it` |
| `tqsl_subtractDates` | Days between two dates | `qso_graph_trust::store::Store::expiring_certificates` counts the days a certificate has left, the one use QG Trust has | `qso-graph-trust/src/store/tests/import.rs::expiry_uses_validity_end_utc_dates_and_a_strict_threshold` |
| `tqsl_convertDateToText` | A date as `YYYY-MM-DD` | `qso_graph_trust::qso::Date` displays as `YYYY-MM-DD` | `qso-graph-trust/src/qso.rs::a_qso_is_written_as_lotw_receives_it` |
| `tqsl_isDateValid` | Whether a date is a real one | `qso_graph_trust::qso::Date::from_iso` makes only real dates | `qso-graph-trust/src/qso.rs::dates_and_times_are_checked` |
| `tqsl_isDateNull` | Whether a date is empty | Not applicable: a date that may be missing is an `Option<Date>`; no date is empty |  |
| `tqsl_isTimeValid` | Whether a time is a real one | `qso_graph_trust::qso::Time::from_adif` makes only real times | `qso-graph-trust/src/qso.rs::dates_and_times_are_checked` |
| `tqsl_convertTimeToText` | A time as `HH:MM:SSZ` | `qso_graph_trust::qso::Time` displays as `HH:MM:SSZ` | `qso-graph-trust/src/qso.rs::a_qso_is_written_as_lotw_receives_it` |
| `tqsl_getVersion` | The library's version | `qso_graph_trust::VERSION` | `qso-graph-trust/src/lib.rs::version_is_semantic` |
| `tqsl_getConfigVersion` | The configuration's version | `qso_graph_trust::lotw::CONFIG_VERSION` (internal: the configuration is compiled in) | `qso-graph-trust/src/lotw/mod.rs::the_configuration_is_the_one_checked_in` |
| `tqsl_selectCertificates` | List the certificates held | `qso_graph_trust::store::Store::certificates`; `qg-trust cert list` | `qso-graph-trust/src/store/tests.rs::every_section_round_trips_and_stored_keys_sign_the_same_logs` `qso-graph-trust-cli/src/commands/tests.rs::certificates_list_with_their_dates_and_as_json` |
| `tqsl_selectCACertificates` | List the root and CA certificates | `qso_graph_trust::store::Store::trusted_roots`; `qg-trust root list` | `qso-graph-trust/src/store/tests/roots.rs::the_list_holds_lotws_four_built_in_certificates_and_they_cannot_be_removed` |
| `tqsl_getSelectedCertificate` | One certificate from a list | Not applicable: the list is a `Vec`; indexing it is Rust's own |  |
| `tqsl_isCertificateExpired` | Whether a certificate has expired | `qso_graph_trust::certificate::Certificate::is_valid_at`, `qso_graph_trust::store::Store::expiring_certificates` | `qso-graph-trust/src/certificate.rs::the_lotw_fields_are_read` `qso-graph-trust/src/store/tests/import.rs::expiry_uses_validity_end_utc_dates_and_a_strict_threshold` |
| `tqsl_isCertificateSuperceded` | Whether a newer certificate replaces it | Not needed: QG Trust keeps every certificate and chooses the signer by the QSOs' dates (`qg-trust sign --cert` to choose), so it keeps no superseded mark |  |
| `tqsl_getCertificateKeyOnly` | Whether it is a key waiting for its certificate | `qso_graph_trust::store::Store::pending_requests` | `qso-graph-trust/src/store/tests/requests.rs::pending_metadata_and_custody_survive_request_drop_and_reopen` |
| `tqsl_isCertificateRenewable` | Whether it can be renewed | Not needed: `qg-trust cert renew` renews any certificate whose key the store holds, one past its end too |  |
| `tqsl_getCertificateEncoded` | The certificate, encoded for a signed log | `qso_graph_trust::certificate::Certificate::tcert_base64` | `qso-graph-trust/tests/differential.rs::the_signed_log_is_tqsllibs` |
| `tqsl_getKeyEncoded` | The private key, encoded for a backup | `qso_graph_trust::store::Store::export_part`: the key leaves the store only encrypted by QG Trust; no call returns it | `qso-graph-trust/src/store/part/tests.rs::complete_roundtrip_replaces_existing_content_and_preserves_signatures` |
| `tqsl_importKeyPairEncoded` | A certificate and key from a backup | `qso_graph_trust::store::Store::add_certificate_with_key` (from a `.tbk`), `qso_graph_trust::store::Store::restore_part`; `qg-trust import` | `qso-graph-trust/tests/tbk_import.rs::every_certificate_key_and_location_comes_through` `qso-graph-trust-cli/src/commands/tests.rs::a_tqsl_backup_imports_certificates_keys_locations_and_the_signed_record` `qso-graph-trust/src/store/part/tests.rs::complete_roundtrip_replaces_existing_content_and_preserves_signatures` |
| `tqsl_getCertificateSerial` | The certificate's serial number | `qso_graph_trust::certificate::Certificate::serial` | `qso-graph-trust/src/certificate.rs::serials_are_read_whole_and_never_negative` |
| `tqsl_getCertificateSerialExt` | The serial number, in hexadecimal | `qso_graph_trust::certificate::Certificate::serial_number` (its bytes) | `qso-graph-trust/src/certificate.rs::serials_are_read_whole_and_never_negative` |
| `tqsl_getCertificateSerialLength` | The length of that hexadecimal | `qso_graph_trust::certificate::Certificate::serial_number`, whose length is its own | `qso-graph-trust/src/certificate.rs::serials_are_read_whole_and_never_negative` |
| `tqsl_getCertificateIssuer` | The issuer's name | Not needed: QG Trust checks the issuer itself (`qso_graph_trust::certificate::Certificate::verify`) and names an issuer it cannot trust in its error |  |
| `tqsl_getCertificateIssuerOrganization` | The issuer's organization | Not needed: as `tqsl_getCertificateIssuer` |  |
| `tqsl_getCertificateIssuerOrganizationalUnit` | The issuer's unit | Not needed: as `tqsl_getCertificateIssuer` |  |
| `tqsl_getCertificateCallSign` | The certificate's call | `qso_graph_trust::certificate::Certificate::callsign` | `qso-graph-trust/src/certificate.rs::the_lotw_fields_are_read` |
| `tqsl_getCertificateAROName` | The holder's name | Not needed: QG Trust's certificate details are call, DXCC entity, QSO dates, validity and serial (FEATURE-PARITY.md 1.4) |  |
| `tqsl_getCertificateEmailAddress` | The holder's email address | Not needed: as `tqsl_getCertificateAROName` |  |
| `tqsl_getCertificateQSONotBeforeDate` | The first QSO date it may sign | `qso_graph_trust::certificate::Certificate::qso_dates` | `qso-graph-trust/src/certificate.rs::the_lotw_fields_are_read` |
| `tqsl_getCertificateQSONotAfterDate` | The last QSO date it may sign | `qso_graph_trust::certificate::Certificate::qso_dates` | `qso-graph-trust/src/certificate.rs::the_lotw_fields_are_read` |
| `tqsl_getCertificateNotBeforeDate` | When it comes into force | `qso_graph_trust::certificate::Certificate::validity` | `qso-graph-trust/src/certificate.rs::the_lotw_fields_are_read` `qso-graph-trust/src/store/tests/import.rs::expiry_uses_validity_end_utc_dates_and_a_strict_threshold` |
| `tqsl_getCertificateNotAfterDate` | When it ends | `qso_graph_trust::certificate::Certificate::validity` | `qso-graph-trust/src/certificate.rs::the_lotw_fields_are_read` `qso-graph-trust/src/store/tests/import.rs::expiry_uses_validity_end_utc_dates_and_a_strict_threshold` |
| `tqsl_getCertificateDXCCEntity` | Its DXCC entity | `qso_graph_trust::certificate::Certificate::dxcc` | `qso-graph-trust/src/certificate.rs::the_lotw_fields_are_read` |
| `tqsl_getCertificateRequestAddress1` | Address line 1 from its request | Not needed: QG Trust keeps no personal details; a renewal asks for them again (`qg-trust cert renew --name …`) |  |
| `tqsl_getCertificateRequestAddress2` | Address line 2 from its request | Not needed: as `tqsl_getCertificateRequestAddress1` |  |
| `tqsl_getCertificateRequestCity` | The city from its request | Not needed: as `tqsl_getCertificateRequestAddress1` |  |
| `tqsl_getCertificateRequestState` | The state from its request | Not needed: as `tqsl_getCertificateRequestAddress1` |  |
| `tqsl_getCertificateRequestPostalCode` | The postal code from its request | Not needed: as `tqsl_getCertificateRequestAddress1` |  |
| `tqsl_getCertificateRequestCountry` | The country from its request | Not needed: as `tqsl_getCertificateRequestAddress1` |  |
| `tqsl_getCertificatePrivateKeyType` | Whether its key is there, and protected | `qso_graph_trust::store::StoredCertificate::key_name` (a key is held), `qso_graph_trust::signing::KeyEntry::is_encrypted` | `qso-graph-trust/tests/tbk_import.rs::a_protected_key_is_checked_as_far_as_it_can_be_without_its_password` `qso-graph-trust-cli/src/commands/tests.rs::certificates_list_with_their_dates_and_as_json` |
| `tqsl_freeCertificate` | Free a certificate | Not applicable: Rust frees a value when it is dropped; there is nothing to free by hand |  |
| `tqsl_freeCertificateList` | Free a list of certificates | Not applicable: Rust frees a value when it is dropped; there is nothing to free by hand |  |
| `tqsl_getCertificateStatus` | A certificate's status as LoTW last gave it | Not needed: asking LoTW whether a certificate is still good calls ARRL and waits on a decision (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_setCertificateStatus` | Record that status | Not needed: as `tqsl_getCertificateStatus` |  |
| `tqsl_importTQSLFile` | Load ARRL's answer (`.tq6`) | `qso_graph_trust::store::Store::import_tq6`; `qg-trust import` | `qso-graph-trust/src/store/tests/import.rs::tq6_attaches_a_matching_pending_request_and_otherwise_loads_keyless` |
| `tqsl_getSerialFromTQSLFile` | The serial in a `.tq6`, before loading it | Not needed: `qso_graph_trust::store::Store::import_tq6` returns what it loaded, so nothing is read twice |  |
| `tqsl_getNumProviders` | How many certificate providers there are | Not needed: LoTW is the one provider; a request names it (`qso_graph_trust::request::CertificateRequest::provider`) |  |
| `tqsl_getProvider` | One certificate provider | Not needed: as `tqsl_getNumProviders` |  |
| `tqsl_createCertRequest` | Make a certificate request (`.tq5`) | `qso_graph_trust::request::CertificateRequest::generate`, `qso_graph_trust::store::Store::store_request`; `qg-trust cert request` | `qso-graph-trust/src/request/tests.rs::same_test_key_reproduces_tqsllib_requests_except_identification` `qso-graph-trust/src/store/tests/requests.rs::pending_metadata_and_custody_survive_request_drop_and_reopen` |
| `tqsl_exportPKCS12File` | Save a certificate and key as a `.p12` | Not needed: QG Trust saves no `.p12`; its export moves keys (FEATURE-PARITY.md, Won't add) |  |
| `tqsl_exportPKCS12FileWeakCrypto` | The same, in the older format Apple's Keychain read | Not needed: as `tqsl_exportPKCS12File` |  |
| `tqsl_exportPKCS12Base64` | The same, as base64 | Not needed: as `tqsl_exportPKCS12File` |  |
| `tqsl_importPKCS12File` | Load a certificate and key from a `.p12` | `qso_graph_trust::store::Store::import_pkcs12`; `qg-trust import` | `qso-graph-trust/src/store/tests/import.rs::default_pkcs12_imports_for_both_corpus_key_password_cases_and_signs` |
| `tqsl_importPKCS12Base64` | The same, from base64 | `qso_graph_trust::store::Store::import_pkcs12`, which takes the bytes, wherever they came from | `qso-graph-trust/src/store/tests/import.rs::default_pkcs12_imports_for_both_corpus_key_password_cases_and_signs` |
| `tqsl_getDeletedCallsignCertificates` | List deleted certificates that can be restored | Not needed: a deleted certificate is gone; restoring one is later (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_freeDeletedCertificateList` | Free that list | Not applicable: Rust frees a value when it is dropped; there is nothing to free by hand |  |
| `tqsl_restoreCallsignCertificate` | Restore a deleted certificate | Not needed: as `tqsl_getDeletedCallsignCertificates` |  |
| `tqsl_deleteCertificate` | Delete a certificate and its key | `qso_graph_trust::store::Store::delete_certificate`; `qg-trust cert delete` | `qso-graph-trust/src/store/tests.rs::public_certificates_and_location_mutations_preserve_exact_names` `qso-graph-trust-cli/src/commands/tests.rs::a_certificate_is_deleted_only_with_force` |
| `tqsl_beginSigning` | Unlock a key to sign | `qso_graph_trust::store::Store::with_key`, `qso_graph_trust::signing::KeyEntry::unlock` | `qso-graph-trust/src/store/tests.rs::every_section_round_trips_and_stored_keys_sign_the_same_logs` `qso-graph-trust/tests/differential.rs::a_protected_key_needs_its_password` |
| `tqsl_checkSigningStatus` | Whether a key is unlocked | Not applicable: an unlocked key (`qso_graph_trust::signing::TqslKey`) exists only inside `qso_graph_trust::store::Store::with_key`, so there is no state to ask about |  |
| `tqsl_getMaxSignatureSize` | The largest signature it can make | Not applicable: a signature is returned as a `Vec<u8>` of its own size |  |
| `tqsl_signDataBlock` | Sign data | `qso_graph_trust::signing::TqslKey::sign` | `qso-graph-trust/tests/differential.rs::a_1024_bit_key_signs_as_tqsllib` |
| `tqsl_verifyDataBlock` | Check a signature | Not needed: LoTW checks the signatures it receives; QG Trust's are proved byte for byte against tqsllib's in its tests |  |
| `tqsl_signQSORecord` | Sign one QSO | `qso_graph_trust::signed_log::sign_log`, which signs each QSO's `qso_graph_trust::qso::Qso::sign_data` | `qso-graph-trust/tests/differential.rs::the_signed_log_is_tqsllibs` `qso-graph-trust/src/qso.rs::a_qso_is_written_as_lotw_receives_it` |
| `tqsl_endSigning` | Lock the key again | Not applicable: the key is wiped and dropped when `qso_graph_trust::store::Store::with_key`'s closure returns |  |
| `tqsl_initStationLocationCapture` | Start a new station location | `qso_graph_trust::station::StationLocation::new` | `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_endStationLocationCapture` | Finish with a station location | Not applicable: Rust frees a value when it is dropped; there is nothing to free by hand |  |
| `tqsl_updateStationLocationCapture` | Refresh the wizard's pages | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_getNumStationLocationCapturePages` | How many pages the wizard has | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_getStationLocationCapturePage` | The current page | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_setStationLocationCapturePage` | Go to a page | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_setStationLocationCertFlags` | Which certificates a page offers | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_nextStationLocationCapture` | Go to the next page | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_getNextStationLocationCapturePage` | The next page's number | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_prevStationLocationCapture` | Go to the previous page | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_getPrevStationLocationCapturePage` | The previous page's number | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_getCurrentStationLocationCapturePage` | The current page's number | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_hasNextStationLocationCapture` | Whether there is a next page | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_hasPrevStationLocationCapture` | Whether there is a previous page | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_saveStationLocationCapture` | Save the station location | `qso_graph_trust::store::Store::add_location`, `qso_graph_trust::store::Store::replace_location`; `qg-trust location add`, `qg-trust location edit` | `qso-graph-trust/src/store/tests.rs::public_certificates_and_location_mutations_preserve_exact_names` `qso-graph-trust-cli/src/commands/tests.rs::station_locations_are_added_shown_changed_and_deleted` |
| `tqsl_getStationLocationCaptureName` | The location's name | `qso_graph_trust::store::StoredLocation::name` | `qso-graph-trust/src/store/tests.rs::public_certificates_and_location_mutations_preserve_exact_names` |
| `tqsl_setStationLocationCaptureName` | Name the location | `qso_graph_trust::store::Store::add_location` (the name is an argument) | `qso-graph-trust/src/store/tests.rs::public_certificates_and_location_mutations_preserve_exact_names` |
| `tqsl_getNumStationLocations` | How many locations are saved | `qso_graph_trust::store::Store::locations` | `qso-graph-trust/src/store/tests.rs::every_section_round_trips_and_stored_keys_sign_the_same_logs` |
| `tqsl_getStationLocationName` | A saved location's name | `qso_graph_trust::store::StoredLocation::name` | `qso-graph-trust/src/store/tests.rs::every_section_round_trips_and_stored_keys_sign_the_same_logs` |
| `tqsl_getStationLocationCallSign` | A saved location's call | `qso_graph_trust::station::StationLocation::call` | `qso-graph-trust/tests/tbk_import.rs::every_certificate_key_and_location_comes_through` |
| `tqsl_getStationLocationField` | One field of a saved location | `qso_graph_trust::station::StationLocation::get` | `qso-graph-trust/src/station.rs::fields_are_listed_in_the_configurations_order` |
| `tqsl_getStationLocation` | Open a saved location | `qso_graph_trust::store::Store::locations`; `qg-trust location show` | `qso-graph-trust/src/store/tests.rs::every_section_round_trips_and_stored_keys_sign_the_same_logs` `qso-graph-trust-cli/src/commands/tests.rs::station_locations_are_added_shown_changed_and_deleted` |
| `tqsl_getStationLocationErrors` | What was wrong with a saved location | `qso_graph_trust::station::StationError`, returned when a location is read | `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_getStationDataEnc` | The saved locations, as a file's bytes | `qso_graph_trust::store::Store::export_part` carries them | `qso-graph-trust/src/store/part/tests.rs::complete_roundtrip_replaces_existing_content_and_preserves_signatures` |
| `tqsl_freeStationDataEnc` | Free those bytes | Not applicable: Rust frees a value when it is dropped; there is nothing to free by hand |  |
| `tqsl_mergeStationLocations` | Merge locations from a backup | `qso_graph_trust::store::Store::add_location` for each one not there; `qg-trust import` keeps those already there | `qso-graph-trust-cli/src/commands/tests.rs::a_tqsl_backup_imports_certificates_keys_locations_and_the_signed_record` |
| `tqsl_deleteStationLocation` | Delete a location | `qso_graph_trust::store::Store::delete_location`; `qg-trust location delete` | `qso-graph-trust/src/store/tests.rs::public_certificates_and_location_mutations_preserve_exact_names` `qso-graph-trust-cli/src/commands/tests.rs::station_locations_are_added_shown_changed_and_deleted` |
| `tqsl_restoreStationLocation` | Restore a deleted location | Not needed: a deleted location is gone; restoring one is later (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_getDeletedStationLocations` | List deleted locations | Not needed: as `tqsl_restoreStationLocation` |  |
| `tqsl_freeDeletedLocationList` | Free that list | Not applicable: Rust frees a value when it is dropped; there is nothing to free by hand |  |
| `tqsl_getNumLocationField` | How many fields a page has | `qso_graph_trust::station::fields_for`, every field an entity's location takes; `qg-trust location fields` | `qso-graph-trust/src/lotw/mod.rs::a_us_location_lists_its_fields_in_page_order` |
| `tqsl_getLocationFieldDataLabelSize` | The length of a field's label | Not applicable: sizes a C buffer; Rust strings carry their length |  |
| `tqsl_getLocationFieldDataLabel` | A field's label | Not needed: QG Trust names a field as LoTW does (`US_STATE`); the words a screen shows for it are QSO Graph Desktop's |  |
| `tqsl_getLocationFieldDataGABBISize` | The length of a field's name | Not applicable: sizes a C buffer; Rust strings carry their length |  |
| `tqsl_getLocationFieldDataGABBI` | A field's name as LoTW receives it | `qso_graph_trust::station::fields_for`, which gives those names | `qso-graph-trust/src/lotw/mod.rs::a_us_location_lists_its_fields_in_page_order` `qso-graph-trust/src/station.rs::fields_are_listed_in_the_configurations_order` |
| `tqsl_getLocationFieldInputType` | How a field is entered: list, text | `qso_graph_trust::lotw::is_list` (internal) | `qso-graph-trust/src/station.rs::list_values_are_matched_and_written_as_the_list_writes_them` |
| `tqsl_getLocationFieldDataType` | Whether a field is text or a number | `qso_graph_trust::lotw::FieldKind` (internal) | `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_getLocationFieldFlags` | A field's flags | `qso_graph_trust::lotw::LocField` (internal: its kind, length, range and the field it depends on) | `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_getLocationFieldDataLength` | A field's longest value | `qso_graph_trust::lotw::LocField::len` (internal) | `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_getLocationFieldCharData` | A field's text | `qso_graph_trust::station::StationLocation::get` | `qso-graph-trust/src/station.rs::fields_are_listed_in_the_configurations_order` |
| `tqsl_getLocationFieldIntData` | A field's number | `qso_graph_trust::station::StationLocation::get`, checked as a number when the location is made | `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_getLocationFieldIndex` | Which list item a field holds | Not applicable: a list field holds its value, matched against the list, not an index into it |  |
| `tqsl_getNumLocationFieldListItems` | How many items a field's list has | `qso_graph_trust::lotw::loc_values` (internal) | `qso-graph-trust/src/lotw/mod.rs::a_us_location_lists_its_fields_in_page_order` `qso-graph-trust/src/station.rs::list_values_are_matched_and_written_as_the_list_writes_them` |
| `tqsl_getLocationFieldListItem` | One item of a field's list | `qso_graph_trust::lotw::loc_values` (internal) | `qso-graph-trust/src/lotw/mod.rs::a_us_location_lists_its_fields_in_page_order` `qso-graph-trust/src/station.rs::list_values_are_matched_and_written_as_the_list_writes_them` |
| `tqsl_setLocationFieldCharData` | Set a field's text | `qso_graph_trust::station::StationLocation::new` (with its fields); `qg-trust location edit` | `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` `qso-graph-trust-cli/src/commands/tests.rs::station_locations_are_added_shown_changed_and_deleted` |
| `tqsl_setLocationFieldIntData` | Set a field's number | `qso_graph_trust::station::StationLocation::new` | `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_setLocationFieldIndex` | Choose a field's list item | Not applicable: as `tqsl_getLocationFieldIndex` |  |
| `tqsl_getLocationFieldChanged` | Whether a field's list changed on refresh | Not applicable: one page of TQSL's station-location wizard; QG Trust has no pages, and builds and checks a location whole with `qso_graph_trust::station::StationLocation::new` |  |
| `tqsl_getLocationCallSign` | A location's call | `qso_graph_trust::station::StationLocation::call` | `qso-graph-trust/tests/tbk_import.rs::every_certificate_key_and_location_comes_through` |
| `tqsl_setLocationCallSign` | Set a location's call | `qso_graph_trust::station::StationLocation::new`; `qg-trust location edit --call` | `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` `qso-graph-trust-cli/src/commands/tests.rs::station_locations_are_added_shown_changed_and_deleted` |
| `tqsl_getLocationField` | A location's field | `qso_graph_trust::station::StationLocation::get` | `qso-graph-trust/src/station.rs::fields_are_listed_in_the_configurations_order` |
| `tqsl_getLocationFieldLabel` | A location's field, as its list item's label | `qso_graph_trust::lotw::loc_value_label` (internal: ARRL's labels, also accepted as values) | `qso-graph-trust/src/station.rs::list_values_are_matched_and_written_as_the_list_writes_them` |
| `tqsl_setLocationField` | Set a location's field | `qso_graph_trust::station::StationLocation::new`, `qso_graph_trust::store::Store::replace_location`; `qg-trust location edit` | `qso-graph-trust/src/store/tests.rs::public_certificates_and_location_mutations_preserve_exact_names` `qso-graph-trust-cli/src/commands/tests.rs::station_locations_are_added_shown_changed_and_deleted` |
| `tqsl_getLocationDXCCEntity` | A location's DXCC entity | `qso_graph_trust::station::StationLocation::dxcc` | `qso-graph-trust/tests/tbk_import.rs::every_certificate_key_and_location_comes_through` |
| `tqsl_getLocationQSODetails` | A location's details as a QSO's record keeps them | `qso_graph_trust::store::duplicate_key` and the station each `qso_graph_trust::store::SignedQso` records, as TQSL writes them | `qso-graph-trust/src/store/tests/signed.rs::standard_backup_keys_and_station_descriptions_match_every_qso` |
| `tqsl_getLocationStationDetails` | A location's details as the signed record keeps them | `qso_graph_trust::store::SignedQso::station`, as TQSL writes it | `qso-graph-trust/src/store/tests/signed.rs::standard_backup_keys_and_station_descriptions_match_every_qso` |
| `tqsl_saveCallsignLocationInfo` | Save details LoTW gave for a call | Not needed: those details come from a call to ARRL's server; QG Trust's library makes no connection but the upload |  |
| `tqsl_getCallsignLocationInfo` | Read those details back | Not needed: as `tqsl_saveCallsignLocationInfo` |  |
| `tqsl_validateVUCCGrid` | Whether a grid fits the entity and state | Not needed: TQSL warns and does not refuse; checking a grid against the entity or state is later (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_getNumDXCCEntity` | How many DXCC entities there are | `qso_graph_trust::lotw::DXCC` (internal: ARRL's list) | `qso-graph-trust/src/station.rs::an_entitys_name_is_arrls_and_a_number_it_does_not_list_has_none` |
| `tqsl_getDXCCEntity` | One DXCC entity | `qso_graph_trust::lotw::dxcc` (internal) | `qso-graph-trust/src/station.rs::an_entitys_name_is_arrls_and_a_number_it_does_not_list_has_none` `qso-graph-trust/src/lotw/mod.rs::a_us_location_lists_its_fields_in_page_order` |
| `tqsl_getDXCCEntityName` | An entity's name | `qso_graph_trust::station::dxcc_name`; `qg-trust location fields` | `qso-graph-trust/src/station.rs::an_entitys_name_is_arrls_and_a_number_it_does_not_list_has_none` `qso-graph-trust-cli/src/commands/tests.rs::station_locations_are_added_shown_changed_and_deleted` |
| `tqsl_getDXCCZoneMap` | An entity's CQ and ITU zones | `qso_graph_trust::lotw::zone_pairs` (internal), which refuses a zone that does not fit | `qso-graph-trust/src/lotw/mod.rs::a_us_location_lists_its_fields_in_page_order` `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_getDXCCStartDate` | When an entity began | Not needed: QG Trust does not compare a QSO's date with its entity's; the dates it checks are the certificate's |  |
| `tqsl_getDXCCEndDate` | When an entity ended | Not needed: as `tqsl_getDXCCStartDate` |  |
| `tqsl_getDXCCDeleted` | Whether an entity is deleted | Not needed: the tables carry the mark (`qso_graph_trust::lotw::DxccEntity::deleted`); nothing QG Trust does depends on it |  |
| `tqsl_getNumBand` | How many bands there are | `qso_graph_trust::lotw::BANDS` (internal) | `qso-graph-trust/src/lotw/mod.rs::frequencies_fall_in_their_bands` |
| `tqsl_getBand` | One band | `qso_graph_trust::lotw::band` (internal) | `qso-graph-trust/src/lotw/mod.rs::frequencies_fall_in_their_bands` |
| `tqsl_getNumMode` | How many modes there are | `qso_graph_trust::lotw::MODES` (internal) | `qso-graph-trust/src/lotw/mod.rs::modes_map_from_adif_as_the_configuration_says` |
| `tqsl_getMode` | One mode | `qso_graph_trust::lotw::MODES` (internal) | `qso-graph-trust/src/lotw/mod.rs::modes_map_from_adif_as_the_configuration_says` |
| `tqsl_getNumADIFMode` | How many ADIF modes there are | `qso_graph_trust::lotw::ADIF_MODES` (internal) | `qso-graph-trust/src/lotw/mod.rs::modes_map_from_adif_as_the_configuration_says` |
| `tqsl_getADIFModeEntry` | One ADIF mode | `qso_graph_trust::lotw::ADIF_MODES` (internal) | `qso-graph-trust/src/lotw/mod.rs::modes_map_from_adif_as_the_configuration_says` |
| `tqsl_getNumPropagationMode` | How many propagation modes there are | `qso_graph_trust::lotw::is_prop_mode` (internal) | `qso-graph-trust/src/qso.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_getPropagationMode` | One propagation mode | `qso_graph_trust::lotw::is_prop_mode` (internal) | `qso-graph-trust/src/qso.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_getNumSatellite` | How many satellites there are | `qso_graph_trust::lotw::is_satellite` (internal) | `qso-graph-trust/src/qso.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_getSatellite` | One satellite | `qso_graph_trust::lotw::is_satellite` (internal) | `qso-graph-trust/src/qso.rs::what_lotw_would_refuse_is_refused` |
| `tqsl_clearCabrilloMap` | Forget the custom Cabrillo contests | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_setCabrilloMapEntry` | Add a custom Cabrillo contest | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_getCabrilloMapEntry` | Look up a Cabrillo contest | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_clearADIFModes` | Forget the custom mode mappings | `qso_graph_trust::options::SigningOptions::adif_modes`, given for each log, so there is nothing global to clear | `qso-graph-trust/tests/signing_options.rs::settings_sign_and_record_exactly_as_tqsllib` |
| `tqsl_setADIFMode` | Add a custom mode mapping | `qso_graph_trust::options::SigningOptions::adif_modes`; `qg-trust sign --mode` | `qso-graph-trust/tests/signing_options.rs::settings_sign_and_record_exactly_as_tqsllib` |
| `tqsl_getADIFMode` | The LoTW mode for an ADIF mode | `qso_graph_trust::lotw::lotw_mode` (internal), `qso_graph_trust::qso::Qso::mode` | `qso-graph-trust/src/lotw/mod.rs::modes_map_from_adif_as_the_configuration_says` |
| `tqsl_getADIFSubMode` | The ADIF mode and submode for a LoTW mode | Not needed: QG Trust maps ADIF to LoTW's modes, the one direction signing needs |  |
| `tqsl_getGABBItCERT` | The signed log's certificate record | `qso_graph_trust::signed_log::sign_log`, with `qso_graph_trust::certificate::Certificate::tcert_base64` | `qso-graph-trust/tests/differential.rs::the_signed_log_is_tqsllibs` |
| `tqsl_getGABBItSTATION` | The signed log's station record | `qso_graph_trust::signed_log::sign_log` | `qso-graph-trust/tests/differential.rs::the_signed_log_is_tqsllibs` `qso-graph-trust/tests/standard_set.rs::every_location_signs_as_tqsllib` |
| `tqsl_getGABBItCONTACT` | The signed log's QSO record | `qso_graph_trust::signed_log::sign_log` | `qso-graph-trust/tests/differential.rs::the_signed_log_is_tqsllibs` |
| `tqsl_getGABBItCONTACTData` | The same, with the signed data | `qso_graph_trust::signed_log::sign_log`, `qso_graph_trust::qso::Qso::sign_data` | `qso-graph-trust/tests/differential.rs::the_signed_log_is_tqsllibs` `qso-graph-trust/src/qso.rs::a_qso_is_written_as_lotw_receives_it` |
| `tqsl_verifyGridFormat` | Check and normalize a grid square | `qso_graph_trust::station::StationLocation::new` | `qso-graph-trust/src/station.rs::what_lotw_would_refuse_is_refused` |
| `tqslTrace` | Write a line to the diagnostic log | `qg-trust -t`; the library writes no log | `qso-graph-trust-cli/src/cli/tests.rs::t_writes_a_diagnostic_log_with_no_password_or_key_in_it` |
| `tqsl_closeDiagFile` | Close the diagnostic log | Not applicable: `qg-trust -t`'s log is closed when the program ends |  |
| `tqsl_diagFileOpen` | Whether the diagnostic log is open | Not applicable: `qg-trust -t` is given or not, for the whole run |  |
| `tqsl_openDiagFile` | Open the diagnostic log | `qg-trust -t` | `qso-graph-trust-cli/src/cli/tests.rs::t_writes_a_diagnostic_log_with_no_password_or_key_in_it` `qso-graph-trust-cli/src/cli/trace.rs::the_log_is_its_owners_alone_even_over_a_file_there_before` |
| `tqsl_removeUploadDatabase` | Delete the record of QSOs signed | `qso_graph_trust::store::Store::wipe_signed_qsos`; CLI `-w` and `signed clear` | `qso-graph-trust/src/store/tests/signed.rs::large_record_is_compact_bounded_and_roundtrips` |
| `utf8_to_wchar` | UTF-8 to Windows' wide characters | Not applicable: Rust strings are UTF-8, and its standard library converts at the operating system's boundary |  |
| `wchar_to_utf8` | Windows' wide characters to UTF-8 | Not applicable: as `utf8_to_wchar` |  |
| `free_wchar` | Free a wide-character string | Not applicable: Rust frees a value when it is dropped; there is nothing to free by hand |  |
| `tqsl_cabrilloGetError` | A Cabrillo error, in words | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_beginCabrillo` | Open a Cabrillo file | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_getCabrilloContest` | Its contest | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_getCabrilloFreqType` | Whether the contest is HF or VHF | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_getCabrilloLine` | The line being read | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_getCabrilloRecordText` | The record being read | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_getCabrilloField` | The record's next field | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_endCabrillo` | Close the Cabrillo file | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_adifGetError` | An ADIF error, in words | `qso_graph_trust::records::RecordError`'s `Display`, which says where | `qso-graph-trust/src/records.rs::malformed_input_is_refused_and_says_where` |
| `tqsl_beginADIF` | Open an ADI or ADX file | `qso_graph_trust::records::parse` | `qso-graph-trust/src/adx.rs::equivalent_fields_and_detection` |
| `tqsl_getADIFField` | The next field | `qso_graph_trust::records::Record::get`, `qso_graph_trust::records::Record::text` | `qso-graph-trust/src/records.rs::fields_records_and_types_are_read_exactly` |
| `tqsl_getADIFLine` | The line being read | `qso_graph_trust::records::RecordError` names where the input is wrong | `qso-graph-trust/src/records.rs::malformed_input_is_refused_and_says_where` |
| `tqsl_endADIF` | Close the ADIF file | Not applicable: Rust frees a value when it is dropped; there is nothing to free by hand |  |
| `tqsl_adifMakeField` | Write one ADIF field | Not needed: QG Trust reads ADIF and writes none; making ADIF is a logger's job (FEATURE-PARITY.md, Nice to have) |  |

## `cabrillo.h`

| tqsllib | What it does | QG Trust | Test |
|---|---|---|---|
| `tqsl_beginConverter` | Start signing QSOs a caller supplies | `qso_graph_trust::signed_log::sign_log`, given the QSOs (`qso_graph_trust::qso::Qso`) | `qso-graph-trust/tests/differential.rs::the_signed_log_is_tqsllibs` |
| `tqsl_beginADIFConverter` | Start signing an ADIF file | `qso_graph_trust::records::parse`, `qso_graph_trust::qso::Qso::from_adif`, `qso_graph_trust::store::Store::prepare_signing`; `qg-trust sign` | `qso-graph-trust/src/store/tests/signed.rs::choices_write_only_the_selected_qsos_and_record_only_after_success` `qso-graph-trust-cli/src/commands/tests.rs::every_location_signs_from_the_store_as_tqsllib_signs_it` |
| `tqsl_beginCabrilloConverter` | Start signing a Cabrillo file | Not needed: Cabrillo is not read; most loggers export ADIF (FEATURE-PARITY.md, Nice to have) |  |
| `tqsl_endConverter` | Finish signing | Not applicable: Rust frees a value when it is dropped; there is nothing to free by hand |  |
| `tqsl_setConverterAllowBadCall` | Sign calls that are not amateur calls | `qso_graph_trust::options::SigningOptions::allow_bad_calls`; `qg-trust sign --allow-bad-calls` | `qso-graph-trust/tests/signing_options.rs::calls_refuse_controls_and_xml_forbidden_characters_with_any_options` |
| `tqsl_setConverterQTHDetails` | What the log's own location details do | `qso_graph_trust::options::SigningOptions::qth`; `qg-trust -f`, `qg-trust sign --qth` | `qso-graph-trust/tests/signing_options.rs::settings_sign_and_record_exactly_as_tqsllib` `qso-graph-trust-cli/src/commands/tests.rs::a_logger_chooses_what_the_logs_own_location_details_do_with_f` |
| `tqsl_setConverterAllowDuplicates` | Sign QSOs signed before | `qso_graph_trust::store::DuplicateChoice::SignAgain`; `qg-trust sign` (the default; `-d` leaves them out) | `qso-graph-trust/src/store/tests/signed.rs::choices_write_only_the_selected_qsos_and_record_only_after_success` |
| `tqsl_setConverterIgnoreSeconds` | Leave seconds out | `qso_graph_trust::options::SigningOptions::ignore_seconds` | `qso-graph-trust/tests/signing_options.rs::settings_sign_and_record_exactly_as_tqsllib` |

## `adif.h`

| tqsllib | What it does | QG Trust | Test |
|---|---|---|---|
| `tqsl_setConverterIgnoreCallsigns` | Do not check the log's own calls | `qso_graph_trust::options::SigningOptions::ignore_log_callsigns` | `qso-graph-trust/tests/signing_options.rs::settings_sign_and_record_exactly_as_tqsllib` `qso-graph-trust/tests/signing_options.rs::preferences_are_explicit_and_do_not_change_other_conversions` |
| `tqsl_setConverterAppName` | Name the program in the signed log | Not needed: the signed log names QG Trust and its version itself, the one line that differs from tqsllib's |  |
| `tqsl_setConverterDupesOnly` | Record QSOs as signed without signing them | `qso_graph_trust::store::Store::add_signed_qsos` | `qso-graph-trust/src/store/tests/signed.rs::large_record_is_compact_bounded_and_roundtrips` |
| `tqsl_converterRollBack` | Undo what signing recorded | `qso_graph_trust::store::SignedLog::write_to` records only once the log is written; CLI `-z` writes without recording, so there is nothing to undo | `qso-graph-trust/src/store/tests/signed.rs::choices_write_only_the_selected_qsos_and_record_only_after_success` |
| `tqsl_converterCommit` | Keep what signing recorded | `qso_graph_trust::store::SignedLog::write_to` | `qso-graph-trust/src/store/tests/signed.rs::choices_write_only_the_selected_qsos_and_record_only_after_success` |
| `tqsl_getDuplicateRecords` | Read the record of QSOs signed | `qso_graph_trust::store::Store::signed_qsos` | `qso-graph-trust/src/store/tests/signed.rs::large_record_is_compact_bounded_and_roundtrips` `qso-graph-trust/src/store/part/tests.rs::complete_roundtrip_replaces_existing_content_and_preserves_signatures` |

## `tqslconvert.h`

| tqsllib | What it does | QG Trust | Test |
|---|---|---|---|
| `tqsl_getDuplicateRecordsV2` | The same, with each station | `qso_graph_trust::store::Store::signed_qsos` (each with its station) | `qso-graph-trust/src/store/tests/signed.rs::standard_backup_keys_and_station_descriptions_match_every_qso` |
| `tqsl_putDuplicateRecord` | Write to that record | `qso_graph_trust::store::Store::add_signed_qsos`, `qso_graph_trust::store::Store::import_signed_qsos` (from a `.tbk`) | `qso-graph-trust/src/store/tests/signed.rs::large_record_is_compact_bounded_and_roundtrips` `qso-graph-trust/src/store/tests/signed.rs::standard_backup_keys_and_station_descriptions_match_every_qso` |
| `tqsl_setADIFConverterDateFilter` | Sign only QSOs between two dates | `qg-trust sign -b … -e …` (`--from`, `--to`) | `qso-graph-trust-cli/src/cli/tests.rs::a_date_range_leaves_out_the_qsos_outside_it` |
| `tqsl_getConverterGABBI` | The next signed record | `qso_graph_trust::store::SigningSelection::sign`, `qso_graph_trust::signed_log::sign_log_with_options` | `qso-graph-trust/src/store/tests/signed.rs::choices_write_only_the_selected_qsos_and_record_only_after_success` `qso-graph-trust/tests/standard_set.rs::every_location_signs_as_tqsllib` `qso-graph-trust/tests/signing_options.rs::settings_sign_and_record_exactly_as_tqsllib` |
| `tqsl_getConverterCert` | The certificate the last QSO was signed with | `qso_graph_trust::signed_log::sign_log` signs a log with the one certificate it is given | `qso-graph-trust/tests/differential.rs::a_log_is_not_signed_with_another_certificates_key` |
| `tqsl_getConverterLine` | The input line last read | `qso_graph_trust::signed_log::LogError` names the QSO at fault | `qso-graph-trust-cli/src/cli/tests.rs::a_qso_lotw_would_refuse_is_left_out_and_the_rest_signed` |
| `tqsl_getConverterRecordText` | The input record last read | Not needed: QG Trust names the QSO and the field at fault rather than echoing the record |  |
<!-- tqsllib-map:end -->
