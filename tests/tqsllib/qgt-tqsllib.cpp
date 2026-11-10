// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
//
// qgt-tqsllib: drives tqsllib 2.8.7 through its public API, to make the reference files QGT's
// differential tests compare against (qso-graph-desktop#171). Test tooling only: built and run
// inside the harness container (Containerfile), never part of QGT's crates, never shipped. It does
// what TrustedQSL's own extra programs cannot: make a request whose key has a password, import a
// .p12 with its key, export one, and sign with a password-protected key.
//
//   qgt-tqsllib request CALL DXCC EMAIL OUT.tq5 [KEYPASS]
//   qgt-tqsllib import-p12 FILE P12PASS [KEYPASS]
//   qgt-tqsllib export-p12 CALL FILE P12PASS [KEYPASS] [weak]
//   qgt-tqsllib location NAME CALL DXCC [FIELD=VALUE ...]
//   qgt-tqsllib sign LOCATION IN.adi OUT.tq7 [KEYPASS]
//   qgt-tqsllib sign-cabrillo LOCATION IN.log OUT.tq7
//   qgt-tqsllib read-cabrillo IN.log OUT.records
//
// tqsllib reads and writes the folder TQSLDIR names. Every error ends the run with tqsllib's own
// message and a nonzero exit, so a reference file is never made from a step that failed.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>

#include "tqsllib.h"
#include "tqslconvert.h"
#include "cabrillo.h"
#include "tqslerrno.h"

namespace {

[[noreturn]] void fail(const std::string& what) {
	std::fprintf(stderr, "qgt-tqsllib: %s: %s\n", what.c_str(), tqsl_getErrorString());
	std::exit(1);
}

[[noreturn]] void usage() {
	std::fprintf(stderr,
		"usage: qgt-tqsllib request CALL DXCC EMAIL OUT.tq5 [KEYPASS]\n"
		"       qgt-tqsllib import-p12 FILE P12PASS [KEYPASS]\n"
		"       qgt-tqsllib export-p12 CALL FILE P12PASS [KEYPASS] [weak]\n"
		"       qgt-tqsllib location NAME CALL DXCC [FIELD=VALUE ...]\n"
		"       qgt-tqsllib sign LOCATION IN.adi OUT.tq7 [KEYPASS]\n");
	std::exit(2);
}

// Print what tqsllib reports while importing, so the run's log says what was stored.
int report(int, const char* msg, void*) {
	std::printf("%s\n", msg);
	return 0;
}

// The one certificate for CALL, or a failure: two would make the reference ambiguous.
tQSL_Cert certificate_for(const char* call) {
	tQSL_Cert* certs = nullptr;
	int n = 0;
	if (tqsl_selectCertificates(&certs, &n, call, 0, nullptr, nullptr, 1))
		fail(std::string("selecting the certificate for ") + call);
	if (n != 1) {
		std::fprintf(stderr, "qgt-tqsllib: %d certificates for %s, not one\n", n, call);
		std::exit(1);
	}
	return certs[0];
}

// gen_crq's request (TrustedQSL's src/gen_crq.cpp), with the same test name and address, and the
// key protected by KEYPASS when one is given. tqsllib generates the key (1024-bit in 2.8.7) and
// writes it to keys/<call> in its own format.
int request(int argc, char** argv) {
	if (argc < 6 || argc > 7) usage();
	TQSL_CERT_REQ crq;
	std::memset(&crq, 0, sizeof crq);
	std::snprintf(crq.callSign, sizeof crq.callSign, "%s", argv[2]);
	crq.dxccEntity = std::atoi(argv[3]);
	std::snprintf(crq.emailAddress, sizeof crq.emailAddress, "%s", argv[4]);
	std::snprintf(crq.name, sizeof crq.name, "%s", "QGT Test Operator");
	std::snprintf(crq.address1, sizeof crq.address1, "%s", "1 No Place");
	std::snprintf(crq.city, sizeof crq.city, "%s", "City");
	std::snprintf(crq.state, sizeof crq.state, "%s", "ST");
	std::snprintf(crq.country, sizeof crq.country, "%s", "USA");
	if (tqsl_initDate(&crq.qsoNotBefore, "2020-01-01")) fail("setting the first QSO date");
	// In the request itself, as TQSL's app passes it: TQSL_CERT_REQ.password is an array, so
	// tqsl_createCertRequest never asks the callback (src/openssl_cert.cpp, req->password == NULL).
	if (argc == 7) std::snprintf(crq.password, sizeof crq.password, "%s", argv[6]);
	if (tqsl_createCertRequest(argv[5], &crq, nullptr, nullptr))
		fail(std::string("making the request ") + argv[5]);
	std::printf("made request %s for %s\n", argv[5], argv[2]);
	return 0;
}

int import_p12(int argc, char** argv) {
	if (argc < 4 || argc > 5) usage();
	const char* keypass = argc == 5 ? argv[4] : "";
	if (tqsl_importPKCS12File(argv[2], argv[3], keypass, nullptr, report, nullptr))
		fail(std::string("importing ") + argv[2]);
	return 0;
}

int export_p12(int argc, char** argv) {
	if (argc < 5 || argc > 7) usage();
	tQSL_Cert cert = certificate_for(argv[2]);
	char* keypass = argc >= 6 ? argv[5] : nullptr;
	bool weak = argc == 7 && std::strcmp(argv[6], "weak") == 0;
	if (argc == 7 && !weak) usage();
	// Exporting the key needs it unlocked, as tqsllib.h says for tqsl_exportPKCS12File.
	if (tqsl_beginSigning(cert, keypass, nullptr, nullptr))
		fail("unlocking the key");
	int r = weak ? tqsl_exportPKCS12FileWeakCrypto(cert, argv[3], argv[4])
	             : tqsl_exportPKCS12File(cert, argv[3], argv[4]);
	if (r) fail(std::string("exporting ") + argv[3]);
	tqsl_endSigning(cert);
	return 0;
}

// Set field F of the page being captured: a list field by the code it stores, as station_loc sets
// DXCC; a text field as written.
void set_field(tQSL_Location loc, int f, const std::string& name, const std::string& value) {
	int input = 0;
	if (tqsl_getLocationFieldInputType(loc, f, &input)) fail("reading " + name + "'s type");
	if (input == TQSL_LOCATION_FIELD_DDLIST || input == TQSL_LOCATION_FIELD_LIST) {
		int nitems = 0;
		if (tqsl_getNumLocationFieldListItems(loc, f, &nitems)) fail("reading " + name + "'s list");
		for (int i = 0; i < nitems; i++) {
			char code[256];
			if (tqsl_setLocationFieldIndex(loc, f, i)) fail("choosing " + name);
			if (tqsl_getLocationFieldCharData(loc, f, code, sizeof code)) fail("reading " + name);
			if (value == code) return;
		}
		std::fprintf(stderr, "qgt-tqsllib: %s has no item %s\n", name.c_str(), value.c_str());
		std::exit(1);
	}
	if (tqsl_setLocationFieldCharData(loc, f, value.c_str())) fail("setting " + name);
}

int location(int argc, char** argv) {
	if (argc < 5) usage();
	std::map<std::string, std::string> fields = {{"CALL", argv[3]}, {"DXCC", argv[4]}};
	for (int a = 5; a < argc; a++) {
		const char* eq = std::strchr(argv[a], '=');
		if (!eq || eq == argv[a]) usage();
		fields[std::string(argv[a], eq - argv[a])] = eq + 1;
	}
	tQSL_Location loc;
	if (tqsl_initStationLocationCapture(&loc)) fail("starting a station location");
	if (tqsl_setStationLocationCapturePage(loc, 1)) fail("opening page 1");
	// Page by page and field by field in the page's own order, as TQSL's app fills one in: a field's
	// list depends on the fields before it (CALL, then DXCC, then the state, then its counties), so
	// each is set and the page updated before the next is read.
	std::map<std::string, bool> set;
	for (;;) {
		int nfield = 0;
		if (tqsl_getNumLocationField(loc, &nfield)) fail("reading the page's fields");
		for (int f = 0; f < nfield; f++) {
			char gabbi[256];
			if (tqsl_getLocationFieldDataGABBI(loc, f, gabbi, sizeof gabbi)) fail("reading a field's name");
			auto it = fields.find(gabbi);
			if (it == fields.end() || set[it->first]) continue;
			set_field(loc, f, it->first, it->second);
			set[it->first] = true;
			if (tqsl_updateStationLocationCapture(loc)) fail("updating after " + it->first);
		}
		// As TQSL's app reads it (apps/stationdial.cpp:414): on the last page this answers 1 with
		// no error, so nonzero, like rval 0, means there is no next page.
		int more = 0;
		if (tqsl_hasNextStationLocationCapture(loc, &more) || !more) break;
		if (tqsl_nextStationLocationCapture(loc)) fail("opening the next page");
	}
	for (auto& [name, value] : fields) {
		if (!set[name]) {
			std::fprintf(stderr, "qgt-tqsllib: no station-location field %s\n", name.c_str());
			return 1;
		}
	}
	if (tqsl_setStationLocationCaptureName(loc, argv[2])) fail("naming the location");
	if (tqsl_saveStationLocationCapture(loc, 1)) fail("saving the location");
	tqsl_endStationLocationCapture(&loc);
	std::printf("saved station location %s\n", argv[2]);
	return 0;
}

// converter's loop (TrustedQSL's src/converter.cpp), with the key's password passed to
// tqsl_beginSigning, and duplicates refused and committed so uploaded.db records the log.
int sign(int argc, char** argv) {
	if (argc < 5 || argc > 6) usage();
	char* keypass = argc == 6 ? argv[5] : std::getenv("QGT_TEST_KEYPASS");
	tQSL_Location loc;
	if (tqsl_getStationLocation(&loc, argv[2])) fail(std::string("opening location ") + argv[2]);
	char call[256];
	int dxcc = 0;
	if (tqsl_getLocationCallSign(loc, call, sizeof call)) fail("reading the location's call");
	if (tqsl_getLocationDXCCEntity(loc, &dxcc)) fail("reading the location's DXCC");
	tQSL_Cert* certs = nullptr;
	int ncerts = 0;
	if (tqsl_selectCertificates(&certs, &ncerts, call, dxcc, nullptr, nullptr, 1))
		fail("selecting certificates");
	if (ncerts < 1) {
		std::fprintf(stderr, "qgt-tqsllib: no certificate for %s\n", call);
		return 1;
	}
	tQSL_Converter conv = nullptr;
	if (std::string(argv[1]) == "sign-cabrillo") {
		if (tqsl_beginCabrilloConverter(&conv, argv[3], certs, ncerts, loc)) fail("reading Cabrillo");
	} else if (tqsl_beginADIFConverter(&conv, argv[3], certs, ncerts, loc)) fail("reading ADIF");
	tqsl_setConverterAllowDuplicates(conv, std::string(argv[1]) == "sign-cabrillo");
	// Optional settings for the signing-options differential corpus. No process-global map
	// survives a run. TQSL's app installs these after opening the converter (tqsl.cpp:2286–2295).
	if (const char* value = std::getenv("QGT_IGNORE_SECONDS"))
		tqsl_setConverterIgnoreSeconds(conv, std::atoi(value));
	if (const char* value = std::getenv("QGT_IGNORE_CALLSIGNS"))
		tqsl_setConverterIgnoreCallsigns(conv, std::atoi(value));
	if (const char* value = std::getenv("QGT_ALLOW_BAD_CALLS"))
		tqsl_setConverterAllowBadCall(conv, std::atoi(value));
	if (const char* value = std::getenv("QGT_QTH"))
		tqsl_setConverterQTHDetails(conv, std::atoi(value));
	if (const char* value = std::getenv("QGT_MODE_MAP")) {
		std::string mapping(value);
		auto eq = mapping.find('=');
		if (eq == std::string::npos) usage();
		if (tqsl_setADIFMode(mapping.substr(0, eq).c_str(), mapping.substr(eq + 1).c_str()))
			fail("installing the custom mode map");
	}
	std::ofstream out(argv[4], std::ios::out | std::ios::trunc | std::ios::binary);
	if (!out) {
		std::fprintf(stderr, "qgt-tqsllib: cannot write %s\n", argv[4]);
		return 1;
	}
	for (;;) {
		const char* gabbi = tqsl_getConverterGABBI(conv);
		if (gabbi) {
			out << gabbi;
			continue;
		}
		if (tQSL_Error == TQSL_SIGNINIT_ERROR) {
			tQSL_Cert cert;
			if (tqsl_getConverterCert(conv, &cert)) fail("getting the signing certificate");
			if (tqsl_beginSigning(cert, keypass, nullptr, nullptr)) fail("unlocking the key");
			continue;
		}
		// A new uploaded.db was just made: TQSL's app carries on with it (apps/tqsl.cpp:2407).
		if (tQSL_Error == TQSL_NEW_UPLOAD_DB) continue;
		if (tQSL_Error == TQSL_DUPLICATE_QSO) {
			int line = 0;
			tqsl_getConverterLine(conv, &line);
			std::printf("duplicate, skipped: line %d\n", line);
			continue;
		}
		break;
	}
	out.close();
	if (tQSL_Error != TQSL_NO_ERROR) {
		// The message first: asking for the line clears tqsllib's error.
		std::string why = tqsl_getErrorString();
		int code = tQSL_Error;
		int line = 0;
		tqsl_getConverterLine(conv, &line);
		tqsl_converterRollBack(conv);
		std::fprintf(stderr, "qgt-tqsllib: signing, at line %d: %s (error %d)\n", line, why.c_str(), code);
		return 1;
	}
	tqsl_converterCommit(conv);
	tqsl_endConverter(&conv);
	std::printf("signed %s into %s\n", argv[3], argv[4]);
	return 0;
}

}  // namespace

// Private TSV for the offline differential; no log data is printed on stdout.
int read_cabrillo(int argc, char** argv) {
	if (argc != 4) usage();
	std::ofstream out(argv[3], std::ios::binary);
	tQSL_Cabrillo cab = nullptr;
	if (tqsl_beginCabrillo(&cab, argv[2])) { out << "REFUSED\n"; return 0; }
	std::map<std::string, std::string> record;
	for (;;) {
		tqsl_cabrilloField field;
		TQSL_CABRILLO_ERROR_TYPE status;
		if (tqsl_getCabrilloField(cab, &field, &status)) { out << "REFUSED\n"; break; }
		if (status == TQSL_CABRILLO_EOF) break;
		record[field.name] = field.value;
		if (status == TQSL_CABRILLO_EOR) {
			out << record["CALL"] << '\t' << record["BAND"] << '\t' << record["MODE"] << '\t'
				<< record["QSO_DATE"] << '\t' << record["TIME_ON"] << '\t' << record["FREQ"] << '\n';
			record.clear();
		}
	}
	tqsl_endCabrillo(&cab);
	return 0;
}

int main(int argc, char** argv) {
	if (argc < 2) usage();
	// tqsllib's own trace, to the file QGT_TQSL_TRACE names, for finding why a step failed.
	if (const char* trace = std::getenv("QGT_TQSL_TRACE"))
		tQSL_DiagFile = std::fopen(trace, "a");
	if (tqsl_init()) fail("starting tqsllib");
	std::string cmd = argv[1];
	if (cmd == "request") return request(argc, argv);
	if (cmd == "import-p12") return import_p12(argc, argv);
	if (cmd == "export-p12") return export_p12(argc, argv);
	if (cmd == "location") return location(argc, argv);
	if (cmd == "sign" || cmd == "sign-cabrillo") return sign(argc, argv);
	if (cmd == "read-cabrillo") return read_cabrillo(argc, argv);
	usage();
}
