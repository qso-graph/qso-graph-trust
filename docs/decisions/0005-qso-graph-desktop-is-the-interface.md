# 0005: No QGT app: QSO Graph Desktop is QG Trust's interface

Decided 2026-11-02 by KI7MT (KI7MT/ki7mt-ai-lab-devel#50). Supersedes the app in decisions 0001 and
0003.

## What was decided

- **QG Trust is the library and its command line,** `qg-trust`, installable without QSO Graph Desktop and
  callable from other programs.
- **There is no standalone QG Trust app.** Its interface is QSO Graph Desktop, where QG Trust ships as an
  official extension. A ham who wants only certificate management installs QSO Graph Desktop and turns on
  QG Trust alone: every extension starts off, and turning one off deactivates it rather than hiding it
  (qso-graph-desktop `docs/P8.md`).
- QG Rig and QG UDP follow the same shape.

## Why

One interface means one shell to build, secure and maintain, and one store of certificates, keys and
personas, rather than a second Electron app holding its own copy of the same ones.

## Still open

Where the library's code loads in QSO Graph Desktop: inside the core's native addon, so it is in memory
whether or not the extension is on, or with the extension, so turning QG Trust off removes the code as
well. The second keeps the code holding a key narrower; it depends on whether the extension host can load
a native addon. Decided with phase 3 (qso-graph-desktop#172).
