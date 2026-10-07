# Changelog

## [0.6.3](https://github.com/SVGreg/surfaceguard/compare/v0.6.2...v0.6.3) (2026-10-07)


### Bug Fixes

* **hooks:** gate builtin-named local skills, reject path-like names, fail closed on errors ([#387](https://github.com/SVGreg/surfaceguard/issues/387)) ([891db50](https://github.com/SVGreg/surfaceguard/commit/891db505e4a6daefa9e6b7f1c49c166532208ed9))
* **rules:** an all-composite reports every first-branch match, so suppress is per line ([#403](https://github.com/SVGreg/surfaceguard/issues/403)) ([e5ef4fd](https://github.com/SVGreg/surfaceguard/commit/e5ef4fd217b6c5431701566809b81b4210c20b79))
* **rules:** narrow SG-SEC-001 — "Local Storage" counts only in path form ([#393](https://github.com/SVGreg/surfaceguard/issues/393)) ([567e04b](https://github.com/SVGreg/surfaceguard/commit/567e04be37e8bc5649bdd9695a3c5ac311904a77))
* **rules:** SG-INJ-011 tells a device-code login from ClickFix by where the text goes ([#402](https://github.com/SVGreg/surfaceguard/issues/402)) ([89977f4](https://github.com/SVGreg/surfaceguard/commit/89977f454cb739da4ceede66000e0d052c8a7c67))
* **skill:** reject named pipes and other non-regular files instead of blocking on them ([#397](https://github.com/SVGreg/surfaceguard/issues/397)) ([2dbc63e](https://github.com/SVGreg/surfaceguard/commit/2dbc63e5cb4baec8ad9f494e43b6fa82b180b71c))

## [0.6.2](https://github.com/SVGreg/surfaceguard/compare/v0.6.1...v0.6.2) (2026-10-03)


### Features

* **rules:** add SG-STEER-002 — dependency steering tripwire (AST02) (closes [#366](https://github.com/SVGreg/surfaceguard/issues/366)) ([#377](https://github.com/SVGreg/surfaceguard/issues/377)) ([32f2122](https://github.com/SVGreg/surfaceguard/commit/32f212210d87b49adf54b3ecffff4799458c7d15))


### Bug Fixes

* **keyless:** refuse single-file bundles in SignBundle and fix identity exit codes ([#378](https://github.com/SVGreg/surfaceguard/issues/378)) ([4b05e01](https://github.com/SVGreg/surfaceguard/commit/4b05e01225104cd0fd929f7963b61c0ee5a967d7))
* **rules:** widen SG-NET-001 with paste and OOB hosts; cap tweet-embed t.co ([#381](https://github.com/SVGreg/surfaceguard/issues/381)) ([ddc2123](https://github.com/SVGreg/surfaceguard/commit/ddc212332943150b3c1a3ccb982db7402e1019d5))

## [0.6.1](https://github.com/SVGreg/surfaceguard/compare/v0.6.0...v0.6.1) (2026-10-01)


### Features

* **rules:** add SG-MCP-002 — MCP tool preference manipulation (AST04) (closes [#89](https://github.com/SVGreg/surfaceguard/issues/89)) ([#370](https://github.com/SVGreg/surfaceguard/issues/370)) ([f858b3c](https://github.com/SVGreg/surfaceguard/commit/f858b3cc00cac5b8455108ca3663d9b2bf25983e))
* **rules:** section-scoped context rules cap prose under a prohibition heading (closes [#280](https://github.com/SVGreg/surfaceguard/issues/280)) ([#375](https://github.com/SVGreg/surfaceguard/issues/375)) ([d140035](https://github.com/SVGreg/surfaceguard/commit/d140035becae119ebf3e685b988529c1f0b91208))
* **rules:** SG-MCP-003/004 — remote tool-source registration, disclosed and judged (AST02) (closes [#289](https://github.com/SVGreg/surfaceguard/issues/289)) ([#376](https://github.com/SVGreg/surfaceguard/issues/376)) ([3c1b7fe](https://github.com/SVGreg/surfaceguard/commit/3c1b7fe8af4ac2d473b8afe3d4369040c94a5ba8))
* **rules:** SG-NET-002 catches a decoded blob piped or eval'd into a shell (closes [#118](https://github.com/SVGreg/surfaceguard/issues/118)) ([#371](https://github.com/SVGreg/surfaceguard/issues/371)) ([47a16a3](https://github.com/SVGreg/surfaceguard/commit/47a16a3ec3c73d4174a1ba6629e107670ff65fde))
* **skill:** scan .tsx/.jsx/.rs/.go/.lua/.fish/.vbs as scripts (closes [#187](https://github.com/SVGreg/surfaceguard/issues/187)) ([#374](https://github.com/SVGreg/surfaceguard/issues/374)) ([2bdbc52](https://github.com/SVGreg/surfaceguard/commit/2bdbc52fc1d9d5b570c3353eb35567c79e0e82f0))


### Bug Fixes

* **attest:** refuse symlinks on every write and rewrite SKILL.md atomically (closes [#140](https://github.com/SVGreg/surfaceguard/issues/140)) ([#373](https://github.com/SVGreg/surfaceguard/issues/373)) ([9287b50](https://github.com/SVGreg/surfaceguard/commit/9287b5003acaaf9e2d845ed17eebd7d085fcaf48))

## [0.6.0](https://github.com/SVGreg/surfaceguard/compare/v0.5.5...v0.6.0) (2026-09-28)


### Features

* **action:** scan a folder of skills from the default path (M9-09) ([#359](https://github.com/SVGreg/surfaceguard/issues/359)) ([67b3d71](https://github.com/SVGreg/surfaceguard/commit/67b3d7124e99457ef3e151971821602813d4a7c2))
* **cli:** scan --installed and surfaceguard locations (M9-07) ([#356](https://github.com/SVGreg/surfaceguard/issues/356)) ([124e9d8](https://github.com/SVGreg/surfaceguard/commit/124e9d8a183ad195f973e021c0e1c0e991d62a81))
* **cli:** scan &lt;path&gt;... — folder discovery and many paths (M9-05) ([#354](https://github.com/SVGreg/surfaceguard/issues/354)) ([a55408c](https://github.com/SVGreg/surfaceguard/commit/a55408c2d8702e16c2787f1bfb9e6fe53d23a856))
* **cli:** verify many skills — folders, paths and --installed (M9-10) ([#360](https://github.com/SVGreg/surfaceguard/issues/360)) ([d7f452c](https://github.com/SVGreg/surfaceguard/commit/d7f452cda1ddc24d96be9b66fd4daa721a51e5fd))
* **locations:** embedded registry of agent skill locations (M9-06) ([#355](https://github.com/SVGreg/surfaceguard/issues/355)) ([5d3155b](https://github.com/SVGreg/surfaceguard/commit/5d3155b4a3f96a181144890202d4a794d67527fc))
* **policy:** waive a whole skill pinned to its Merkle root ([#363](https://github.com/SVGreg/surfaceguard/issues/363)) ([9f7227f](https://github.com/SVGreg/surfaceguard/commit/9f7227fda8808853196e48acdfdac04c5596c9b9))
* **report:** multi-bundle SARIF — one run, root-relative URIs (M9-04) ([#353](https://github.com/SVGreg/surfaceguard/issues/353)) ([c4ef94a](https://github.com/SVGreg/surfaceguard/commit/c4ef94a633c5ecf0543d47d6750ed840185b6065))
* **scan:** multi-bundle scan engine and aggregate text/JSON report (M9-03) ([#352](https://github.com/SVGreg/surfaceguard/issues/352)) ([cc52439](https://github.com/SVGreg/surfaceguard/commit/cc52439497fb65adc04bd28094bdb96eb26b2c23))
* **skill:** Discover() — bounded, symlink-safe, deterministic bundle discovery (M9-02) ([#350](https://github.com/SVGreg/surfaceguard/issues/350)) ([b438ac2](https://github.com/SVGreg/surfaceguard/commit/b438ac292a2c876cd5597e8092e211a0e657cd43))


### Bug Fixes

* **guard:** verdict cache served stale decisions after a signature swap, a waiver expiry or an attestation expiry ([#357](https://github.com/SVGreg/surfaceguard/issues/357)) ([9799aa6](https://github.com/SVGreg/surfaceguard/commit/9799aa6a11b670403c63de86ff682d8619c33bec))
* **rules:** widen and narrow SG-EXE-004 — systemd/Windows/login-item persistence; crontab and rc leaves no longer fire on prose or SQL ([#361](https://github.com/SVGreg/surfaceguard/issues/361)) ([9ac13ea](https://github.com/SVGreg/surfaceguard/commit/9ac13ea46a14c4264c59fe33b7b9c4e666273403))
* **skill:** classify .mcp.json, per-IDE and one-file-per-tool MCP manifests as configs ([#187](https://github.com/SVGreg/surfaceguard/issues/187)) ([#362](https://github.com/SVGreg/surfaceguard/issues/362)) ([99f9db5](https://github.com/SVGreg/surfaceguard/commit/99f9db557e000670169d72660dac151c82edf27c))


### Miscellaneous Chores

* release 0.6.0 ([58066e0](https://github.com/SVGreg/surfaceguard/commit/58066e00f7b7e84bf94796098984801f216f86a5))

## [0.5.5](https://github.com/SVGreg/surfaceguard/compare/v0.5.4...v0.5.5) (2026-09-27)


### Features

* **rules:** add SG-EVA-004 — reviewer-directed verdict manipulation (AST08) ([#331](https://github.com/SVGreg/surfaceguard/issues/331)) ([e9ccd1b](https://github.com/SVGreg/surfaceguard/commit/e9ccd1b116d7f3649bf9d0ccbd66c0219d0e3708))
* **rules:** widen SG-MTA-001 to the verbatim YAML tag, Ruby Psych gadget tags and %TAG handles (AST04) ([#346](https://github.com/SVGreg/surfaceguard/issues/346)) ([a2fd91e](https://github.com/SVGreg/surfaceguard/commit/a2fd91e6b4ae22593fb82d03c44deea2235f6330))
* **rules:** widen SG-SEC-001 to CLI-printed and env-held credentials (AST03) ([#332](https://github.com/SVGreg/surfaceguard/issues/332)) ([cc70ff6](https://github.com/SVGreg/surfaceguard/commit/cc70ff61523848e3b69edef039e39645936daea7))


### Bug Fixes

* **evaluation:** fetch_clawhub and fetch_skillsmp honour OUTROOT and LEDGER_SOURCE ([#347](https://github.com/SVGreg/surfaceguard/issues/347)) ([9ecff67](https://github.com/SVGreg/surfaceguard/commit/9ecff6720581c63b7b194ef1471b49a68824657f))
* **oms:** refuse a statement whose subject root disagrees with its resources ([#334](https://github.com/SVGreg/surfaceguard/issues/334)) ([750c772](https://github.com/SVGreg/surfaceguard/commit/750c77223f09a663b153835f94f58bb33b507ec5))
* **rules:** narrow and widen SG-NET-002 — table pipes, argument-less mentions, data to interpreters; sudo -E, /bin/bash, env, tee ([#341](https://github.com/SVGreg/surfaceguard/issues/341)) ([dff88fe](https://github.com/SVGreg/surfaceguard/commit/dff88fe8b38409313eabb3ae94823eed3595e7fa))
* **rules:** narrow SG-INJ-011 — the relay verb must start a clause, so a negated relay no longer fires ([#342](https://github.com/SVGreg/surfaceguard/issues/342)) ([aaec47c](https://github.com/SVGreg/surfaceguard/commit/aaec47c75098916da92668c1152590558e194b10))
* **rules:** narrow SG-SEC-001 — the verb→path gap no longer crosses a sentence ([#327](https://github.com/SVGreg/surfaceguard/issues/327)) ([00e30fa](https://github.com/SVGreg/surfaceguard/commit/00e30fa9ba245b89134bc9239575ed6d0ef4cfcd)), closes [#325](https://github.com/SVGreg/surfaceguard/issues/325)
* **verify:** anchor keyless certificate validity on a proven log entry's time ([#343](https://github.com/SVGreg/surfaceguard/issues/343)) ([71c6d5d](https://github.com/SVGreg/surfaceguard/commit/71c6d5d6e70cc80c312e0c62b236bbb3fdb92e75))

## [0.5.4](https://github.com/SVGreg/surfaceguard/compare/v0.5.3...v0.5.4) (2026-09-19)


### Bug Fixes

* **cmd:** outputWriter returns an exitErr instead of calling os.Exit ([#323](https://github.com/SVGreg/surfaceguard/issues/323)) ([53c032d](https://github.com/SVGreg/surfaceguard/commit/53c032d1f03965c5b82d27b3584a5a9f68b9c7dc))
* **evaluation:** report line shape in rule_findings.py so structural matches can be judged ([#317](https://github.com/SVGreg/surfaceguard/issues/317)) ([ba55286](https://github.com/SVGreg/surfaceguard/commit/ba55286aec087f29d36d70bb6ffe024f30383f06))
* **report:** percent-encode the SARIF artifact URI ([#320](https://github.com/SVGreg/surfaceguard/issues/320)) ([a2377f8](https://github.com/SVGreg/surfaceguard/commit/a2377f870e6ff7c9515dc3d7c8af07cce1d8e82f))

## [0.5.3](https://github.com/SVGreg/surfaceguard/compare/v0.5.2...v0.5.3) (2026-09-16)


### Features

* **rules:** add SG-EXE-010 — host security control disabled (AST01) ([#300](https://github.com/SVGreg/surfaceguard/issues/300)) ([fb5cea8](https://github.com/SVGreg/surfaceguard/commit/fb5cea8e82f76979fc87f126661dc8dae9fd6c43)), closes [#298](https://github.com/SVGreg/surfaceguard/issues/298)
* **rules:** add SG-INJ-012 — falsified completion report (AST01) ([#291](https://github.com/SVGreg/surfaceguard/issues/291)) ([f859c73](https://github.com/SVGreg/surfaceguard/commit/f859c73578b7bdbca07776273afb846147ba9d5f)), closes [#288](https://github.com/SVGreg/surfaceguard/issues/288)
* **rules:** add SG-INJ-013 — structural concealment by padding (AST01/AST04) ([#310](https://github.com/SVGreg/surfaceguard/issues/310)) ([01b236e](https://github.com/SVGreg/surfaceguard/commit/01b236e0761c6d384842dcf20f4a877728947df5)), closes [#308](https://github.com/SVGreg/surfaceguard/issues/308)


### Bug Fixes

* **cmd:** reject a --ttl-days that makes an attestation born expired ([#301](https://github.com/SVGreg/surfaceguard/issues/301)) ([f2ed805](https://github.com/SVGreg/surfaceguard/commit/f2ed8050588e5540d0a11a8b7fd9d844a9b30292))
* **eval:** repair the skillsmp fetcher, which had been returning zero bundles ([#304](https://github.com/SVGreg/surfaceguard/issues/304)) ([3992a78](https://github.com/SVGreg/surfaceguard/commit/3992a78d20f697ca12983d9221a47d0e17868c4e))
* **policy:** reject the two policy misconfigurations that still failed silently ([#292](https://github.com/SVGreg/surfaceguard/issues/292)) ([be9f51a](https://github.com/SVGreg/surfaceguard/commit/be9f51a0eecde4116d946269a8255989ef020306))
* **rules:** SG-AS-001 stops at command boundaries and at installs ([#297](https://github.com/SVGreg/surfaceguard/issues/297)) ([12b7efa](https://github.com/SVGreg/surfaceguard/commit/12b7efa2c394e49fe2dcb631cf7784ddd481f880)), closes [#294](https://github.com/SVGreg/surfaceguard/issues/294)
* **rules:** SG-EXE-003 detects privilege grants, not privileged commands ([#287](https://github.com/SVGreg/surfaceguard/issues/287)) ([e38b4a7](https://github.com/SVGreg/surfaceguard/commit/e38b4a7c60418b354f1d0a814c40033340616265))
* **rules:** SG-INJ-002's comment leaf needs whole words (closes [#277](https://github.com/SVGreg/surfaceguard/issues/277)) ([#281](https://github.com/SVGreg/surfaceguard/issues/281)) ([45df97b](https://github.com/SVGreg/surfaceguard/commit/45df97b3a231c2d4648497232443d7c094cea9e2))
* **rules:** the documentary penalty no longer reads a leaf's own text as context (closes [#143](https://github.com/SVGreg/surfaceguard/issues/143)) ([#283](https://github.com/SVGreg/surfaceguard/issues/283)) ([8ba1f1b](https://github.com/SVGreg/surfaceguard/commit/8ba1f1b204f6a5f81f646807db2e1506687920ba))
* **verify:** a co-signature must not mask a revoked key ([#311](https://github.com/SVGreg/surfaceguard/issues/311)) ([16700e7](https://github.com/SVGreg/surfaceguard/commit/16700e747127d792e857983f746a8c158ad90985))

## [0.5.2](https://github.com/SVGreg/surfaceguard/compare/v0.5.1...v0.5.2) (2026-09-12)


### Features

* **rules:** add SG-CFG-003 — instruction to write the user's agent configuration (closes [#251](https://github.com/SVGreg/surfaceguard/issues/251)) ([#273](https://github.com/SVGreg/surfaceguard/issues/273)) ([98229c8](https://github.com/SVGreg/surfaceguard/commit/98229c86c7222d60b77f75ad75178f185f44f1dd))


### Bug Fixes

* **rules:** anchor SG-SEC-001's .aws alternative to a path separator (closes [#260](https://github.com/SVGreg/surfaceguard/issues/260)) ([#268](https://github.com/SVGreg/surfaceguard/issues/268)) ([0f005a8](https://github.com/SVGreg/surfaceguard/commit/0f005a85e2063c0de8f00731f789288d4ecf6f84))
* **rules:** SG-AS-001 no longer reads a bundle-relative sibling as snooping (closes [#249](https://github.com/SVGreg/surfaceguard/issues/249)) ([#271](https://github.com/SVGreg/surfaceguard/issues/271)) ([c4a3eb6](https://github.com/SVGreg/surfaceguard/commit/c4a3eb6d8911830797d5ab55a3bbb69eb1d81c8b))
* **rules:** SG-AS-001 stops reading install instructions as snooping (closes [#272](https://github.com/SVGreg/surfaceguard/issues/272)) ([#274](https://github.com/SVGreg/surfaceguard/issues/274)) ([0910314](https://github.com/SVGreg/surfaceguard/commit/0910314347c62315b8316c2ab626fbba83da47ee))
* **rules:** SG-DEP-001 no longer reads an IAM policy wildcard as a floating dependency (closes [#263](https://github.com/SVGreg/surfaceguard/issues/263)) ([#275](https://github.com/SVGreg/surfaceguard/issues/275)) ([3d4adf7](https://github.com/SVGreg/surfaceguard/commit/3d4adf7fba4cefe94f18810f1f992af9e408dfde))
* **rules:** SG-EXE-001 ignores exec aliased to execFile via promisify (closes [#246](https://github.com/SVGreg/surfaceguard/issues/246)) ([#278](https://github.com/SVGreg/surfaceguard/issues/278)) ([f14e116](https://github.com/SVGreg/surfaceguard/commit/f14e11665995d57473bd5e544e728b308fa483f4))
* **rules:** SG-INJ-002 ignores prose that documents a code point (closes [#250](https://github.com/SVGreg/surfaceguard/issues/250)) ([#276](https://github.com/SVGreg/surfaceguard/issues/276)) ([6cfca0d](https://github.com/SVGreg/surfaceguard/commit/6cfca0d4a5a22db90b9aa3a0468427b39e70d0b6))
* **rules:** SG-INJ-010 ignores a directive whose object is a quoted claim (closes [#264](https://github.com/SVGreg/surfaceguard/issues/264)) ([#279](https://github.com/SVGreg/surfaceguard/issues/279)) ([5143cb6](https://github.com/SVGreg/surfaceguard/commit/5143cb6e12ca2b3d9a3af982a8f1394afe0bef5a))
* **rules:** SG-REF-003 requires an external locator, SG-ANTI-001 drops "unlimited" (closes [#262](https://github.com/SVGreg/surfaceguard/issues/262), closes [#261](https://github.com/SVGreg/surfaceguard/issues/261)) ([#269](https://github.com/SVGreg/surfaceguard/issues/269)) ([a4404cf](https://github.com/SVGreg/surfaceguard/commit/a4404cf5a65ee3138f6d93d30edd092c4b4c4428))

## [0.5.1](https://github.com/SVGreg/surfaceguard/compare/v0.5.0...v0.5.1) (2026-09-10)


### Features

* **report:** add --snippet to show the source line that triggered a finding ([#257](https://github.com/SVGreg/surfaceguard/issues/257)) ([e5d5666](https://github.com/SVGreg/surfaceguard/commit/e5d566632feeb2eed383872c1104e09192bc335d))

## [0.5.0](https://github.com/SVGreg/surfaceguard/compare/v0.4.1...v0.5.0) (2026-09-07)


### ⚠ BREAKING CHANGES

* remove every trace of the former name ([#255](https://github.com/SVGreg/surfaceguard/issues/255))
* move schema identifiers to surfaceguard.svgreg.net, and gate apiVersion ([#254](https://github.com/SVGreg/surfaceguard/issues/254))

### Features

* **eval:** add install-ranked skills.sh corpus and vendor regression anchor ([#247](https://github.com/SVGreg/surfaceguard/issues/247)) ([c2ba001](https://github.com/SVGreg/surfaceguard/commit/c2ba00136057f24918fb2d767e21540128b24874))
* **maintain:** add sg-corpus-sweep — fetch fresh skills into quarantine, scan, mine ([#253](https://github.com/SVGreg/surfaceguard/issues/253)) ([c4fc73d](https://github.com/SVGreg/surfaceguard/commit/c4fc73de222d6fcd815780ca7e31c807e0fd5a1e))
* move schema identifiers to surfaceguard.svgreg.net, and gate apiVersion ([#254](https://github.com/SVGreg/surfaceguard/issues/254)) ([5644879](https://github.com/SVGreg/surfaceguard/commit/56448792c6f532cd27c1752b62099aa3b40ea831))


### Code Refactoring

* remove every trace of the former name ([#255](https://github.com/SVGreg/surfaceguard/issues/255)) ([220ba15](https://github.com/SVGreg/surfaceguard/commit/220ba159c7662df9de099d70dc53fdfdd34d3be4))

## [0.4.1](https://github.com/SVGreg/surfaceguard/compare/v0.4.0...v0.4.1) (2026-09-07)


### Bug Fixes

* **cli:** report the real version when not built by GoReleaser ([#244](https://github.com/SVGreg/surfaceguard/issues/244)) ([b311472](https://github.com/SVGreg/surfaceguard/commit/b3114721850039cd9a0ca53231c6939f897b0f2d))

## [0.4.0](https://github.com/SVGreg/surfaceguard/compare/v0.3.0...v0.4.0) (2026-09-07)


### ⚠ BREAKING CHANGES

* the Go module path is now github.com/SVGreg/surfaceguard and the binary is `surfaceguard`. Module paths have no redirect; update imports. The repo URL and `uses:` refs redirect on GitHub.

### Code Refactoring

* rename surfaceguard to SurfaceGuard ([#242](https://github.com/SVGreg/surfaceguard/issues/242)) ([7426ae3](https://github.com/SVGreg/surfaceguard/commit/7426ae32609ebc5bf85f8b2e1fdab45102aa0ebb))

## [0.3.0](https://github.com/SVGreg/surfaceguard/compare/v0.2.2...v0.3.0) (2026-09-04)


### Features

* **attest:** add an ECDSA P-256 signing path (M4-05) ([#217](https://github.com/SVGreg/surfaceguard/issues/217)) ([f56bbee](https://github.com/SVGreg/surfaceguard/commit/f56bbee2e0a6f4480d0c60206a4d688382a01454))
* **attest:** build the OMS manifest, root digest, and statement (M4-04) ([#216](https://github.com/SVGreg/surfaceguard/issues/216)) ([7cd70ed](https://github.com/SVGreg/surfaceguard/commit/7cd70ed87fe269db6c5232a8300b21b6645a3b73))
* **attest:** implement OMS path canonicalization and enumeration (M4-03) ([#215](https://github.com/SVGreg/surfaceguard/issues/215)) ([d509e13](https://github.com/SVGreg/surfaceguard/commit/d509e1369c4cd88240dde3168f32a3ad3c870d8d))
* **attest:** vendor the OMS v1.0 vectors and model the bundle format (M4-02) ([#214](https://github.com/SVGreg/surfaceguard/issues/214)) ([5b9a6eb](https://github.com/SVGreg/surfaceguard/commit/5b9a6eb1b1d44869ac7ae2933ab2dbb912777fe9))
* **attest:** write OMS bundles with sign --oms (M4-06) ([#218](https://github.com/SVGreg/surfaceguard/issues/218)) ([c92b6ae](https://github.com/SVGreg/surfaceguard/commit/c92b6ae5e5aec2fcabafe2cfcc87229cdcb87adf))
* **card:** make skill cards verifiable against their subject (M5-06) ([#234](https://github.com/SVGreg/surfaceguard/issues/234)) ([bd6ad8c](https://github.com/SVGreg/surfaceguard/commit/bd6ad8cb1d27c193ad82a4a325fc3551cf52b6cd))
* **ci:** add a composite GitHub Action that scans and uploads SARIF (M3-06) ([#211](https://github.com/SVGreg/surfaceguard/issues/211)) ([772979d](https://github.com/SVGreg/surfaceguard/commit/772979d33639f5282ec6aaf82a8f4e8c3ff5d63f))
* **cli:** add --format sarif to scan, with docs (M3-02) ([#207](https://github.com/SVGreg/surfaceguard/issues/207)) ([4134c02](https://github.com/SVGreg/surfaceguard/commit/4134c020a3215eeff7b69c6439e81171db86ed90))
* **cli:** add `surfaceguard guard` (M5-04) ([#231](https://github.com/SVGreg/surfaceguard/issues/231)) ([d23f64b](https://github.com/SVGreg/surfaceguard/commit/d23f64b3ab7b11317e05e5e4ee14675ec1d5a8ca))
* **guard:** add Guard(), the one-shot load-time decision (M5-02) ([#229](https://github.com/SVGreg/surfaceguard/issues/229)) ([778b190](https://github.com/SVGreg/surfaceguard/commit/778b1909c5e1c473ea5d27c1c34cdcf6d189f080))
* **guard:** add install-time mode (M5-05) ([#233](https://github.com/SVGreg/surfaceguard/issues/233)) ([6999f19](https://github.com/SVGreg/surfaceguard/commit/6999f197b24a4d18ae27c1c225d243f2ba620d5b))
* **guard:** cache verdicts by content hash and policy (M5-03) ([#230](https://github.com/SVGreg/surfaceguard/issues/230)) ([1d19de7](https://github.com/SVGreg/surfaceguard/commit/1d19de7c9dfceba48b174adb03ebf38c36428522))
* **hooks:** gate skills on `guard`'s decision, not `verify`'s text (M5-07) ([#235](https://github.com/SVGreg/surfaceguard/issues/235)) ([bd40e83](https://github.com/SVGreg/surfaceguard/commit/bd40e83f6c8f49476f6a32c1b00cdd4a98fb7da5))
* **keyless:** add Sigstore keyless signing as a separate module (M4-12) ([#222](https://github.com/SVGreg/surfaceguard/issues/222)) ([250561a](https://github.com/SVGreg/surfaceguard/commit/250561ac8bb81fc88215acf1e571c74a9fd114a5))
* **policy:** add identity-based trust rules (M4-08) ([#220](https://github.com/SVGreg/surfaceguard/issues/220)) ([5b0a66a](https://github.com/SVGreg/surfaceguard/commit/5b0a66a14fb6d04cc4f57e7ddd7587e0cad18adc))
* **report:** emit SARIF 2.1.0 from a scan report (M3-01) ([#205](https://github.com/SVGreg/surfaceguard/issues/205)) ([a1b0e58](https://github.com/SVGreg/surfaceguard/commit/a1b0e58550d89cfd927307f8cb52939ec13070fa))
* **report:** emit waived findings as SARIF suppressions (M3-04) ([#209](https://github.com/SVGreg/surfaceguard/issues/209)) ([b2c8f0a](https://github.com/SVGreg/surfaceguard/commit/b2c8f0aa80a50410b3168c785aff0c47845c3d2c))
* **report:** export the AST taxonomy into SARIF (M3-03) ([#208](https://github.com/SVGreg/surfaceguard/issues/208)) ([5d24b54](https://github.com/SVGreg/surfaceguard/commit/5d24b5472916a1ca68583ddaa21b450358431ead))
* **verify:** verify keyless (certificate-bound) OMS signatures (M4-09) ([#221](https://github.com/SVGreg/surfaceguard/issues/221)) ([db737ee](https://github.com/SVGreg/surfaceguard/commit/db737ee966401677b6ccba05ff8b9dc05b302a33))
* **verify:** verify OMS bundles and auto-detect the signature format (M4-07) ([#219](https://github.com/SVGreg/surfaceguard/issues/219)) ([313f1af](https://github.com/SVGreg/surfaceguard/commit/313f1afe242f30f88a68633403c062ec901afe45))
* **verify:** verify Rekor inclusion proofs and signed checkpoints (M4-10) ([#224](https://github.com/SVGreg/surfaceguard/issues/224)) ([79db070](https://github.com/SVGreg/surfaceguard/commit/79db0709090cf04d38b59b5e369c8e1b3fb82d39))


### Bug Fixes

* **verify:** report the log timestamp even when no roots are pinned ([#223](https://github.com/SVGreg/surfaceguard/issues/223)) ([b15bfeb](https://github.com/SVGreg/surfaceguard/commit/b15bfeb1062862696181833418b391f1e99e939e))


### Performance Improvements

* **rules:** compile the built-in packs once per process (M5-09) ([#237](https://github.com/SVGreg/surfaceguard/issues/237)) ([03fa98c](https://github.com/SVGreg/surfaceguard/commit/03fa98c1e70456905f10b06b652e23db747bd5ba))


### Miscellaneous Chores

* release 0.3.0 ([25e0c10](https://github.com/SVGreg/surfaceguard/commit/25e0c10aa4cdf542b9d99a500895234983270418))

## [0.2.2](https://github.com/SVGreg/surfaceguard/compare/v0.2.1...v0.2.2) (2026-08-21)


### Features

* **rules:** add SG-EXE-008 — covert resource abuse / cryptomining (AST01) ([#194](https://github.com/SVGreg/surfaceguard/issues/194)) ([3c148ed](https://github.com/SVGreg/surfaceguard/commit/3c148ed2b303cb4bad92eae3bf7419f198594379)), closes [#191](https://github.com/SVGreg/surfaceguard/issues/191)
* **rules:** add SG-EXE-009 — nested agent spawned with the consent gate disabled (AST01/AST03) ([#201](https://github.com/SVGreg/surfaceguard/issues/201)) ([432ca51](https://github.com/SVGreg/surfaceguard/commit/432ca513eb038fdc6950d5f9aafcc64468596434)), closes [#199](https://github.com/SVGreg/surfaceguard/issues/199)


### Bug Fixes

* **rules:** narrow SG-DEP-001 — a hook matcher's "*" is a scope wildcard, not a version ([#190](https://github.com/SVGreg/surfaceguard/issues/190)) ([bcae7d0](https://github.com/SVGreg/surfaceguard/commit/bcae7d05c92523ef61e1702929d31a11dae2cb7e))
* **rules:** widen SG-MTA-003 — the line anchor was an evasion, and defaultMode was invisible ([#198](https://github.com/SVGreg/surfaceguard/issues/198)) ([b3c20dc](https://github.com/SVGreg/surfaceguard/commit/b3c20dc80cea29ffe1bc1aae3b5d676765328414)), closes [#192](https://github.com/SVGreg/surfaceguard/issues/192)
* **scan:** a nested SKILL.md was given the manifest role and then scanned by nothing ([#202](https://github.com/SVGreg/surfaceguard/issues/202)) ([9d765be](https://github.com/SVGreg/surfaceguard/commit/9d765be9649b66848ea5e834241a20cfa4c99362))
* **skill:** scriptExt silently decided the scanned surface — .bat/.cmd/.cjs reached no rule ([#189](https://github.com/SVGreg/surfaceguard/issues/189)) ([c836c57](https://github.com/SVGreg/surfaceguard/commit/c836c57875dee73677755061718ddab3e37c761c))


### Performance Improvements

* **rules:** evaluation was O(matches x text) — every match re-counted from offset 0 ([#196](https://github.com/SVGreg/surfaceguard/issues/196)) ([2ba3191](https://github.com/SVGreg/surfaceguard/commit/2ba319198458d2912af186460f99a3ea67df814e))

## [0.2.1](https://github.com/SVGreg/surfaceguard/compare/v0.2.0...v0.2.1) (2026-08-15)


### Features

* **rules:** context rules that cap severity, so a finding can be demoted instead of erased ([#178](https://github.com/SVGreg/surfaceguard/issues/178)) ([757f925](https://github.com/SVGreg/surfaceguard/commit/757f92521e7a160092f007a2ae63042a9b8ab9d8))
* **rules:** SG-SEC-001 covers crypto-wallet artifacts ([#179](https://github.com/SVGreg/surfaceguard/issues/179)) ([#184](https://github.com/SVGreg/surfaceguard/issues/184)) ([637974d](https://github.com/SVGreg/surfaceguard/commit/637974df019c877ab49f4640832cda9296f53c94))


### Bug Fixes

* **rules:** guard the whole pack set against \b binding to every alternation branch ([#177](https://github.com/SVGreg/surfaceguard/issues/177)) ([3c75417](https://github.com/SVGreg/surfaceguard/commit/3c75417f5242b097c9f6ff8f9974502c962e8915))
* **rules:** polish SG-INJ-001 — scope the weak target slot, add four missing phrase families ([#176](https://github.com/SVGreg/surfaceguard/issues/176)) ([0cadc09](https://github.com/SVGreg/surfaceguard/commit/0cadc09ca2e23260d7904e618a91a022245c0d6c))
* **rules:** widen SG-DEP-007 — bunx was named in the rule but unreachable ([#186](https://github.com/SVGreg/surfaceguard/issues/186)) ([aed38f8](https://github.com/SVGreg/surfaceguard/commit/aed38f8837c89ef6397e0c7a653c35a52a4dfc11))
* **rules:** widen the verb→path window so real credential paths are reachable ([#179](https://github.com/SVGreg/surfaceguard/issues/179)) ([#182](https://github.com/SVGreg/surfaceguard/issues/182)) ([b9a505a](https://github.com/SVGreg/surfaceguard/commit/b9a505afdcbeb520fb551047ac28443853a72a9d))


### Performance Improvements

* **skill:** gatherRefs counted newlines from offset 0 per match — quadratic on untrusted input ([#185](https://github.com/SVGreg/surfaceguard/issues/185)) ([d59ce7f](https://github.com/SVGreg/surfaceguard/commit/d59ce7fc57b388536bcb4e89a94934ee0c98680e))

## [0.2.0](https://github.com/SVGreg/surfaceguard/compare/v0.1.17...v0.2.0) (2026-08-11)


### Features

* **rules:** add SG-CFG-002 — repo-scoped agent settings execute or redirect at load (AST02/AST01) ([#168](https://github.com/SVGreg/surfaceguard/issues/168)) ([b6d593d](https://github.com/SVGreg/surfaceguard/commit/b6d593d594cb45b17ce8eba14d4bc28c03865cd6))
* **rules:** implement the homoglyph_ratio primitive — SG-INJ-002 signal (d) (AST04/AST01) ([#164](https://github.com/SVGreg/surfaceguard/issues/164)) ([7c22d83](https://github.com/SVGreg/surfaceguard/commit/7c22d830b2e7eda3c8915a3e0655c0ab0e300de1))
* **rules:** SG-EXE-007 — read-only tool reconfigured into an execution primitive ([#161](https://github.com/SVGreg/surfaceguard/issues/161)) ([2b2fa78](https://github.com/SVGreg/surfaceguard/commit/2b2fa78fabc207372d12d5a67f77258213ad3789))


### Bug Fixes

* **cmd:** keygen refuses to overwrite an existing key instead of destroying it ([#169](https://github.com/SVGreg/surfaceguard/issues/169)) ([df9fede](https://github.com/SVGreg/surfaceguard/commit/df9feded391d7e161f7dfd530c956b88c7603589))
* **report:** stop writing ANSI escapes into redirected files, and escape U+061C ([#162](https://github.com/SVGreg/surfaceguard/issues/162)) ([7a99874](https://github.com/SVGreg/surfaceguard/commit/7a99874ffbfea5f955395557ed99404b08c17d18))


### Miscellaneous Chores

* release 0.2.0 ([0ff8e2d](https://github.com/SVGreg/surfaceguard/commit/0ff8e2d60d41cf4069502cd2604d1f44fe3aab06))

## [0.1.17](https://github.com/SVGreg/surfaceguard/compare/v0.1.16...v0.1.17) (2026-08-09)


### Features

* **rules:** add SG-EVA-001 — self-extracting payload staged in a scanner-skipped location (AST08/AST01) ([#130](https://github.com/SVGreg/surfaceguard/issues/130)) ([d1cecec](https://github.com/SVGreg/surfaceguard/commit/d1cecece52ce90822f1695e8fb59fe30081b3e65))
* **rules:** add SG-EVA-003 — bundled image/PDF as an instruction carrier (AST08/AST01) ([#150](https://github.com/SVGreg/surfaceguard/issues/150)) ([0d9b2b5](https://github.com/SVGreg/surfaceguard/commit/0d9b2b52ceb311305056f5c67d728206a3ff4a25))
* **rules:** add SG-EXE-006 — dynamic-context command executed before the model sees the skill (AST01/AST03) ([#137](https://github.com/SVGreg/surfaceguard/issues/137)) ([7c43c6a](https://github.com/SVGreg/surfaceguard/commit/7c43c6a9eaf5f20252c2d23f8b17663f36b72f43))
* **rules:** add SG-MEM-003 — persisted state re-loaded to govern future behaviour (AST01/AST03) ([#153](https://github.com/SVGreg/surfaceguard/issues/153)) ([33c6985](https://github.com/SVGreg/surfaceguard/commit/33c6985512aaaa3c4e687bf73628de0b0807ef49))
* **rules:** add SG-REF-004 — external ruleset declared authoritative (AST05/AST01) ([#145](https://github.com/SVGreg/surfaceguard/issues/145)) ([4b657d7](https://github.com/SVGreg/surfaceguard/commit/4b657d733601e5f8fefc98f96a90240436502212))


### Bug Fixes

* **attest:** bound the attestation read — .skillsig was exempt from every size cap ([#139](https://github.com/SVGreg/surfaceguard/issues/139)) ([d80a300](https://github.com/SVGreg/surfaceguard/commit/d80a300c53ae5296c0aa2898d6925d8a3d498b40))
* **rules:** narrow SG-TRIG-001 — require an activation anchor, not just a universal noun ([#129](https://github.com/SVGreg/surfaceguard/issues/129)) ([3d5b428](https://github.com/SVGreg/surfaceguard/commit/3d5b428d5bb5cc3cc8153213d04ce0156b7ea212))
* **rules:** polish SG-INJ-010 — directive vs description, and unbreak its headline leaves ([#142](https://github.com/SVGreg/surfaceguard/issues/142)) ([f371663](https://github.com/SVGreg/surfaceguard/commit/f3716631b320010e5d2c818edff5de8f70e5c9cc))
* **rules:** polish SG-MTA-001 — widen the deserialization family, unbreak its own suppress ([#152](https://github.com/SVGreg/surfaceguard/issues/152)) ([e4ea726](https://github.com/SVGreg/surfaceguard/commit/e4ea7268081eed02c8dfefbadfcfac26af16e960))
* **rules:** SG-ANTI-001 no longer flags the MIT license as jailbreak framing ([#136](https://github.com/SVGreg/surfaceguard/issues/136)) ([6711d85](https://github.com/SVGreg/surfaceguard/commit/6711d8580d3e570767e8a38f48d57f9b94fba94d))
* **rules:** SG-MTA-003 sees bundled sub-agents, and its wildcard leaf works again ([#158](https://github.com/SVGreg/surfaceguard/issues/158)) ([2426116](https://github.com/SVGreg/surfaceguard/commit/24261165a5e52654c8e99ed0de5dada2adef4ebb))
* **verify:** a revoked key and an expired attestation now fail verification ([#151](https://github.com/SVGreg/surfaceguard/issues/151)) ([ccb06bb](https://github.com/SVGreg/surfaceguard/commit/ccb06bb6dce41ba1ab2c006aff1410347054b7a6))

## [0.1.16](https://github.com/SVGreg/surfaceguard/compare/v0.1.15...v0.1.16) (2026-08-04)


### Features

* **rules:** add SG-EVA-002 — encrypted / password-protected payload container (AST08/AST02) ([#122](https://github.com/SVGreg/surfaceguard/issues/122)) ([b2d396c](https://github.com/SVGreg/surfaceguard/commit/b2d396c7b1696e234753540a9ec1812763770352)), closes [#117](https://github.com/SVGreg/surfaceguard/issues/117)
* **rules:** add SG-INJ-011 — agent-relayed user command, "ClickFix 2.0" (AST01) ([#123](https://github.com/SVGreg/surfaceguard/issues/123)) ([40ebfab](https://github.com/SVGreg/surfaceguard/commit/40ebfab6a66943c816f5a2f2f3206f0c9c8f5649)), closes [#119](https://github.com/SVGreg/surfaceguard/issues/119)


### Bug Fixes

* **evaluation:** adjust parallelism handling in scripts and documentation ([3a44ce8](https://github.com/SVGreg/surfaceguard/commit/3a44ce8f976aec65626335d7550c29519222c5ae))
* **policy:** reject silent misconfiguration instead of loading it quietly ([#125](https://github.com/SVGreg/surfaceguard/issues/125)) ([329397d](https://github.com/SVGreg/surfaceguard/commit/329397d3534c9e5f29754b70d801068e0258690f)), closes [#124](https://github.com/SVGreg/surfaceguard/issues/124)

## [0.1.15](https://github.com/SVGreg/surfaceguard/compare/v0.1.14...v0.1.15) (2026-08-01)


### Features

* **rules:** add SG-REF-005 — self-ingested instructions (AST05/AST01) ([#112](https://github.com/SVGreg/surfaceguard/issues/112)) ([937a0f8](https://github.com/SVGreg/surfaceguard/commit/937a0f8ea6728a7ef00b31e3d16ffdaf1892bdf2))
* **rules:** shell-form overwrite of instruction files — SG-INJ-004 + SG-ROGUE-001 (AST01/AST03) ([#116](https://github.com/SVGreg/surfaceguard/issues/116)) ([3acccc0](https://github.com/SVGreg/surfaceguard/commit/3acccc06341fea31df8d8a4f380973221d6faa23))


### Bug Fixes

* **rules:** polish SG-ROGUE-001 — catch remote-fetch self-overwrite, drop authoring FPs ([#115](https://github.com/SVGreg/surfaceguard/issues/115)) ([c84fe8e](https://github.com/SVGreg/surfaceguard/commit/c84fe8e70d37ebd4e74a56e99f5e468b8841fa8a))
* **scan:** dedup skill-card external_refs and stop emitting null permissions ([#113](https://github.com/SVGreg/surfaceguard/issues/113)) ([e399fd8](https://github.com/SVGreg/surfaceguard/commit/e399fd83aac5b8dbdbad073e493668313bfd643d))

## [0.1.14](https://github.com/SVGreg/surfaceguard/compare/v0.1.13...v0.1.14) (2026-07-31)


### Features

* **rules:** add SG-INJ-007 — terminal/ANSI escape-sequence injection (AST01/AST08) ([#107](https://github.com/SVGreg/surfaceguard/issues/107)) ([89d0f3e](https://github.com/SVGreg/surfaceguard/commit/89d0f3e5d3ee5791d73c8906909901995a8dcea8))
* **skills:** sg-rule-polish audits real corpus false positives ([#101](https://github.com/SVGreg/surfaceguard/issues/101)) ([ac8b1b4](https://github.com/SVGreg/surfaceguard/commit/ac8b1b4ded81600e7849fb2b96b84e6057df86b5))


### Bug Fixes

* **rules:** widen and narrow SG-INJ-006 — extraction families + quoted-mention carve-out ([#104](https://github.com/SVGreg/surfaceguard/issues/104)) ([d09c6db](https://github.com/SVGreg/surfaceguard/commit/d09c6db15a9acd06331759d303e4b00d0a0da7bc))

## [0.1.13](https://github.com/SVGreg/surfaceguard/compare/v0.1.12...v0.1.13) (2026-07-29)


### Features

* **eval:** add SkillsMP + vendor-org corpus fetchers; consolidate clawhub ([#94](https://github.com/SVGreg/surfaceguard/issues/94)) ([3c8b54c](https://github.com/SVGreg/surfaceguard/commit/3c8b54c026958bf414479d8528f30b35f15a84cf))
* **eval:** interactive HTML report generator (report_html.py) ([#96](https://github.com/SVGreg/surfaceguard/issues/96)) ([7a9c1aa](https://github.com/SVGreg/surfaceguard/commit/7a9c1aaba63caf3c2446fce9b767d6e9f4c0903c))


### Bug Fixes

* **attest:** enforce key algorithm, accept empty front-matter, report real .pub mode ([#98](https://github.com/SVGreg/surfaceguard/issues/98)) ([5d6cc1f](https://github.com/SVGreg/surfaceguard/commit/5d6cc1f071d52f74486786a5c1a0cefa485ef688))
* **rules:** SG-EXE-002 — only flag broad-target wipes, not variable cleanup ([#97](https://github.com/SVGreg/surfaceguard/issues/97)) ([036e0df](https://github.com/SVGreg/surfaceguard/commit/036e0dfa6e02d07b9c1ed95451651dfbbd9ca2d1))
* **scan:** scan bundled reference docs — payload in references/*.md no longer passes ([#99](https://github.com/SVGreg/surfaceguard/issues/99)) ([e1b8b78](https://github.com/SVGreg/surfaceguard/commit/e1b8b78b04878be6609de1c68d8dae556de74821))
* **skill:** cap total bytes loaded per bundle, not just per file ([#100](https://github.com/SVGreg/surfaceguard/issues/100)) ([b3f113b](https://github.com/SVGreg/surfaceguard/commit/b3f113bac34a878042a2c0403e63382d849c2546))

## [0.1.12](https://github.com/SVGreg/surfaceguard/compare/v0.1.11...v0.1.12) (2026-07-28)


### Features

* **rules:** add SG-STEER-001 — behavioral steering / bias injection (AST01) ([#91](https://github.com/SVGreg/surfaceguard/issues/91)) ([354aebe](https://github.com/SVGreg/surfaceguard/commit/354aebe82e1a8a999d8e6392d7ffaf8d88744569))


### Bug Fixes

* **rules:** normalize URL authority in scanURLHost + rune-safe truncate ([#92](https://github.com/SVGreg/surfaceguard/issues/92)) ([a265038](https://github.com/SVGreg/surfaceguard/commit/a265038420afcca279ed08eae7bfc0dcf8ca909e))

## [0.1.11](https://github.com/SVGreg/surfaceguard/compare/v0.1.10...v0.1.11) (2026-07-28)


### Features

* **rules:** add SG-DEP-010 — install-lifecycle hook runs a command (AST02/AST01) ([#76](https://github.com/SVGreg/surfaceguard/issues/76)) ([21bf291](https://github.com/SVGreg/surfaceguard/commit/21bf291775e2f30e5cfeccc924d339be834fea9d))
* **rules:** add SG-DEP-011 — fetches a binary/blob and marks it executable (AST02/AST01) ([#75](https://github.com/SVGreg/surfaceguard/issues/75)) ([a9dd4f7](https://github.com/SVGreg/surfaceguard/commit/a9dd4f7594ccd638ff4da05fbfd8cc76f3b77ce1))
* **rules:** add SG-INJ-008 — conditional / time-bomb instruction (AST01) ([#81](https://github.com/SVGreg/surfaceguard/issues/81)) ([2a18b6a](https://github.com/SVGreg/surfaceguard/commit/2a18b6a5fe6a2c79261e626a4219d1e781752605))
* **rules:** add SG-INJ-010 — concealment / secrecy directive (AST01) ([#84](https://github.com/SVGreg/surfaceguard/issues/84)) ([3639772](https://github.com/SVGreg/surfaceguard/commit/3639772e2008fe15d1ac9816842696d2688b2c8b))
* **rules:** add SG-NET-008 — disabled TLS / certificate verification (AST01/AST06) ([#74](https://github.com/SVGreg/surfaceguard/issues/74)) ([976245c](https://github.com/SVGreg/surfaceguard/commit/976245c7ee9da543da8ee006287e22f7975da9a5))
* **rules:** add SG-TRIG-001 — over-broad activation trigger (AST04) ([#87](https://github.com/SVGreg/surfaceguard/issues/87)) ([3de0c28](https://github.com/SVGreg/surfaceguard/commit/3de0c28629ff08025b1c3186d0384e32479f6c8c))


### Bug Fixes

* **cmd:** quote filesystem paths in output to neutralize terminal injection ([#78](https://github.com/SVGreg/surfaceguard/issues/78)) ([8bd5ff5](https://github.com/SVGreg/surfaceguard/commit/8bd5ff576f28770e2f332d11cca08cfb334e1a1a))
* **rules:** make the documentary/code-example penalties prose-only ([#79](https://github.com/SVGreg/surfaceguard/issues/79)) ([90b79ad](https://github.com/SVGreg/surfaceguard/commit/90b79ada87cdde0e44a3c27478d19dea3c43ab0e))
* **rules:** widen SG-EXE-002 to cover non-rm-rf destructive ops ([#86](https://github.com/SVGreg/surfaceguard/issues/86)) ([970e438](https://github.com/SVGreg/surfaceguard/commit/970e438701ca6783bd353f604fb7f502c7a2e2c9))
* **rules:** widen SG-NET-002 to cover non-pipe fetch-exec forms ([#80](https://github.com/SVGreg/surfaceguard/issues/80)) ([3969663](https://github.com/SVGreg/surfaceguard/commit/396966380ac959d9404adc019bb8cb69878efd37))
* **skill:** classify extensionless perl/php scripts and label shebang language ([#85](https://github.com/SVGreg/surfaceguard/issues/85)) ([75dea6f](https://github.com/SVGreg/surfaceguard/commit/75dea6fa774d72c585ef15cdaf9ba4f68d3dd9d5))

## [0.1.10](https://github.com/SVGreg/surfaceguard/compare/v0.1.9...v0.1.10) (2026-07-26)


### Features

* **rules:** add SG-DEP-008 — install redirected to a non-default registry (AST02/AST07) ([#59](https://github.com/SVGreg/surfaceguard/issues/59)) ([2fe8177](https://github.com/SVGreg/surfaceguard/commit/2fe8177f671c308cce93561628efadec33f830f3))
* **rules:** add SG-DEP-009 — dependency from a raw VCS URL or bare archive (AST02/AST07) ([#67](https://github.com/SVGreg/surfaceguard/issues/67)) ([2af3632](https://github.com/SVGreg/surfaceguard/commit/2af36322192f9777b22edae9b6947580a1aa5b3e))
* **rules:** add SG-INJ-009 — role confusion / forged operator turn (AST01) ([#70](https://github.com/SVGreg/surfaceguard/issues/70)) ([bce68b0](https://github.com/SVGreg/surfaceguard/commit/bce68b0f662a10c9d59c743f6dfc12e55c5f8d22))
* **rules:** add SG-MCP-001 — MCP tool-description poisoning (AST04/AST01) ([#58](https://github.com/SVGreg/surfaceguard/issues/58)) ([36d0173](https://github.com/SVGreg/surfaceguard/commit/36d01737371fcd87b12d59acf3e484f94be49d55))
* **rules:** add SG-MTA-004 — over-broad filesystem permission scope (AST03) ([#71](https://github.com/SVGreg/surfaceguard/issues/71)) ([7ed404f](https://github.com/SVGreg/surfaceguard/commit/7ed404f6c90bc509a1acd23e216ee1e578e42dc4))
* **rules:** add SG-NET-005 — DNS exfiltration / hardcoded IP endpoint (AST01/AST06) ([#62](https://github.com/SVGreg/surfaceguard/issues/62)) ([26b569a](https://github.com/SVGreg/surfaceguard/commit/26b569a031eab11f9233b6ded8d1bbc2e99208d3))
* **rules:** add SG-SEC-005 — instruction to attach a credential to an outbound request (AST03/AST01) ([#66](https://github.com/SVGreg/surfaceguard/issues/66)) ([f833c33](https://github.com/SVGreg/surfaceguard/commit/f833c33a97c11fa1a9b8a85ecb562faa8d07af55))


### Bug Fixes

* **report:** escape terminal control characters in the text report ([#68](https://github.com/SVGreg/surfaceguard/issues/68)) ([dacd91d](https://github.com/SVGreg/surfaceguard/commit/dacd91d080e797c538386288346dc94dd4ac8549))
* **rules:** widen SG-CFG-001 to YAML and TOML hook configs ([#61](https://github.com/SVGreg/surfaceguard/issues/61)) ([1ec654b](https://github.com/SVGreg/surfaceguard/commit/1ec654bab258f6db4703a003d0cb34d14483f43a))
* **verify:** neutralize forged verdict lines and fail closed on unreadable expiry ([#60](https://github.com/SVGreg/surfaceguard/issues/60)) ([d8fa7ef](https://github.com/SVGreg/surfaceguard/commit/d8fa7efde0a2d2480ccd8b0187607930447dea59))

## [0.1.9](https://github.com/SVGreg/surfaceguard/compare/v0.1.8...v0.1.9) (2026-07-25)


### Features

* **rules:** add SG-CFG-001 — bundled agent-hook config auto-execution (AST02/AST01) ([#52](https://github.com/SVGreg/surfaceguard/issues/52)) ([9148bbb](https://github.com/SVGreg/surfaceguard/commit/9148bbb267bc028ad44837acaa4024d71876cbff))
* **rules:** add SG-DEP-001 — unpinned/floating dependency (AST02/AST07) ([#43](https://github.com/SVGreg/surfaceguard/issues/43)) ([f532100](https://github.com/SVGreg/surfaceguard/commit/f532100c5da7e66d84ad548e4557747eb19a22b5))
* **rules:** add SG-MEM-001 — persistent context / memory poisoning (AST01/AST03) ([#53](https://github.com/SVGreg/surfaceguard/issues/53)) ([bdf30de](https://github.com/SVGreg/surfaceguard/commit/bdf30deb13a4944b9ae80a5bdbf41e5a2ccf9dc0))


### Bug Fixes

* **attest:** force mode 0600 on private keys and bind the DSSE payload type ([#46](https://github.com/SVGreg/surfaceguard/issues/46)) ([a96f7d0](https://github.com/SVGreg/surfaceguard/commit/a96f7d002a477df1b7d6631b49098076eb10d5b4))
* **rules:** widen SG-AS-001 to real agent-config read idioms ([#51](https://github.com/SVGreg/surfaceguard/issues/51)) ([54ac099](https://github.com/SVGreg/surfaceguard/commit/54ac0991a54fdff28f2f4fc793b9bcc1ce5eb35c))

## [0.1.8](https://github.com/SVGreg/surfaceguard/compare/v0.1.7...v0.1.8) (2026-07-25)


### Features

* **rules:** add SG-DEP-007 — remote-package auto-execution via a runner (AST02) ([#33](https://github.com/SVGreg/surfaceguard/issues/33)) ([6edd78b](https://github.com/SVGreg/surfaceguard/commit/6edd78b86c55c1aea31c8a058e3752a5a191adf8))


### Bug Fixes

* **policy:** fail closed when a waiver's expiry date is malformed ([#38](https://github.com/SVGreg/surfaceguard/issues/38)) ([62876e1](https://github.com/SVGreg/surfaceguard/commit/62876e1aa38096fc6b7e8d33a88f3436fedd5981))
* **rules:** polish SG-SEC-001 — more credential files + exfil verbs ([#27](https://github.com/SVGreg/surfaceguard/issues/27)) ([1125da4](https://github.com/SVGreg/surfaceguard/commit/1125da45a47978f70772c973937414d8f7f8e428))
* **rules:** widen SG-ANTI-001 to cover more jailbreak framings ([#39](https://github.com/SVGreg/surfaceguard/issues/39)) ([181791f](https://github.com/SVGreg/surfaceguard/commit/181791f6a68e0e1786af9d57e421815413eb5619))
* **rules:** widen SG-SEC-003 to real env-harvest variants; fix printenv FP ([#35](https://github.com/SVGreg/surfaceguard/issues/35)) ([756d6be](https://github.com/SVGreg/surfaceguard/commit/756d6be3caae0cf9e2cfbf238253eab37b93ee2e))
* **scan:** use a struct dedup key so '|' in a path or rule id can't collide ([#34](https://github.com/SVGreg/surfaceguard/issues/34)) ([8773613](https://github.com/SVGreg/surfaceguard/commit/87736130460254e7dfbbe3aa6f750ad02b8e46ab))

## [0.1.7](https://github.com/SVGreg/surfaceguard/compare/v0.1.6...v0.1.7) (2026-07-24)


### Bug Fixes

* **rules:** per-line dedup keeps the highest-confidence match ([#25](https://github.com/SVGreg/surfaceguard/issues/25)) ([1695f62](https://github.com/SVGreg/surfaceguard/commit/1695f62889c92ed42ca972a18953490a879b8e44))

## [0.1.6](https://github.com/SVGreg/surfaceguard/compare/v0.1.5...v0.1.6) (2026-07-24)


### Features

* **rules:** add SG-REF-003 — runtime instruction fetch (external brain) (AST05) ([#20](https://github.com/SVGreg/surfaceguard/issues/20)) ([5b95072](https://github.com/SVGreg/surfaceguard/commit/5b95072cf8ac828ab8a0e8a1536cbfbe83f34172))


### Bug Fixes

* **rules:** widen SG-INJ-001 to cover more instruction-override families ([#16](https://github.com/SVGreg/surfaceguard/issues/16)) ([c432051](https://github.com/SVGreg/surfaceguard/commit/c432051e47911d6a7d5f885673d600923506cafd))

## [0.1.5](https://github.com/SVGreg/surfaceguard/compare/v0.1.4...v0.1.5) (2026-07-23)


### Features

* **evaluation:** add scripts for fetching and scanning ClawHub skills ([#10](https://github.com/SVGreg/surfaceguard/issues/10)) ([6f921df](https://github.com/SVGreg/surfaceguard/commit/6f921df095e65e0d46b090b03b748e7f8b2d8b27))
* **rules:** SG-NET-007 — rendered-image/link data exfiltration ([#9](https://github.com/SVGreg/surfaceguard/issues/9)) ([0cec31b](https://github.com/SVGreg/surfaceguard/commit/0cec31b1342eea5f39efabded15e84bb3bac13a7))


### Bug Fixes

* **skill:** apply symlink and size-cap guards to single-file mode ([#12](https://github.com/SVGreg/surfaceguard/issues/12)) ([a0b0081](https://github.com/SVGreg/surfaceguard/commit/a0b0081574048bebc94ce7b6528813bc518966d5))

## [0.1.4](https://github.com/SVGreg/surfaceguard/compare/v0.1.3...v0.1.4) (2026-07-22)


### Features

* add maintenance skills and update .gitignore for runtime state ([9a5be1f](https://github.com/SVGreg/surfaceguard/commit/9a5be1f9a3a555b8e2a059dbc4c83d9f42c64152))

## [0.1.3](https://github.com/SVGreg/surfaceguard/compare/v0.1.2...v0.1.3) (2026-07-22)


### Bug Fixes

* **rules:** widen SG-NET-006 to cover more reverse-shell families ([#4](https://github.com/SVGreg/surfaceguard/issues/4)) ([70802ce](https://github.com/SVGreg/surfaceguard/commit/70802ce9b672e0a3bb2790fc89981a71900e1ae7))

## [0.1.2](https://github.com/SVGreg/surfaceguard/compare/v0.1.1...v0.1.2) (2026-07-20)


### Features

* **hooks:** add surfaceguard PreToolUse hook for Claude Code ([9490186](https://github.com/SVGreg/surfaceguard/commit/94901860a073ccf5398132361f25524d01de17d5))

## [0.1.1](https://github.com/SVGreg/surfaceguard/compare/v0.1.0...v0.1.1) (2026-07-19)


### Features

* add SKILL.md.skillsig for attestation payload and signatures ([1f9bd9f](https://github.com/SVGreg/surfaceguard/commit/1f9bd9fc9e368c678560db2c357d6c008fa1c651))

## 0.1.0 (2026-07-19)


### Features

* add binary release pipeline, install script, and release skill ([34e861b](https://github.com/SVGreg/surfaceguard/commit/34e861bb83789fd1a8425dc15ceb126894e5afce))
* **cli:** friendlier errors and richer help ([875f251](https://github.com/SVGreg/surfaceguard/commit/875f251948e14666bfd21c96b14515e11fc24033))
* **config:** add initial trust roster configuration with public key details ([54ce4df](https://github.com/SVGreg/surfaceguard/commit/54ce4df483cf12be4a8de4c53dfd03f6dce8a193))
* **docs:** add CLAUDE.md for project guidance and usage instructions ([4ca01a2](https://github.com/SVGreg/surfaceguard/commit/4ca01a281cf69cdbab85831775da304843306d82))
* **keygen:** also write a public-only &lt;name&gt;.pub companion ([c14f278](https://github.com/SVGreg/surfaceguard/commit/c14f278f2f85633eb0c3032cfc1e1f420fc7a884))
* M1+M2 scan/sign/verify core (first runnable version) ([ccc183f](https://github.com/SVGreg/surfaceguard/commit/ccc183ff15fe9e147c4426bbd3ee5eb2638e18f1))
* **report:** cite the corresponding OWASP AST risk per finding ([b82cc32](https://github.com/SVGreg/surfaceguard/commit/b82cc321be589c03f24fae66c7122a3d5c5bcee3))
* **rules:** enhance core-injection and core-secret rules with additional regex patterns for better instruction and credential handling ([f3e4094](https://github.com/SVGreg/surfaceguard/commit/f3e4094c5d03fdd53322a188c5b9662ca0d299b1))


### Bug Fixes

* **rules:** reconcile rule→OWASP AST mappings against the Top 10 ([a3bea53](https://github.com/SVGreg/surfaceguard/commit/a3bea5318847f1b93e3bb1b945ec06bbacdb1ff2))
* **scan:** report true file line numbers for SKILL.md findings ([c408aaf](https://github.com/SVGreg/surfaceguard/commit/c408aaf656c56f96b3feed11e11d5413549b004f))
* update API version from surfaceguard.dev to surfaceguard.net across multiple files ([e3201e4](https://github.com/SVGreg/surfaceguard/commit/e3201e493da744e29cf90483707b26c8a6284ab0))
