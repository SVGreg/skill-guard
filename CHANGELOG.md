# Changelog

## [0.1.11](https://github.com/SVGreg/skill-guard/compare/v0.1.10...v0.1.11) (2026-07-28)


### Features

* **rules:** add SG-DEP-010 — install-lifecycle hook runs a command (AST02/AST01) ([#76](https://github.com/SVGreg/skill-guard/issues/76)) ([21bf291](https://github.com/SVGreg/skill-guard/commit/21bf291775e2f30e5cfeccc924d339be834fea9d))
* **rules:** add SG-DEP-011 — fetches a binary/blob and marks it executable (AST02/AST01) ([#75](https://github.com/SVGreg/skill-guard/issues/75)) ([a9dd4f7](https://github.com/SVGreg/skill-guard/commit/a9dd4f7594ccd638ff4da05fbfd8cc76f3b77ce1))
* **rules:** add SG-INJ-008 — conditional / time-bomb instruction (AST01) ([#81](https://github.com/SVGreg/skill-guard/issues/81)) ([2a18b6a](https://github.com/SVGreg/skill-guard/commit/2a18b6a5fe6a2c79261e626a4219d1e781752605))
* **rules:** add SG-INJ-010 — concealment / secrecy directive (AST01) ([#84](https://github.com/SVGreg/skill-guard/issues/84)) ([3639772](https://github.com/SVGreg/skill-guard/commit/3639772e2008fe15d1ac9816842696d2688b2c8b))
* **rules:** add SG-NET-008 — disabled TLS / certificate verification (AST01/AST06) ([#74](https://github.com/SVGreg/skill-guard/issues/74)) ([976245c](https://github.com/SVGreg/skill-guard/commit/976245c7ee9da543da8ee006287e22f7975da9a5))
* **rules:** add SG-TRIG-001 — over-broad activation trigger (AST04) ([#87](https://github.com/SVGreg/skill-guard/issues/87)) ([3de0c28](https://github.com/SVGreg/skill-guard/commit/3de0c28629ff08025b1c3186d0384e32479f6c8c))


### Bug Fixes

* **cmd:** quote filesystem paths in output to neutralize terminal injection ([#78](https://github.com/SVGreg/skill-guard/issues/78)) ([8bd5ff5](https://github.com/SVGreg/skill-guard/commit/8bd5ff576f28770e2f332d11cca08cfb334e1a1a))
* **rules:** make the documentary/code-example penalties prose-only ([#79](https://github.com/SVGreg/skill-guard/issues/79)) ([90b79ad](https://github.com/SVGreg/skill-guard/commit/90b79ada87cdde0e44a3c27478d19dea3c43ab0e))
* **rules:** widen SG-EXE-002 to cover non-rm-rf destructive ops ([#86](https://github.com/SVGreg/skill-guard/issues/86)) ([970e438](https://github.com/SVGreg/skill-guard/commit/970e438701ca6783bd353f604fb7f502c7a2e2c9))
* **rules:** widen SG-NET-002 to cover non-pipe fetch-exec forms ([#80](https://github.com/SVGreg/skill-guard/issues/80)) ([3969663](https://github.com/SVGreg/skill-guard/commit/396966380ac959d9404adc019bb8cb69878efd37))
* **skill:** classify extensionless perl/php scripts and label shebang language ([#85](https://github.com/SVGreg/skill-guard/issues/85)) ([75dea6f](https://github.com/SVGreg/skill-guard/commit/75dea6fa774d72c585ef15cdaf9ba4f68d3dd9d5))

## [0.1.10](https://github.com/SVGreg/skill-guard/compare/v0.1.9...v0.1.10) (2026-07-26)


### Features

* **rules:** add SG-DEP-008 — install redirected to a non-default registry (AST02/AST07) ([#59](https://github.com/SVGreg/skill-guard/issues/59)) ([2fe8177](https://github.com/SVGreg/skill-guard/commit/2fe8177f671c308cce93561628efadec33f830f3))
* **rules:** add SG-DEP-009 — dependency from a raw VCS URL or bare archive (AST02/AST07) ([#67](https://github.com/SVGreg/skill-guard/issues/67)) ([2af3632](https://github.com/SVGreg/skill-guard/commit/2af36322192f9777b22edae9b6947580a1aa5b3e))
* **rules:** add SG-INJ-009 — role confusion / forged operator turn (AST01) ([#70](https://github.com/SVGreg/skill-guard/issues/70)) ([bce68b0](https://github.com/SVGreg/skill-guard/commit/bce68b0f662a10c9d59c743f6dfc12e55c5f8d22))
* **rules:** add SG-MCP-001 — MCP tool-description poisoning (AST04/AST01) ([#58](https://github.com/SVGreg/skill-guard/issues/58)) ([36d0173](https://github.com/SVGreg/skill-guard/commit/36d01737371fcd87b12d59acf3e484f94be49d55))
* **rules:** add SG-MTA-004 — over-broad filesystem permission scope (AST03) ([#71](https://github.com/SVGreg/skill-guard/issues/71)) ([7ed404f](https://github.com/SVGreg/skill-guard/commit/7ed404f6c90bc509a1acd23e216ee1e578e42dc4))
* **rules:** add SG-NET-005 — DNS exfiltration / hardcoded IP endpoint (AST01/AST06) ([#62](https://github.com/SVGreg/skill-guard/issues/62)) ([26b569a](https://github.com/SVGreg/skill-guard/commit/26b569a031eab11f9233b6ded8d1bbc2e99208d3))
* **rules:** add SG-SEC-005 — instruction to attach a credential to an outbound request (AST03/AST01) ([#66](https://github.com/SVGreg/skill-guard/issues/66)) ([f833c33](https://github.com/SVGreg/skill-guard/commit/f833c33a97c11fa1a9b8a85ecb562faa8d07af55))


### Bug Fixes

* **report:** escape terminal control characters in the text report ([#68](https://github.com/SVGreg/skill-guard/issues/68)) ([dacd91d](https://github.com/SVGreg/skill-guard/commit/dacd91d080e797c538386288346dc94dd4ac8549))
* **rules:** widen SG-CFG-001 to YAML and TOML hook configs ([#61](https://github.com/SVGreg/skill-guard/issues/61)) ([1ec654b](https://github.com/SVGreg/skill-guard/commit/1ec654bab258f6db4703a003d0cb34d14483f43a))
* **verify:** neutralize forged verdict lines and fail closed on unreadable expiry ([#60](https://github.com/SVGreg/skill-guard/issues/60)) ([d8fa7ef](https://github.com/SVGreg/skill-guard/commit/d8fa7efde0a2d2480ccd8b0187607930447dea59))

## [0.1.9](https://github.com/SVGreg/skill-guard/compare/v0.1.8...v0.1.9) (2026-07-25)


### Features

* **rules:** add SG-CFG-001 — bundled agent-hook config auto-execution (AST02/AST01) ([#52](https://github.com/SVGreg/skill-guard/issues/52)) ([9148bbb](https://github.com/SVGreg/skill-guard/commit/9148bbb267bc028ad44837acaa4024d71876cbff))
* **rules:** add SG-DEP-001 — unpinned/floating dependency (AST02/AST07) ([#43](https://github.com/SVGreg/skill-guard/issues/43)) ([f532100](https://github.com/SVGreg/skill-guard/commit/f532100c5da7e66d84ad548e4557747eb19a22b5))
* **rules:** add SG-MEM-001 — persistent context / memory poisoning (AST01/AST03) ([#53](https://github.com/SVGreg/skill-guard/issues/53)) ([bdf30de](https://github.com/SVGreg/skill-guard/commit/bdf30deb13a4944b9ae80a5bdbf41e5a2ccf9dc0))


### Bug Fixes

* **attest:** force mode 0600 on private keys and bind the DSSE payload type ([#46](https://github.com/SVGreg/skill-guard/issues/46)) ([a96f7d0](https://github.com/SVGreg/skill-guard/commit/a96f7d002a477df1b7d6631b49098076eb10d5b4))
* **rules:** widen SG-AS-001 to real agent-config read idioms ([#51](https://github.com/SVGreg/skill-guard/issues/51)) ([54ac099](https://github.com/SVGreg/skill-guard/commit/54ac0991a54fdff28f2f4fc793b9bcc1ce5eb35c))

## [0.1.8](https://github.com/SVGreg/skill-guard/compare/v0.1.7...v0.1.8) (2026-07-25)


### Features

* **rules:** add SG-DEP-007 — remote-package auto-execution via a runner (AST02) ([#33](https://github.com/SVGreg/skill-guard/issues/33)) ([6edd78b](https://github.com/SVGreg/skill-guard/commit/6edd78b86c55c1aea31c8a058e3752a5a191adf8))


### Bug Fixes

* **policy:** fail closed when a waiver's expiry date is malformed ([#38](https://github.com/SVGreg/skill-guard/issues/38)) ([62876e1](https://github.com/SVGreg/skill-guard/commit/62876e1aa38096fc6b7e8d33a88f3436fedd5981))
* **rules:** polish SG-SEC-001 — more credential files + exfil verbs ([#27](https://github.com/SVGreg/skill-guard/issues/27)) ([1125da4](https://github.com/SVGreg/skill-guard/commit/1125da45a47978f70772c973937414d8f7f8e428))
* **rules:** widen SG-ANTI-001 to cover more jailbreak framings ([#39](https://github.com/SVGreg/skill-guard/issues/39)) ([181791f](https://github.com/SVGreg/skill-guard/commit/181791f6a68e0e1786af9d57e421815413eb5619))
* **rules:** widen SG-SEC-003 to real env-harvest variants; fix printenv FP ([#35](https://github.com/SVGreg/skill-guard/issues/35)) ([756d6be](https://github.com/SVGreg/skill-guard/commit/756d6be3caae0cf9e2cfbf238253eab37b93ee2e))
* **scan:** use a struct dedup key so '|' in a path or rule id can't collide ([#34](https://github.com/SVGreg/skill-guard/issues/34)) ([8773613](https://github.com/SVGreg/skill-guard/commit/87736130460254e7dfbbe3aa6f750ad02b8e46ab))

## [0.1.7](https://github.com/SVGreg/skill-guard/compare/v0.1.6...v0.1.7) (2026-07-24)


### Bug Fixes

* **rules:** per-line dedup keeps the highest-confidence match ([#25](https://github.com/SVGreg/skill-guard/issues/25)) ([1695f62](https://github.com/SVGreg/skill-guard/commit/1695f62889c92ed42ca972a18953490a879b8e44))

## [0.1.6](https://github.com/SVGreg/skill-guard/compare/v0.1.5...v0.1.6) (2026-07-24)


### Features

* **rules:** add SG-REF-003 — runtime instruction fetch (external brain) (AST05) ([#20](https://github.com/SVGreg/skill-guard/issues/20)) ([5b95072](https://github.com/SVGreg/skill-guard/commit/5b95072cf8ac828ab8a0e8a1536cbfbe83f34172))


### Bug Fixes

* **rules:** widen SG-INJ-001 to cover more instruction-override families ([#16](https://github.com/SVGreg/skill-guard/issues/16)) ([c432051](https://github.com/SVGreg/skill-guard/commit/c432051e47911d6a7d5f885673d600923506cafd))

## [0.1.5](https://github.com/SVGreg/skill-guard/compare/v0.1.4...v0.1.5) (2026-07-23)


### Features

* **evaluation:** add scripts for fetching and scanning ClawHub skills ([#10](https://github.com/SVGreg/skill-guard/issues/10)) ([6f921df](https://github.com/SVGreg/skill-guard/commit/6f921df095e65e0d46b090b03b748e7f8b2d8b27))
* **rules:** SG-NET-007 — rendered-image/link data exfiltration ([#9](https://github.com/SVGreg/skill-guard/issues/9)) ([0cec31b](https://github.com/SVGreg/skill-guard/commit/0cec31b1342eea5f39efabded15e84bb3bac13a7))


### Bug Fixes

* **skill:** apply symlink and size-cap guards to single-file mode ([#12](https://github.com/SVGreg/skill-guard/issues/12)) ([a0b0081](https://github.com/SVGreg/skill-guard/commit/a0b0081574048bebc94ce7b6528813bc518966d5))

## [0.1.4](https://github.com/SVGreg/skill-guard/compare/v0.1.3...v0.1.4) (2026-07-22)


### Features

* add maintenance skills and update .gitignore for runtime state ([9a5be1f](https://github.com/SVGreg/skill-guard/commit/9a5be1f9a3a555b8e2a059dbc4c83d9f42c64152))

## [0.1.3](https://github.com/SVGreg/skill-guard/compare/v0.1.2...v0.1.3) (2026-07-22)


### Bug Fixes

* **rules:** widen SG-NET-006 to cover more reverse-shell families ([#4](https://github.com/SVGreg/skill-guard/issues/4)) ([70802ce](https://github.com/SVGreg/skill-guard/commit/70802ce9b672e0a3bb2790fc89981a71900e1ae7))

## [0.1.2](https://github.com/SVGreg/skill-guard/compare/v0.1.1...v0.1.2) (2026-07-20)


### Features

* **hooks:** add skill-guard PreToolUse hook for Claude Code ([9490186](https://github.com/SVGreg/skill-guard/commit/94901860a073ccf5398132361f25524d01de17d5))

## [0.1.1](https://github.com/SVGreg/skill-guard/compare/v0.1.0...v0.1.1) (2026-07-19)


### Features

* add SKILL.md.skillsig for attestation payload and signatures ([1f9bd9f](https://github.com/SVGreg/skill-guard/commit/1f9bd9fc9e368c678560db2c357d6c008fa1c651))

## 0.1.0 (2026-07-19)


### Features

* add binary release pipeline, install script, and release skill ([34e861b](https://github.com/SVGreg/skill-guard/commit/34e861bb83789fd1a8425dc15ceb126894e5afce))
* **cli:** friendlier errors and richer help ([875f251](https://github.com/SVGreg/skill-guard/commit/875f251948e14666bfd21c96b14515e11fc24033))
* **config:** add initial trust roster configuration with public key details ([54ce4df](https://github.com/SVGreg/skill-guard/commit/54ce4df483cf12be4a8de4c53dfd03f6dce8a193))
* **docs:** add CLAUDE.md for project guidance and usage instructions ([4ca01a2](https://github.com/SVGreg/skill-guard/commit/4ca01a281cf69cdbab85831775da304843306d82))
* **keygen:** also write a public-only &lt;name&gt;.pub companion ([c14f278](https://github.com/SVGreg/skill-guard/commit/c14f278f2f85633eb0c3032cfc1e1f420fc7a884))
* M1+M2 scan/sign/verify core (first runnable version) ([ccc183f](https://github.com/SVGreg/skill-guard/commit/ccc183ff15fe9e147c4426bbd3ee5eb2638e18f1))
* **report:** cite the corresponding OWASP AST risk per finding ([b82cc32](https://github.com/SVGreg/skill-guard/commit/b82cc321be589c03f24fae66c7122a3d5c5bcee3))
* **rules:** enhance core-injection and core-secret rules with additional regex patterns for better instruction and credential handling ([f3e4094](https://github.com/SVGreg/skill-guard/commit/f3e4094c5d03fdd53322a188c5b9662ca0d299b1))


### Bug Fixes

* **rules:** reconcile rule→OWASP AST mappings against the Top 10 ([a3bea53](https://github.com/SVGreg/skill-guard/commit/a3bea5318847f1b93e3bb1b945ec06bbacdb1ff2))
* **scan:** report true file line numbers for SKILL.md findings ([c408aaf](https://github.com/SVGreg/skill-guard/commit/c408aaf656c56f96b3feed11e11d5413549b004f))
* update API version from skillguard.dev to skillguard.net across multiple files ([e3201e4](https://github.com/SVGreg/skill-guard/commit/e3201e493da744e29cf90483707b26c8a6284ab0))
