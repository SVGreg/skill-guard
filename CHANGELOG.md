# Changelog

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
