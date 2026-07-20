# Changelog

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
