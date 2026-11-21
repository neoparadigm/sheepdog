# Governance

* **Maintainers** merge changes, cut releases and handle security reports (`CODEOWNERS`).
* **Decisions** are made by lazy consensus on pull requests. A change that touches an invariant in
  `docs/threat-model.md`, a pack's deny rules, the log format or the policy schema needs an ADR in
  `docs/adr/` and two maintainer approvals.
* **Becoming a maintainer:** sustained, reviewed contributions and an invitation from existing
  maintainers (a majority vote). Maintainers who are inactive for 12 months become emeritus.
* **Releases** follow semantic versioning. Policy-affecting changes (new default deny/ask rules,
  new packs on by default) are listed under *Changed* in `CHANGELOG.md` because they change the
  policy hash.
* **The name** `sheepdogai`/`sheepdogai` is a placeholder (see README); a rename is a maintainer
  decision recorded in an ADR.
* **Conflicts of interest and conduct** follow `CODE_OF_CONDUCT.md`.
