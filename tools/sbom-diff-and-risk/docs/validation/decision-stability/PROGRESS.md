# Decision stability qualification progress

Status: **BLOCKED / AUDIT_PENDING**. Both C02 and C03 are approved and repaired.
The local candidate is uncommitted; no public actions occurred.

- Final semantic tree: `0760a5543df366f3a8237c60a187cde7f3aae0b0`.
- Windows CPython 3.12: 817 passed for each existing seed 103/117/120.
- Native Linux CPython 3.11.17 on ext4: 817 passed, plus targeted rerun.
- 72 literal policy microcases; 55 transitions: 25 STABLE, 23 JUSTIFIED_REVERSAL,
  7 INVALID_INPUT, zero unresolved contract decisions. Seeds do not multiply cases.
- N01-N14 reached/detected every round; golden checks passed; network attempts zero.
- Changed-file Ruff passed. Full Ruff output exactly matches baseline F821.
- Four protected repositories preserved; only candidate branch/worktree additions.
- Fresh independent production/oracle reviewers executed 105/129 tests and probes
  on the first C03 repair. The production reviewer found missing index preflight;
  it was reproduced and corrected, then the final candidate requalified.
- Reviewer infrastructure failed again. The exact final patch and a self-contained
  private evidence package are retained for final review. No final audit approval.

Earlier 473/776/786-test results remain historical receipts, not final-source proof.
Raw logs, source archives and machine paths remain outside the source checkout.
