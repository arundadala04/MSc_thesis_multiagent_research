"""Run the Arm A baseline over the seed dependency CVEs and report how it behaves.

For each CVE the baseline retrieves grounding from the knowledge base, generates a patch
and verifies it on the four checks, then a confidence score routes it to auto or review.
We report the proposed version, whether it reaches the fix and whether it installs, so the
baseline's behaviour is visible before any reflection loop is added.

Run:  python run_baseline.py
Needs the Azure key in .env, plus Docker for the install test.
"""
from devsecagent import arm_a, dataset, deployer, kb
from devsecagent.retriever import Retriever
from devsecagent.versions import at_least


def main():
    retriever = Retriever(kb.documents())
    cases = dataset.load()
    auto = correct = installs = resolved = 0

    print(f"{'CVE':18s} {'package':12s} {'->version':11s} {'conf':>5s} "
          f"{'route':8s} {'fix?':5s} {'installs?':9s}")
    print("-" * 80)
    for case in cases:
        f = case.finding
        grounding = "\n".join(retriever.search(f"{f.cve} {f.package} {f.severity}"))
        patch = arm_a.run(f, grounding)
        reaches_fix = at_least(patch.to_version, case.true_fix)
        can_install, _ = deployer.installable(f.package, patch.to_version)
        is_auto = patch.decision == "auto"

        auto += is_auto
        correct += reaches_fix
        installs += can_install
        resolved += is_auto and reaches_fix and can_install
        print(f"{f.cve:18s} {f.package:12s} {patch.to_version:11s} {patch.confidence:5.2f} "
              f"{patch.decision:8s} {'yes' if reaches_fix else 'no':5s} "
              f"{'yes' if can_install else 'no':9s}")

    n = len(cases)
    print("-" * 80)
    print(f"\nArm A baseline over {n} dependency CVEs:")
    print(f"  auto-approved (no human)            : {auto}/{n} = {auto / n:.0%}")
    print(f"  reaches the fixed version           : {correct}/{n} = {correct / n:.0%}")
    print(f"  proposed version installs           : {installs}/{n} = {installs / n:.0%}")
    print(f"  resolved (auto + reaches + installs) : {resolved}/{n} = {resolved / n:.0%}")
    print("\nThe baseline routes on the confidence score before testing the install, so some")
    print("auto-approved fixes do not install. That is the gap a reflection loop would close.")


if __name__ == "__main__":
    main()
