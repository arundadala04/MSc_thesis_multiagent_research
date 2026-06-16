# DevSecAgent

Autonomous vulnerability remediation in a CI/CD pipeline.
MSc Cybersecurity thesis ICT solution, Arun Teja Dadala (x25101013), NCI.

## Idea

Scan a project for known CVEs, then for each finding retrieve background notes, generate
a dependency fix with an LLM, check that fix, and deploy it in a container with a
rollback if it breaks the build. This is the **baseline** decision core (Arm A): a single
generate-then-verify pass with no retry. It is the system the later multi-agent design is
measured against, so it is built and characterised first.

The pipeline has four stages:

1. **Scan** — Trivy and Snyk both scan the project and their findings are merged and
   de-duplicated. They are complementary: Trivy reads the manifest statically with no
   account, while Snyk scans the installed environment for direct and transitive
   vulnerabilities. This is a broader surface than a single scanner.
2. **Retrieve** — a hybrid FAISS + BM25 + RRF retriever pulls the most relevant notes
   from a CVE knowledge base as grounding for the fix.
3. **Patch (Arm A core)** — one model generates the upgrade, a second scores it on four
   checks (correctness, completeness, safety, consistency), and a confidence score routes
   it to apply-automatically or send-for-review.
4. **Deploy** — the fix is installed and tested in a Docker container; a change that
   breaks the build is rolled back.

## The four checks

The verifier scores each from 0 to 1 and the weighted total is the confidence:

- **correctness** — does the new version actually fix this CVE
- **completeness** — is anything left unfixed
- **safety** — does the upgrade avoid breaking the project
- **consistency** — does it agree with the scanner and the reference notes

`auto` at confidence >= 0.85, `review` from 0.60 to 0.85, `manual` below 0.60.

## Stack

- Azure OpenAI (GPT-4o) for the patch generation and verification
- Trivy and Snyk for scanning (Trivy needs no account; Snyk needs a free API token)
- FAISS + BM25 + RRF for retrieval
- Docker for the deploy / rollback test

## Setup

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e .
    cp .env.example .env

Then put your own Azure OpenAI key and endpoint in `.env`. Both scanners and Docker must
be installed for the scan and deploy steps:

- **Trivy** — install the binary; it runs with no account.
- **Snyk** — `npm install -g snyk` then `snyk auth` (or set a `SNYK_TOKEN`); the free tier
  is enough. If Snyk is not authenticated, the scan still runs on Trivy alone.
- **Docker** — running, for the install / rollback test.

## Run

Run the baseline over the seed dependency CVEs and see how it behaves:

    python run_baseline.py

Run the tests:

    pytest -q

## Layout

    devsecagent/
        config.py     settings from .env
        llm.py        Azure GPT-4o chat and embeddings
        schema.py     Finding, Patch, DeployResult
        scan.py       Trivy and Snyk scanning
        kb.py         the CVE knowledge base
        retriever.py  FAISS + BM25 + RRF retrieval
        patcher.py    generator + four-check verifier + confidence routing
        arm_a.py      baseline core: one generate-verify pass
        deployer.py   apply, test in Docker, promote or rollback
        versions.py   version comparison
        dataset.py    the seed evaluation CVEs
        data/         the CVE knowledge base
    run_baseline.py   run the Arm A baseline over the seed CVEs
    samples/          a vulnerable project to scan
    tests/            unit tests for each stage
