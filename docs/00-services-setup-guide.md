# AWOZ-1227 laptop demo: services and accounts

This maps every box in the CONOPS architecture (Section 2) to a real
service you can stand up on your own laptop, and says plainly which parts
are genuinely free and which have a small, bounded cost.

## The two moving parts

| CONOPS role | Real service | Cost on your laptop |
|---|---|---|
| Databricks sharing endpoint + Unity Catalog (the thing being fronted) | A Databricks workspace | See "Path A vs Path B" below |
| Gravitee API Gateway (the micro-perimeter) | Gravitee API Management, **Community Edition**, self-hosted via Docker | **$0.** Open source, no account, no license key. `docker compose up -d` from this project's `docker-compose.yml` and it's running on `localhost`. |

Gravitee is the easy half of this question — there's no catch. The
Databricks half needs a real decision, because the CONOPS' provider-side
features (creating a share, creating a bearer-token recipient, issuing a
credential file, Unity Catalog entitlements) are the part that varies by
plan.

## Path A: Databricks Free Edition (try this first — zero cost, zero risk)

Databricks Free Edition (the modern replacement for the old Community
Edition) is a real no-cost tier that includes Unity Catalog and
serverless compute, with no credit card and no AWS account needed —
Databricks hosts everything. It's confirmed to work as a Delta Sharing
**recipient** (consuming someone else's share). What's *not* documented
either way is whether it supports the **provider** side this milestone
actually needs: `CREATE SHARE`, `CREATE RECIPIENT` with a bearer token,
and REST API/personal-access-token automation (Free Edition explicitly
has "no access to the account console or account-level APIs," which is
the one documented restriction that could bite us here).

So: sign up for Free Edition, then run `scripts/00_check_capabilities.py`
in this project. It calls your workspace directly and tells you, in about
10 seconds, whether `CREATE SHARE`/`CREATE RECIPIENT`/PAT access actually
work. If they do, **you're done — the whole demo runs for free, forever,
with no AWS account at all.** If they don't, move to Path B.

Sign up: https://www.databricks.com/learn/free-edition (instant, email or
Google/Microsoft sign-in only).

## Path B: Databricks 14-day free trial (Premium, on AWS)

This is the fallback if Free Edition blocks the provider-side calls. The
trial itself is free for 14 days and includes full Unity Catalog, the
account console, and REST API/PAT access — i.e., everything the CONOPS
provider flow needs.

The catch: a Premium-tier Unity Catalog metastore needs its own cloud
storage (an S3 bucket) and an IAM role, which means **you need an AWS
account** linked during setup, even though Databricks itself is free for
14 days. What that costs in practice, running a few hours a day for a
week or two:

- S3 bucket for the metastore root + your tiny synthetic dataset: a few
  cents, almost certainly covered by AWS's Always Free S3 tier (5 GB).
- IAM roles/policies: $0, always free.
- Compute: a Databricks Free-Edition-style serverless SQL warehouse or a
  small cluster, within the trial's included credits.
- The one real risk: if the Quick Start CloudFormation template stands up
  a NAT Gateway for networking, that's billed hourly (~$0.045/hr plus
  data processing) and is **not** covered by AWS free tier. For a short
  demo this is a few dollars at most — just remember to tear the stack
  down (`terraform destroy` / delete the CloudFormation stack) when
  you're done each session rather than leaving it running for weeks.

Sign up: https://www.databricks.com/try-databricks (choose AWS as the
cloud; you'll be prompted to link or create an AWS account during the
guided setup).

## What you do NOT need for this milestone

- **No local LLM, no GPU, no 96GB VRAM box.** That hardware is for your
  separate local-AI/"mimic Claude Code" project — unrelated to AWOZ-1227.
  Nothing in the OpenSharing/Gravitee flow touches an LLM.
- **No SearXNG, no MCP servers.** Also part of the other project.
- **No paid SIEM.** The Gravitee Docker stack already includes
  Elasticsearch for its own gateway logs; this demo repurposes that as
  the stand-in for the real SIEM in T-11's correlation-ID trace.
- **No Gravitee Cloud account.** Self-hosted Community Edition does
  everything this demo needs; Gravitee Cloud (their hosted/paid option)
  is unnecessary here.
- **A Gravitee developer portal / Backstage** for self-registration
  (Section 3.4) ships inside the same Docker Compose stack
  (`developer_portal` service) — no separate signup.

## Order of operations

1. `docker compose up -d` (this project's root) — Gravitee stack live
   locally in about a minute. Confirm the Console loads at
   `http://localhost:8084`.
2. Sign up for Databricks **Free Edition**. Get a workspace URL and a
   personal access token (Settings → Developer → Access tokens).
3. Copy `.env.example` to `.env`, fill in the Databricks host/token and
   leave the Gravitee values as-is (they match the Docker Compose ports).
4. `python3 scripts/00_check_capabilities.py` — this is the fork in the
   road. If it says provider-ready, stay on Free Edition. If not, sign up
   for the Path B trial instead, update `.env`, and re-run it.
5. Proceed through `scripts/01` → `scripts/07` in order (each script's
   docstring says which CONOPS test ID it produces evidence for).

## Why this sequencing matters for sizing the real job

Running Path A's capability check first costs you ten minutes and
nothing else. It tells you, concretely and early, whether the client's
real Databricks environment (which is almost certainly Premium-tier with
full account-console access, per Section 6.1) will behave the same way
your free prototype does — or whether there's a capability gap you'd
otherwise only discover once you're already coordinating with Data Eng
and Data Governance on their calendar. That's the whole point of doing
this solo first: surfacing *that kind of gap* before it costs other
people's time.
