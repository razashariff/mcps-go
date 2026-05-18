# Licensing -- mcps-go

`mcps-go` is published under the **Business Source License 1.1 (BSL 1.1)**.
This page explains what that means in plain English and how to obtain a
commercial production licence.

## At a glance

| Use case                                                          | Licence required           | Cost     |
|-------------------------------------------------------------------|----------------------------|----------|
| Read the source, learn from it, contribute back                   | None (BSL 1.1 grant)       | Free     |
| Run it on your laptop for evaluation                              | None (BSL 1.1 grant)       | Free     |
| Use it in academic research                                       | None (BSL 1.1 grant)       | Free     |
| Use it in a personal project, hobby code, or non-commercial OSS   | None (BSL 1.1 grant)       | Free     |
| Use it in **production at a company**, in a paid product,         |                            |          |
| in a SaaS, in a customer-facing service, or as part of any        |                            |          |
| revenue-generating system                                         | **Commercial licence**     | Paid     |
| Embed it in a redistributable commercial product                  | **Commercial licence**     | Paid     |

The Change Date is **6 May 2030**. After that date, this version of
`mcps-go` converts automatically to Apache License 2.0 (no commercial
licence required for v1.0.0 onwards from that point). New versions
published after the Change Date will be released under their own BSL
terms with their own 4-year clock.

## What "production use" means

Production use is **any use of mcps-go in a system that generates or
supports revenue**, that serves third parties, or that operates as part
of a business's regular operations. Specifically:

- Running mcps-go in a customer-facing SaaS or hosted service
- Embedding mcps-go in a commercial product you sell, license, or distribute
- Using mcps-go to sign or verify messages on behalf of paying customers
- Using mcps-go as part of an internal corporate system that supports
  revenue-generating activity (e.g. AI agent infrastructure inside a bank,
  fintech, payment processor, or regulated entity)
- Running mcps-go in a Watchman, MCP server, or any downstream OSS
  product **when that downstream product is deployed for commercial use**

If you are unsure whether your use is production use, assume it is and
contact us. We will give you a straight answer in writing within 2 working
days.

## What "non-production use" means

Non-production use is **free, no licence required**, no obligation to
contact us. Specifically:

- Reading the source code
- Running tests locally
- Contributing pull requests
- Academic, research, or teaching use
- Personal hobby projects with no commercial intent
- Evaluation use inside a company for up to 90 days, after which
  production use either ceases or a commercial licence is obtained
- Use in non-commercial open-source projects

## Commercial licence pricing

We publish a starting price so you can budget without an enquiry.
Commercial licences are sold as annual subscriptions, per production
deployment.

| Tier                       | Starting price (GBP/year) | What's included                                  |
|----------------------------|---------------------------|--------------------------------------------------|
| Production licence (starter) | **From £25,000**         | One production deployment, one entity, email support, security updates |
| Multi-deployment            | by quotation              | Multiple production deployments, same entity     |
| Enterprise                  | by quotation              | Multi-entity, redistribution rights, SLA, custom support, on-prem      |
| OEM / embed-and-resell      | by quotation              | Right to ship mcps-go inside your commercial product to your customers |

Prices reflect the value mcps-go adds (cryptographic agent identity,
replay protection, tool integrity, FIPS-compatible signing) and are in
line with comparable BSL-licensed middleware (Sentry, MariaDB MaxScale,
Cockroach Enterprise, etc.).

Volume, multi-year, and design-partner discounts available.

## How to obtain a commercial licence

1. Email **contact@agentsign.dev** with:
   - Your company name and country
   - The product or service that will embed mcps-go
   - Estimated number of production deployments
   - Estimated number of monthly active agents using the signing layer
   - Whether you need any custom terms (FIPS attestation, on-prem,
     export control, redistribution, etc.)
2. We respond within 2 working days with a written quotation, draft
   licence, and a 30-minute scoping call if needed.
3. Signature, payment, and licence key issued within 5 working days
   typically.

## What you get on a commercial licence

- A signed commercial production licence agreement, separate from BSL 1.1
- Email support from the maintainer (response within 1 working day)
- Security patches delivered before public disclosure (advance notice
  on any CVE we discover in mcps-go itself)
- Right to use mcps-go in your production environment for the term of
  the agreement
- Indemnity coverage for the licensed binary against third-party
  intellectual-property claims (subject to standard cap-and-carve-out)
- Option to influence roadmap and feature priority

## Downstream operators (Watchman, MCP servers, etc.)

If you are running an **open-source product that embeds mcps-go** (for
example, moov-io/watchman with MCPS signing enabled, or any other MCP
server that imports `github.com/razashariff/mcps-go`), and you are
running it **for commercial purposes**, you require a commercial licence
from CyberSecAI Ltd.

This is the standard BSL 1.1 downstream model. The upstream OSS project
is free to redistribute mcps-go inside their codebase; the downstream
operator who runs that codebase in production is the entity that
requires the commercial licence.

If you are unsure whether your downstream use triggers the licence
requirement, contact us. We will not pursue good-faith downstream
operators who reach out proactively -- we much prefer a conversation
to a dispute.

## Patents

mcps-go and the wider MCPS protocol are covered by UK patent
applications including GB2610372.1 and GB2610349.9, with related
applications pending. A commercial licence to mcps-go includes a
non-exclusive, royalty-free patent licence for the licensed deployments
for the term of the agreement. See your commercial licence agreement
for the full patent grant terms.

The BSL 1.1 grant itself does **not** include a patent licence for
production use. The Change Date conversion to Apache 2.0 in 2030 will
include the Apache 2.0 patent grant for the converted version.

## Frequently asked questions

**Q: I'm a researcher writing a paper. Do I need a licence?**
A: No. Academic and research use is free under BSL 1.1.

**Q: I'm a solo developer building a hobby project. Do I need a licence?**
A: No. Personal, non-commercial hobby use is free.

**Q: I work at a startup and want to evaluate mcps-go before we commit.
Can I do that for free?**
A: Yes, for up to 90 days of evaluation. After 90 days, either stop
production use or obtain a commercial licence.

**Q: I want to fork mcps-go and re-license under MIT. Can I?**
A: No. BSL 1.1 prohibits relicensing. Forks must inherit BSL 1.1 or its
Change License (Apache 2.0 after 6 May 2030).

**Q: I am a Watchman operator running self-hosted Watchman with MCPS
signing enabled. Do I need a licence?**
A: Yes, if Watchman is supporting commercial operations at your
organisation. Contact us -- the standard Watchman-operator licence is
priced at the production-licence starter tier and includes integration
support.

**Q: I am an OSS maintainer of an MCP server that wants to add MCPS
signing for my OSS users. Can I do that without a licence?**
A: Yes -- distributing mcps-go inside another OSS project is permitted.
Your OSS users who run it in production are the parties that may
require a commercial licence.

**Q: How is the £25,000 starting price set?**
A: It reflects the security risk reduction at a regulated entity (one
breach avoided pays for it many times over), the maintenance cost of a
cryptographic middleware library, the FIPS-compatible algorithm choices
that make it deployable in regulated environments, and the standard
BSL-licensed middleware market rate. We do not negotiate on the starter
tier; we negotiate on multi-deployment and enterprise tiers.

**Q: Can I get a discount as a design partner?**
A: Yes. Design partners who allow case-study publication, share
deployment telemetry under NDA, or contribute upstream patches qualify
for discounts of 30-60% on year 1 and 15-30% on years 2-3.

## Contact

**Commercial licensing:** contact@agentsign.dev
**Technical questions:** open a GitHub Issue on this repository
**Security disclosure:** SECURITY.md (coming) or contact@agentsign.dev with subject `[SECURITY]`
**Patents and IP:** contact@agentsign.dev

CyberSecAI Ltd | Registered in England and Wales | https://cybersecai.co.uk
