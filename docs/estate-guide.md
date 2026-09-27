# The estate: systems, matches and imports

A guide for the person who runs CipherHorizon. It explains what the Estate page is telling you and how to act on it. The rules behind the order are in [methodology.md](methodology.md); file formats are in [importing.md](importing.md) and [exporting.md](exporting.md).

## Systems

A **system** is what an owner answers for: an application and the services and machines it runs on. Every endpoint you scan and every machine you inventory belongs to one. You do not have to create systems: they appear as you add things, and you can rename or edit them.

Open a system to see everything about it on one page: why it sits where it does, its details, its services and machines, its certificates with their key sizes, matches, imported documents, coverage and its history.

### Details only a person knows

Owner, environment, exposure, criticality, how long its data must stay secret, and the identifiers a federal inventory asks for (FISMA identifier, FIPS 199 category, high value asset identifier, hosting). None can be observed by any tool, so none is ever filled in for you. **Empty means "not provided"**, and the system says so wherever it matters.

Enter them on the system page, or edit `systems.csv` (Estate → *Export details*) and import it with the API. Every change is recorded with who, what and why, and the record cannot be edited or emptied.

## The Estate page

Systems appear in the order to look at them. The order is decided by four published rules, applied in turn:

1. **Recorded traffic that could be read later**, for data that must stay secret past 2030.
2. **Exposure and criticality**, as you entered them.
3. **Certificate and TLS defects.**
4. **Strength of evidence**: what this product observed comes before what was only imported.

There is no score. Press **Why** on a row to see the rules that applied, what they found, and their sources. A row marked **based on evidence only** was placed without any of the three details above; open the system and enter them, and it moves. A system that has never been scanned is not reported as safe: its row says that exposure is not known.

The order is a way to decide what to look at, not a statement that a lower system is safe.

## Review: which service belongs to which machine

When a scan and an inventory describe the same thing, the product proposes that they belong to one system. It uses three rules only: the endpoint's certificate is held on the machine (same SHA-256 fingerprint), the endpoint's name is the machine's name, or the certificate lists the machine's name.

- A match it is sure of, made entirely from its own scans and collectors, is **joined automatically** and shown on the system page as *Joined automatically because…*, with an **Undo**.
- Everything else waits on the **Review** page: each proposal shows the rule, the values that matched, its strength in words (strong, medium, weak), and whether other systems match too. **Confirm** joins them; **Reject** keeps them apart and the product will not propose it again.
- A certificate on several machines, or a wildcard on dozens of systems, is shown as ambiguous and joins nothing by itself.
- A join that would overwrite different details you entered is refused, and the fields are named.
- A join whose evidence has since disappeared is flagged *evidence gone*; nothing is undone until you decide.

Anything involving an imported document is always a proposal, never automatic: a document can claim anything.

## Imports

**Imports → Import a CBOM** brings in a CycloneDX 1.6 or 1.7 CBOM from another tool. You choose the system; what the document says about its own subject is recorded but never decides where its data goes. The result shows the producer it recognised and what was **not interpreted**, counted by reason, so you can see how much was set aside.

Imported facts are marked as imported. They add to a system, and they never overwrite what a scan or collector observed, and never claim that a key was loaded or used. A system known only from imports is ranked after those that were observed and labelled a lead. **Withdraw** an import to stop its facts counting; the document is kept.

## Certificates

Only public certificate details are read; private keys are never opened. The Certificates page lists every end-entity certificate with its key, signature and expiry, and summarises root and intermediate certificates (a machine trusts hundreds and none is a finding on its own), plus changes to a machine's trusted roots between two uploads. A place where a machine holds a certificate says whether a key is associated **in that store**; that is a property the operating system reports, not a claim about where a key exists.

## Exports

On a system page, **M-23-02 structure** exports the nine items a federal inventory asks for as JSON or CSV, each marked *provided* or *not provided* and by whom. It supports that structure; it does not say the system complies with anything. On an endpoint, **CycloneDX** downloads the CBOM in 1.7 (or 1.6 for older tools).
