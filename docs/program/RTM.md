# RTM: requirements traceability matrix for PRD-003 and PRD-004

The **only** place a requirement is declared done. Checked by `internal/archtest` (`TestRequirementsTraceability`):

- every `REQ-*` id in [PRD-003](../product/PRD-003-cryptographic-estate-model.md) and [PRD-004](../product/PRD-004-tls-scanner-t1-pki-depth.md) has exactly one row here, and every row here exists in a PRD;
- a row with status `done` lists at least one test, and every `Test*`/`Fuzz*` name listed exists in a `_test.go` file of the repository;
- evidence that is not a Go test is written `script:<file>#<check>`, `oracle:<file>` or `report:<doc>#<section>`; those are not resolved automatically, they must point at something that exists in the repository (checked for the file part).

Status: `todo` / `in-progress` / `done` / `deferred`. A `deferred` row must say why in *Notes*. Priority and sources are copied from the PRD; if they differ, the PRD wins and this table is corrected.

Columns: **WP** work package ([ENG-HANDOFF-002](../product/ENG-HANDOFF-002-estate-model.md) §4). **Source** research finding ([RESEARCH-003](../product/RESEARCH-003-ecosystem-standards-and-design-inputs.md)). **SR** security requirement ([SECARCH-001](../product/SECARCH-001-threat-model-and-security-requirements.md)). **Evidence** tests/oracles/reports.

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-MOD-1 | P0 | WP-1 | STRATEGY §data model | SR-10 | TestRebuildEqualsIncrementalProjection, TestLegacyDatabaseMigratesWithoutLosingAnything | done | raw scans.report_json / host_snapshots.cbom_json never rewritten; graph rebuilt by `cipherhorizon db rebuild-graph` |
| REQ-MOD-2 | P0 | WP-1 | STRATEGY | — | TestScanReportProjectsEveryFactAsNetworkEvidence, TestTheSameCertificateIsOneEntity, TestHostCBOMProjectionKeepsTheCollectorsEvidence | done | system = systems table; service = endpoint asset (host:port); certificate, algorithm, software, provider, protocol, suite, group = entities with natural keys |
| REQ-MOD-3 | P0 | WP-1 | STRATEGY | SR-10 | TestScanReportProjectsEveryFactAsNetworkEvidence, TestLegacyDatabaseMigratesWithoutLosingAnything, script:testing/e2e/journey.mjs#E2E | done | journey 60/60 unchanged after migration; findings/ratings are still computed from the untouched stored evaluation |
| REQ-MOD-4 | P0 | WP-1 | STRATEGY | SR-10 | TestHostCBOMProjectionKeepsTheCollectorsEvidence, TestForeignComponentsAreReadAtTheWeakestReading, TestCertificateComponentSharesTheScanKey | done |  |
| REQ-MOD-5 | P0 | WP-1 | — | SR-10 | TestLegacyDatabaseMigratesWithoutLosingAnything, TestFailedMigrationLeavesTheDatabaseIntact, TestFrozenMigrationsAreUnchanged, TestLegacySnapshotsKeepOnlyTheClassTheyCanProve, TestDBRebuildGraphAndStats, TestBackupIsOwnerOnlyOnUnix | done | found and fixed a real bug: a retry within the same second could not take a backup |
| REQ-MOD-6 | P0 | WP-1 | E-1, E-2 | SR-03 | TestStreamsAndSourceClassesStaySeparate, TestSchemaRefusesAnObservationWithoutAMethod, TestValidateRefusals, TestHostUploadSourceClassFollowsTheProducer, TestAHostUploadIsImportedUnlessTheChannelSaysOtherwise | done | host upload class follows the producer the document names (documented weaker guarantee until an authenticated push exists; SECARCH-001 T-03) |
| REQ-MOD-7 | P1 | WP-1 | — | — | TestAnEntityNoLongerObservedIsFlaggedNotDeleted, TestTheSameCertificateIsOneEntity | done |  |
| REQ-CERT-1 | P0 | WP-3 | K-1 | SR-06, SR-07 | TestEachCertificateInEachStoreIsAnObservation, TestOnlyAllowListedStoresAreRequested, TestAStoreThatFailsMakesTheResultPartialNotFatal, TestAStalledStoreIsGivenUpOn, TestNoKeyMaterialFunctionIsCalled, TestKeyAssociationQueryIsTheOnlyPropertyReadAndHasNoBuffer, TestStoresOutsideTheAllowListAreRefusedBeforeWindowsIsCalled, TestTheRealCertificateStoresAnswerSanely, TestTheRealSensorOnThisMachine, oracle:testing/hostdiscovery/compare-certs.ps1, report:docs/host-discovery/wp3-security-review.md | done | syscall review passed; oracle AGREE on this machine (142 expected, 140 detected, 2 unparseable accounted, 0 extra) with 5 negative controls caught; Server/ARM64/elevated not validated |
| REQ-CERT-2 | P0 | WP-2 | K-1 | SR-06, SR-16 | TestFindsCertificatesInTrustStoreAndServiceDirs, TestSymbolicLinkRules, TestBudgetsAreEnforcedAndReported, TestDetectAndDeterminism, TestMalformedInputIsCountedNotFatal, TestAnOverriddenRootCannotBeEscapedBySymlinks, oracle:testing/hostdiscovery/compare-certs.sh, report:docs/host-discovery/stage-3-certificates-report.md | done | oracle AGREE on a real Linux-style tree (212 placements, Mozilla bundles); NOT run on a live Linux host; the overridden-root symlink test skips on this machine (no symlink privilege) and runs in Linux CI |
| REQ-CERT-3 | P0 | WP-2 | K-2, S-5 | SR-06 | TestFindsCertificatesInTrustStoreAndServiceDirs, TestEachCertificateInEachStoreIsAnObservation, TestOneCertificateSeenByAScanAndByAHostIsOneEntity, TestCertificateObservationsCarryOnlyAllowedMetadata, TestEachOccurrenceOfACertificateIsItsOwnObservation | done |  |
| REQ-CERT-4 | P0 | WP-2 | K-4 | SR-06, SR-17 | TestNoKeyMaterialIsReadOrReported, TestOnlyCertificateBlocksAreDecoded, FuzzScanPEM, TestCertificateObservationsCarryOnlyAllowedMetadata, TestCertFileMethodIsDeclaredAdjacentToSecrets, TestNothingButCertificatesComesOut, TestOneCertificateSeenByAScanAndByAHostIsOneEntity | done | mutation checks recorded in the WP-2 and WP-3 reviews |
| REQ-CERT-5 | P0 | WP-2 | K-3 | — | TestEndEntityCertificatesAreListedAndAnchorsAreSummarised, TestASystemListsItsOwnCertificates | done | roots and intermediates summarised; changes to a host's root set reported |
| REQ-CERT-6 | P0 | WP-2 | S-5, C-1 | — | TestOneCertificateSeenByAScanAndByAHostIsOneEntity, TestTheSameCertificateIsOneEntity, TestCertificateComponentSharesTheScanKey | done |  |
| REQ-CERT-7 | P0 | WP-2 | S-6 | — | TestCertificateRules, TestCertificateRulesAgreeWithTheTLSRules, TestEveryCertificateFindingIsCited | done | anomaly rules removed from the requirement (PRD change log 2026-09-26) |
| REQ-CERT-8 | P0 | WP-2 | S-5, K-2 | — | TestOneCertificateSeenByAScanAndByAHostIsOneEntity, TestCertificateDetailRefusesBadFingerprints, script:testing/e2e/estate-phase.mjs#E2E-24 | done | API, CBOM and certificate views carry key size and curve, or say why not |
| REQ-COR-1 | P0 | WP-5 | C-1 | SR-05 | TestAUniqueFirstPartyCertificateIsAStrongAutoConfirmedJoin, TestNamesAloneAreNeverStrong, TestChainCertificatesNeverJoin, TestAnEndpointIsNeverProposedToItsOwnSystem, TestAUniqueFirstPartyMatchAutoConfirmsWithItsExplanation | done | rules J1-J3 only; no fuzzy matching (a near-collision name and an IP address are tested as non-matches); chain and CA certificates never join |
| REQ-COR-2 | P0 | WP-1/WP-5 | C-2, §4.3 | SR-11 | TestLegacyDatabaseMigratesWithoutLosingAnything, TestAUniqueFirstPartyMatchAutoConfirmsWithItsExplanation, TestManualLinksAreConfirmedLinksAndUnlinkingIsARejection, TestLinkRoutesValidateInput | done | links table (migration 6); fixed strength table; states proposed/confirmed/rejected; who and when; manual links of 0.1.0 backfilled as confirmed |
| REQ-COR-3 | P0 | WP-5 | C-3 | SR-05, SR-15 | TestACertificateOnSeveralHostsIsAmbiguousAndJoinsNothing, TestAWildcardOnFortyHostsJoinsNothing, TestAmbiguousMatchesAreProposedAndNeverAutomatic | done | mutation checks: ambiguity, widely-shared cap |
| REQ-COR-4 | P0 | WP-5 | C-4 | SR-03, SR-05 | TestAForgedImportCannotHijackOrBlockTheRealJoin, TestAnUploadedHostLabelDoesNotAutoConfirmByName, TestAForgedImportGetsAProposalAndTheRealJoinStands, TestAUniqueFirstPartyMatchAutoConfirmsWithItsExplanation | done | mutation check: imports allowed to auto-confirm |
| REQ-COR-5 | P0 | WP-5 | C-5 | — | TestAmbiguousMatchesAreProposedAndNeverAutomatic, TestAConfirmedLinkThatLosesItsEvidenceIsFlaggedNotRemoved | done | reject persists across rescans and uploads; a confirmed join that loses its evidence is flagged stale, not removed; mutation checks for both |
| REQ-COR-6 | P0 | WP-5 | C-6 | — | TestAUniqueFirstPartyMatchAutoConfirmsWithItsExplanation, TestExplanationsAreBounded | done | each rule carries the matched values and where they were seen, bounded and cleaned |
| REQ-COR-7 | P0 | WP-5 | — | SR-11, SR-12 | TestAmbiguousMatchesAreProposedAndNeverAutomatic, TestAJoinThatWouldOverwriteOperatorValuesIsBlockedAndExplained, TestManualLinkConflictIsRefusedWithTheFields, TestManualLinksAreConfirmedLinksAndUnlinkingIsARejection, TestEveryMutatingRouteIsGuardedAgainstForgery, script:testing/e2e/estate-phase.mjs#E2E-23 | done | API and review queue UI |
| REQ-COR-8 | P1 | WP-5 | — | SR-15 | TestCorrelationIsDeterministic, TestCorrelationScales | done | deterministic under shuffling; 3,000 endpoints x 3,000 hosts in about 10 ms (pure pass); no explicit time budget is enforced because the pass is cheap; the SQL snapshot at scale is measured in WP-9 |
| REQ-ING-1 | P0 | WP-4 | E-3 | — | TestThirdPartyDocumentsImportWithProvenance, TestImportCommandSendsADocumentAndReportsWhatHappened, TestRealThirdPartyDocumentsValidate, TestRealDocumentsProjectWithoutLoss, script:testing/e2e/estate-phase.mjs#E2E-22 | done | API, CLI and UI upload flow; run on the five real documents |
| REQ-ING-2 | P0 | WP-4 | — | SR-01 | TestRefusals, TestHostileDocumentsAreRefusedAndStoreNothing, FuzzParse, TestValidAndInvalidDocuments, TestUnsupportedVersionsAreRefused, TestOurOwnGoldenCBOMsValidateAgainstTheEmbeddedSchema | done | ADR-0017; 1.1M fuzz executions clean; mutation checks: depth limit, schema check |
| REQ-ING-3 | P0 | WP-4 | E-2 | SR-04 | TestTheSubjectIsChosenByTheOperatorNeverTheDocument, TestTheDocumentsOwnSubjectIsAClaimOnly, TestAnImportNeedsASystemAndValidatesItsName | done |  |
| REQ-ING-4 | P0 | WP-4 | — | SR-03, SR-11 | TestThirdPartyDocumentsImportWithProvenance, TestReimportingWithdrawingAndReactivating, TestAForgedCollectorDocumentIsStillImported, TestImportRoutesAreGuardedLikeTheRest | done | provenance: class, claimed tool/version, SHA-256, size, time, submitting token label, assigned system; audited |
| REQ-ING-5 | P0 | WP-4 | E-1 | SR-18 | TestEvidenceMappingByProducerKind, TestValidateRefusals, TestSourceScanFixtureIsProjectedAsCapabilityFromSource | done | mutation check: import claiming exercised/bound/loaded |
| REQ-ING-6 | P0 | WP-4 | E-3, E-4 | — | TestProfilesAreDetected, TestLensDocumentIsProjectedAndTheRestIsCounted, TestCertificateIdentityFromABomRefHintAndSizeFromTheKeyReference, TestRealDocumentsProjectWithoutLoss | done | CBOMkit, CBOM-Lens 1.6/1.7, Theia (generic: its sample records no tool), own output; run on the real samples; cdxgen: no real sample obtained, covered by the generic path and a name matcher only |
| REQ-ING-7 | P0 | WP-4 | — | — | TestEveryComponentIsAccountedFor, TestLensDocumentIsProjectedAndTheRestIsCounted, TestAnEnormousDocumentIsBoundedAndCounted | done | every component of every fixture and real document is interpreted or counted by reason; the UI summary is WP-8 |
| REQ-ING-8 | P0 | WP-4 | — | SR-18 | TestAnImportCannotOverwriteWhatAScanObserved, TestRebuildKeepsImportsAndTheirPrecedence | done | mutation check: imports may overwrite |
| REQ-ING-9 | P1 | WP-4 | — | SR-11 | TestReimportingWithdrawingAndReactivating, TestRebuildKeepsImportsAndTheirPrecedence | done |  |
| REQ-ING-10 | P2 | later | E-6 | SR-09 |  | deferred | blocked on OQ-2 |
| REQ-SYS-1 | P0 | WP-1 | S-4 | — | TestSystemMetadataIsOptionalAndValidated, TestSystemsAreListedAndEdited | done |  |
| REQ-SYS-2 | P0 | WP-1 | — | SR-11, SR-13 | TestSystemChangesAreAudited, TestAuditLogIsAppendOnly, TestARejectedPatchWritesNothing, TestBulkUpdateIsAllOrNothing, TestSystemsCSVRoundTrip, TestSystemPatchRefusesBadInput, TestHostileSystemTextIsData, TestASystemWithNoMetadataIsRankedAndLabelled | done | the ranking states when it rests on missing inputs (evidenceOnly, basis, missing) |
| REQ-PRI-1 | P0 | WP-6 | S-6 | — | TestRankingFollowsTheRulesInOrder, TestTwoSystemsDifferingOnlyInDataLifetimeRankByIt, TestNoScanIsNotReportedAsSafe, TestTheEstateIsRankedByTheRulesAndEveryRowSaysWhy, TestRankingIsDeterministicAndStableUnderReordering | done | four ordered rules, no composite score; mutation checks: rule order, lifetime |
| REQ-PRI-2 | P0 | WP-6 | STRATEGY | — | TestTheEstateIsRankedByTheRulesAndEveryRowSaysWhy, script:testing/e2e/estate-phase.mjs#E2E-20 | done | the ranking never reads the hygiene score; it appears only per service on the system page and on the TLS overview |
| REQ-PRI-3 | P0 | WP-6 | — | — | TestEveryRuleIsPublishedAndCited, TestAnImportedOnlySystemIsALeadNotAFinding | done | rules published beside the ranking and in docs/methodology.md; mutation check: an unpublished rule name |
| REQ-EXP-1 | P0 | WP-7 | S-1 | SR-14 | TestEncodedOneDotSevenValidatesAgainstTheOneDotSevenSchemaAndOneDotSixStillAgainstOneDotSix, TestOneDotSevenReplacesDeprecatedConstructsAndDoesNotEmitBoth, TestScanCBOMDefaultsToOneDotSevenAndOffersOneDotSix, TestSpecFlag, golden 1.6 and 1.7 CBOMs | done | 1.7 default, --spec 1.6 / output.spec; negative controls; unknown version refused without echoing input; no new dependency (x/text was already required, now direct) |
| REQ-EXP-2 | P0 | WP-7 | S-1 | — | TestRegistryMappingIsCompleteAndValid | done | 52 catalogue entries: mapped or listed with a reason; five gaps documented in docs/exporting.md |
| REQ-EXP-3 | P0 | WP-7 | S-4 | SR-08 | TestTheM2302ExportHasNineItemsMarkedProvidedOrNot, TestTheM2302ExportSaysWhenNothingWasObserved, TestTheM2302ExportDoesNotListAPostQuantumGroup, TestItem4ListsOnlyCitedQuantumVulnerableEndEntityKeys | done | JSON and CSV; wording supports the structure, never compliance; gaps: item 6 (OS), supplier in item 5; mutation checks: operator source, classification filter, group filter, CSV safety |
| REQ-EXP-4 | P2 | later | S-2 | — |  | deferred | P2; after 0.2.0 |
| REQ-EXP-5 | P1 | WP-1/WP-7 | R6 | — | TestOpenAPIDescribesExactlyTheRegisteredRoutes, TestEveryOpenAPIOperationIsComplete, TestEveryDocumentedGETStatusIsOneTheServerReturns | done | hand-written; parity test found a real undocumented 409 on the first run; mutation check: a route removed from the document; bodies not schema-described, mutating-route statuses not test-checked |
| REQ-EXP-6 | P0 | WP-7 | — | SR-08 | TestTheM2302ExportRequiresTheToken, TestEveryAPIRouteRequiresTheToken, TestEveryRouteRefusesAForeignHost | done | export routes are ordinary routes behind the token middleware; the table walk covers each new one; the security.sh extension is WP-9 |
| REQ-UI-1 | P0 | WP-8 | — | — | TestUIDoesNotBorrowAnotherScannersRatingVocabulary, script:testing/e2e/estate-phase.mjs#E2E-20, script:testing/e2e/estate-phase.mjs#E2E-27 | done | Estate is the home; Endpoints, Hosts, Findings and the TLS overview sit under Sources; the CBOM page left the menu (old address kept); README states the category; UX-DESIGN-002 |
| REQ-UI-2 | P0 | WP-8 | — | — | TestTheEstateIsRankedByTheRulesAndEveryRowSaysWhy, script:testing/e2e/estate-phase.mjs#E2E-20, script:testing/e2e/estate-phase.mjs#E2E-21 | done | ranked table, Why toggle with four cited rules, evidence-only marker, evidence kind (observed, imported only, nothing yet) |
| REQ-UI-3 | P0 | WP-8 | — | — | TestItem4ListsOnlyCitedQuantumVulnerableEndEntityKeys, script:testing/e2e/estate-phase.mjs#E2E-21, script:testing/e2e/estate-phase.mjs#E2E-25 | done | one page: why, details editor with reason, services with per-endpoint CycloneDX 1.7/1.6, certificates with key size, matches with undo, imports with provenance, coverage, M-23-02 export, audit history |
| REQ-UI-4 | P0 | WP-8 | — | — | TestCertificateDetailRefusesBadFingerprints, script:testing/e2e/estate-phase.mjs#E2E-24 | done | filters: expiry window, key, signature, origin (origins added to the API); roots and intermediates summarised; root-set changes; certificate page with places and key wording |
| REQ-UI-5 | P0 | WP-8 | — | — | TestAmbiguousMatchesAreProposedAndNeverAutomatic, script:testing/e2e/estate-phase.mjs#E2E-23 | done | queue with rule hits, strength in words, competing proposals, confirm/reject with reason, stale and decided lists, count in the menu |
| REQ-UI-6 | P0 | WP-8 | — | — | TestThirdPartyDocumentsImportWithProvenance, script:testing/e2e/estate-phase.mjs#E2E-22 | done | file, system chosen by the person, detected producer, not-interpreted table, duplicate and refusal handling, withdraw |
| REQ-UI-7 | P1 | WP-8 (P1) | — | — | script:testing/e2e/estate-phase.mjs#E2E-20, script:testing/e2e/journey.mjs#E2E-12.1 | done | first run shows three equal doors; a next-step line names proposals waiting or systems on evidence alone |
| REQ-UI-8 | P0 | WP-8 | — | — | TestNoExternalRequests, TestNoInnerHTMLOrEval, TestPageHasNoInlineScriptOrStyle, script:testing/e2e/estate-phase.mjs#E2E-26, script:testing/e2e/security.sh | done | hostile strings (markup, script, RTL override, 400-character values) in system, import tool, certificate subject, owner, notes render inert in all six new views; no horizontal scroll at 390 px or in dark mode; accessible names checked. Known: a bidi override in a name still reorders its own text on screen |
| REQ-REL-1 | P0 | WP-9 | — | — | report:docs/program/QA-REPORT-002.md | in-progress | CHANGELOG [Unreleased] and README are updated and the migration note is in Changed; the version number and the 0.2.0 cut are made by scripts/prepare-release.sh at release, which has not been run |
| REQ-REL-2 | P0 | WP-9 | — | — | report:docs/estate-guide.md, report:docs/importing.md, report:docs/exporting.md, report:docs/methodology.md, report:docs/host-discovery/stage-3-certificates-report.md | done | user guide (systems, review, imports, certificates, exports), import and export references, prioritisation methodology with citations, certificate sensor report |
| REQ-REL-3 | P1 | WP-9 | — | — | script:scripts/rename.sh, report:docs/engineering/RENAME.md | done | rehearsed on a copy: builds, vets and passes the whole suite; the namespace registration and old-document policy are decisions the doc names |
| REQ-REL-4 | P1 | later | — | — |  | deferred | needs the GitHub repository (owner) |
| REQ-NFR-1 | P1 | WP-9 | — | — | TestListViewsAtScale | done | measured, not promised: every server list under 1 s at 5,000 systems and 50,000 certificates; the certificate list is 22.6 MB and the UI draws 500 rows at once; the 32 MiB import time is not measured |
| REQ-NFR-2 | P0 | all | — | — | report:docs/program/QA-REPORT-002.md | done | 12 cross-builds with CGO_ENABLED=0; no new module |
| REQ-NFR-3 | P0 | all | — | — | TestNoSubprocessAnywhereInLibraryCode, TestCollectorLinksNoServerStoreOrScanner, TestSensorsOnlyObserve | done | architecture tests, unchanged in intent; ADR-0015 records the x509 exception |
| REQ-NFR-4 | P0 | all | — | — | TestNoExternalRequests, TestPageHasNoInlineScriptOrStyle, script:testing/e2e/security.sh | done | no new external request; CSP unchanged |
| REQ-NFR-5 | P0 | all | — | — | report:docs/program/QA-REPORT-002.md | in-progress | tests, lint and vet green; govulncheck and a licence check have not been run (not installed; installing needs a download) |
| REQ-NFR-6 | P1 | WP-9 | — | — | script:testing/e2e/estate-phase.mjs#NFR-a11y | in-progress | accessible names, keyboard-operable controls and no overflow checked on every new view; contrast not measured by a tool |

## PRD-004 — TLS scanner T1 ([ENG-HANDOFF-003](../product/ENG-HANDOFF-003-tls-t1.md) §4 work packages; tests per [QA-PLAN-004](../product/QA-PLAN-004-tls-t1.md))

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-TSTG-1 | P0 | T1b | RESEARCH-004 | — | TestStagesRecorded, TestStagesTLS13Only, TestStagesUnreachable | done |  |
| REQ-TSTG-2 | P0 | T1b | RESEARCH-004 | — | TestStagesRecorded, TestSectionsAndFixFirst, script:testing/e2e/t1-phase.mjs#T1-E2E.7 | done | probes in words, connections per stage (sum = scan total), inconclusive parts; reference snapshots in How we tested |
| REQ-TSTG-3 | P0 | T1b | RESEARCH-004 | — | TestLegacyReportsEvaluate, TestRawChainStapleAndSCTs, report:docs/program/QA-REPORT-003.md#legacy | done | 0.2.0 database upgraded and rendered (QA-REPORT-003 §4); /1 never rewritten |
| REQ-TSTG-4 | P0 | T1b | RESEARCH-004 | SR-21 | TestStagesRecorded, TestHSTSHeaderParsedInScan, TestHSTSNilWhenNotSpeakingHTTP, script:testing/e2e/t1-phase.mjs#T1-E2E.1 | done | default true on serve and tls scan; About, tls-scanning.md and CHANGELOG state it |
| REQ-TSTG-5 | P0 | T1b | RESEARCH-004 | SR-19 | TestTargetOnlyTraffic, script:testing/pki/mutations.py | done | recording dialer and lookup; a 301 to another host is not followed |
| REQ-TCRT-1 | P0 | T1b | RESEARCH-004 | — | TestExtensionFacts, TestRawChainStapleAndSCTs | done | IV class added (CA/B 2.23.140.1.2.3) |
| REQ-TCRT-2 | P0 | T1b | RESEARCH-004 | — | TestNoSNIDifferent, TestRawChainStapleAndSCTs, TestT1TrustMatrix | done | deviation: report-level noSni = same, different or failed; a separate chain only when different (ENG-HANDOFF-003 §6) |
| REQ-TCRT-3 | P0 | T1c | RESEARCH-004 | — | TestT1ChainMatrix, TestT1TrustMatrix, TestLifetimeTablePinned, script:testing/pki/mutations.py | done |  |
| REQ-TCRT-4 | P0 | T1c | RESEARCH-004 | — | TestCertificateRules, TestT1ChainMatrix, script:testing/pki/mutations.py | done | EvaluateCertificate (estate certificates) uses the same scaling |
| REQ-TCRT-5 | P0 | T1c | RESEARCH-004 | — | TestT1ChainMatrix | done |  |
| REQ-TCRT-6 | P1 | T1c | RESEARCH-004 | — | TestT1ChainMatrix | deferred | exponent < 65537 done (CERT.WEAK-EXPONENT); ROCA fingerprint, Debian blocklist and estate-wide shared modulus deferred to T2 |
| REQ-TCRT-7 | P1 | T1c | RESEARCH-004 | — | TestPrivateCATrustAnchors | done | entity attrs extKeyUsage, keyUsage, policyClass, lifetimeDays, wildcards, cnOnly, spkiSha256; certificate API and page show them; list columns are REQ-TUI-13 |
| REQ-TCHN-1 | P0 | T1b | RESEARCH-004 | — | TestServedChain, TestT1ChainMatrix, oracle:testing/pki/oracle.sh | done |  |
| REQ-TCHN-2 | P0 | T1c | RESEARCH-004 | — | TestServedChain, TestT1ChainMatrix, TestT1TrustMatrix, oracle:testing/pki/oracle.sh, script:testing/pki/mutations.py | done | deviation: when the served path ends at a CA, the unknown issuer is reported as an unknown (private) root under CERT.UNTRUSTED, not as a missing intermediate |
| REQ-TCHN-3 | P0 | T1c | RESEARCH-004 | — | TestT1ChainMatrix | done | severity: medium unless TLS 1.3 is negotiated or supported |
| REQ-TCHN-4 | P0 | T1c | RESEARCH-004 | — | TestServedChain, TestT1ChainMatrix | done |  |
| REQ-TCHN-5 | P0 | T1c | RESEARCH-004 | — | TestExpiresFirst, TestT1ChainMatrix | done |  |
| REQ-TCHN-6 | P1 | T1c | RESEARCH-004 | — | TestServedChain | done | page notes chains over 4 KiB |
| REQ-TTRS-1 | P0 | T1c | RESEARCH-004 | — | TestValidate, TestStoresLoad, TestT1TrustMatrix, oracle:testing/pki/oracle.sh | done | CCADB snapshot 2026-10-02: Mozilla 121, Chrome 101 roots |
| REQ-TTRS-2 | P0 | T1c | RESEARCH-004 | SR-20 | TestPrivateCATrustAnchors, TestT1TrustMatrix, script:testing/e2e/security.sh, script:testing/e2e/t1-phase.mjs#T1-E2E.9 | done | deviation: server-wide bundle is the --ca-bundle flag only (serve has no config file) |
| REQ-TTRS-3 | P1 | T1c | RESEARCH-004 | — | TestOSTrustIsOptIn, TestCertificatesAndTrust | done | tls scan --os-trust; the UI shows a "this machine" row only when present |
| REQ-TTRS-4 | P0 | T1c | RESEARCH-004 | — | TestT1TrustMatrix | done |  |
| REQ-TTRS-5 | P0 | T1c | RESEARCH-004 | — | TestNameMatch, TestT1ChainMatrix | done |  |
| REQ-TTRS-6 | P1 | T1c | RESEARCH-004 | — | TestRootConstraintsCarried, TestValidate, TestT1TrustMatrix, script:testing/pki/mutations.py | done | distrust-after, sct_not_after, program name constraints; removed CAs are absent |
| REQ-TREV-1 | P0 | T1b | RESEARCH-004 | SR-23 | TestOCSPAgainstOpenSSL, TestOCSPTamperedAndHostile, FuzzParseOCSP, report:docs/program/QA-REPORT-003.md#fuzz | done |  |
| REQ-TREV-2 | P0 | T1c | RESEARCH-004 | — | TestT1RevocationMatrix, script:testing/pki/mutations.py | done |  |
| REQ-TREV-3 | P0 | T1c | RESEARCH-004 | — | TestT1RevocationMatrix, script:testing/pki/mutations.py | done |  |
| REQ-TREV-4 | P0 | T1c | RESEARCH-004 | — | TestT1RevocationMatrix | done |  |
| REQ-TREV-5 | P0 | T1c | RESEARCH-004 | — | script:testing/e2e/t1-phase.mjs#T1-E2E.15 | done |  |
| REQ-TCT-1 | P0 | T1b | RESEARCH-004 | SR-23 | TestSCTList, TestT1ChainMatrix, FuzzParseSCTList | done | embedded and TLS sources tested end to end; OCSP-carried SCTs use the same decoder but no fixture carries them (QA-REPORT-003 §6) |
| REQ-TCT-2 | P1 | T1c | RESEARCH-004 | — | TestCTLookup, TestGeneratedTablesAreSelfConsistent | done |  |
| REQ-TCT-3 | P0 | T1c | RESEARCH-004 | — | TestT1ChainMatrix, TestT1TrustMatrix | done |  |
| REQ-TKX-1 | P0 | T1c | RESEARCH-004 | — | TestDHPrimesMatchOpenSSL, TestT1HTTPKeyExchangeAndVulnerabilities | done | 14 of 16 primes pinned to OpenSSL 3.5 named groups |
| REQ-TKX-2 | P0 | T1c | RESEARCH-004 | — | TestT1HTTPKeyExchangeAndVulnerabilities | done |  |
| REQ-THTP-1 | P0 | T1b | RESEARCH-004 | SR-23 | TestParseHSTS, TestHSTSHeaderParsedInScan, FuzzParseHSTS | done |  |
| REQ-THTP-2 | P0 | T1c | RESEARCH-004 | — | TestT1HTTPKeyExchangeAndVulnerabilities | done |  |
| REQ-THTP-3 | P0 | T1b | RESEARCH-004 | — | TestHSTSNilWhenNotSpeakingHTTP | done |  |
| REQ-TVLN-1 | P0 | T1c | RESEARCH-004 | — | TestLabelsDoNotChangeHygiene, TestT1HTTPKeyExchangeAndVulnerabilities, script:testing/pki/mutations.py | done |  |
| REQ-TVLN-2 | P1 | T1c | RESEARCH-004 | — | TestDROWNAcrossTheEstate, TestT1HTTPKeyExchangeAndVulnerabilities | done | index built from the latest completed scan of every endpoint at evaluation time |
| REQ-TVLN-3 | P0 | T1c | RESEARCH-004 | — | TestT1HTTPKeyExchangeAndVulnerabilities, script:testing/e2e/journey.mjs#E2E-05.4 | done |  |
| REQ-TDAT-1 | P0 | T1a | RESEARCH-004 | SR-22 | TestGeneratedTablesAreSelfConsistent, TestDHPrimesMatchOpenSSL, TestLifetimeTablePinned, TestSourcesRecorded | done | generator internal/refdata/gen; lifetime table hand-transcribed and pinned |
| REQ-TDAT-2 | P0 | T1a | RESEARCH-004 | — | report:docs/reference-data.md | done | all five lists passed the gate |
| REQ-TDAT-3 | P1 | T1a | RESEARCH-004 | — | TestSourcesRecorded, TestReferenceDataAndServerBundle | done | About page table and every section's How we tested |
| REQ-TUI-1 | P0 | T1d | RESEARCH-004 | — | script:testing/e2e/t1-phase.mjs#T1-E2E.4 | done |  |
| REQ-TUI-2 | P0 | T1d | RESEARCH-004 | — | TestSectionsAndFixFirst, script:testing/e2e/t1-phase.mjs#T1-E2E.5 | done |  |
| REQ-TUI-3 | P0 | T1d | RESEARCH-004 | — | script:testing/e2e/t1-phase.mjs#T1-E2E.6, script:testing/e2e/t1-phase.mjs#T1-E2E.14 | done |  |
| REQ-TUI-4 | P0 | T1d | RESEARCH-004 | — | script:testing/e2e/t1-phase.mjs#T1-E2E.7 | done |  |
| REQ-TUI-5 | P0 | T1d | RESEARCH-004 | — | TestSectionsAndFixFirst, TestLegacyReportsEvaluate, report:docs/program/QA-REPORT-003.md#legacy | done |  |
| REQ-TUI-6 | P0 | T1d | RESEARCH-004 | — | script:testing/e2e/t1-phase.mjs#T1-E2E.8, script:testing/e2e/t1-phase.mjs#T1-E2E.12 | done |  |
| REQ-TUI-7 | P0 | T1d | RESEARCH-004 | — | script:testing/e2e/t1-phase.mjs#T1-E2E.15 | done |  |
| REQ-TUI-8 | P0 | T1d | RESEARCH-004 | — | script:testing/e2e/journey.mjs#E2E-05.4, script:testing/e2e/t1-phase.mjs#T1-E2E.7 | done | Scan details closes the page; History stays a tab |
| REQ-TUI-9 | P0 | T1d | RESEARCH-004 | — | script:testing/e2e/t1-phase.mjs#T1-E2E.16 | done |  |
| REQ-TUI-10 | P1 | T1d | RESEARCH-004 | — |  | deferred | History does not yet mark which sections changed; P1, next increment |
| REQ-TUI-11 | P1 | T1d | RESEARCH-004 | — | report:docs/program/QA-REPORT-003.md#export | done | print/PDF prints the sectioned page; JSON export carries the evaluation with sections |
| REQ-TUI-12 | P0 | T1d | RESEARCH-004 | SR-20 | TestPrivateCATrustAnchors, script:testing/e2e/t1-phase.mjs#T1-E2E.9, script:testing/e2e/t1-phase.mjs#T1-E2E.10 | done |  |
| REQ-TUI-13 | P1 | T1d | RESEARCH-004 | — |  | deferred | Certificates page columns/filters for trust per store, OCSP and SCTs: P1, next increment |
| REQ-TUI-14 | P0 | T1d | RESEARCH-004 | — | TestUIDoesNotBorrowAnotherScannersRatingVocabulary | done |  |
| REQ-TNFR-1 | P0 | T1b | RESEARCH-004 | SR-23 | FuzzParseOCSP, FuzzParseSCTList, FuzzParseHSTS, FuzzServedChain, report:docs/program/QA-REPORT-003.md#fuzz | done | Windows fuzz engine stalls on encoding/asn1 targets; campaigns run on Linux (WSL), 6.4-10.5 M execs each |
| REQ-TNFR-2 | P0 | T1b | RESEARCH-004 | — | report:docs/program/QA-REPORT-003.md#dependencies | done | go.mod unchanged |
| REQ-TNFR-3 | P0 | T1d | RESEARCH-004 | SR-24 | TestNoInnerHTMLOrEval, script:testing/e2e/t1-phase.mjs#T1-E2E.13, script:testing/e2e/security.sh | done |  |
| REQ-TNFR-4 | P0 | T1c | RESEARCH-004 | — | TestPrivateCATrustAnchors, report:docs/program/QA-REPORT-003.md#legacy | done |  |
| REQ-TNFR-5 | P0 | T1c | RESEARCH-004 | — | report:docs/program/QA-REPORT-003.md#budget | done | +1 connection (address targets), +2 (named targets) |
| REQ-TNFR-6 | P0 | T1c | RESEARCH-004 | — | TestOpenAPIDescribesExactlyTheRegisteredRoutes | done | docs/tls-scanning.md, docs/methodology.md |
| REQ-TNFR-7 | P1 | T1c | RESEARCH-004 | — | TestCertificateExtensionsOnlyIn17 | done | docs/cbom-model.md lists what has no field |

## Security requirements (SECARCH-001) coverage

Each SR must be exercised by at least one requirement above; `TestRequirementsTraceability` checks that every `SR-nn` in SECARCH-001 appears in the SR column at least once, except those listed here as cross-cutting.

| SR | Verified by (requirement rows) | Mutation check |
|---|---|---|
| SR-01 | REQ-ING-2 | lower the limit check → oversize test must fail |
| SR-02 | REQ-UI-8, REQ-CERT-3 | reintroduce innerHTML with data → static check must fail |
| SR-03 | REQ-MOD-6, REQ-COR-4, REQ-ING-4 | mark uploads first-party → forged-collector test must fail |
| SR-04 | REQ-ING-3 | use document subject for placement → test must fail |
| SR-05 | REQ-COR-1, REQ-COR-3, REQ-COR-4 | auto-confirm on ambiguity → golden must fail |
| SR-06 | REQ-CERT-1, -2, -3, -4 | remove private-key skip → decoy test must fail |
| SR-07 | REQ-CERT-1 | remove per-call cap → limit test must fail; written syscall review |
| SR-08 | REQ-EXP-3, REQ-EXP-6 | drop token check on an export route → security.sh must fail |
| SR-09 | REQ-ING-10 | deferred with the requirement |
| SR-10 | REQ-MOD-1, REQ-MOD-5 | skip backup → failure-injection test must fail |
| SR-11 | REQ-SYS-2, REQ-COR-2, REQ-COR-7, REQ-ING-4 | skip audit write → audit test must fail |
| SR-12 | REQ-COR-7, REQ-EXP-6 | register a mutating route outside the guard → security.sh must fail |
| SR-13 | REQ-SYS-2 | concatenate a sort key → hostile-value test must fail |
| SR-14 | REQ-EXP-1, REQ-NFR-2 | add an unreviewed dependency → go.mod check must fail |
| SR-15 | REQ-COR-3, REQ-COR-8 | remove the widely-shared cap → test must fail |
| SR-16 | REQ-CERT-2 | follow symlinks unconditionally → symlink fixtures must fail |
| SR-17 | REQ-CERT-4 | echo a document fragment in an error → invariant test must fail |
| SR-18 | REQ-ING-5, REQ-ING-8 | let an import overwrite first-party → precedence test must fail |
| SR-19 | REQ-TSTG-5 | let the scan dial a second host → recording-dialer test must fail |
| SR-20 | REQ-TTRS-2, REQ-TUI-12 | accept key blocks in an anchor upload → decoy-key test must fail |
| SR-21 | REQ-TSTG-4 | follow a Location header → no-redirect test must fail |
| SR-22 | REQ-TDAT-1 | edit a generated list by hand → checksum test must fail |
| SR-23 | REQ-TNFR-1, REQ-TREV-1, REQ-TCT-1, REQ-THTP-1 | remove a length check → fuzz seed test must fail |
| SR-24 | REQ-TNFR-3 | render a certificate subject as markup → hostile journey check must fail |
