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
| REQ-TCRT-2 | P0 | T1b | RESEARCH-004 | — | TestNoSNIDifferent, TestRawChainStapleAndSCTs, TestT1TrustMatrix | done | deviations V-1, V-9: report-level noSni = same, different or failed; a different chain is shown and noted (CERT.NO-SNI-DIFFERENT, info), never judged as the endpoint's certificate |
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

## PRD-005 — Focused flows ([ENG-HANDOFF-004](../product/ENG-HANDOFF-004-focused-flows.md) work packages F1–F8; tests per [QA-PLAN-005](../product/QA-PLAN-005-focused-flows.md))

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-NAV-1 | P0 | F1 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#F-M2, script:testing/e2e/journey.mjs#E2E-14.1 | done | menu Scan, Reports, Inventory, Systems; footer About (plus the vendor credit and version, unchanged) |
| REQ-NAV-2 | P0 | F1 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#F-M6, script:testing/e2e/estate-phase.mjs#E2E-27.1, script:testing/e2e/t1-phase.mjs#T1-E2E.4 | done | 11 old addresses checked; redirects keep the query (?scan=); detail pages mark their parent active |
| REQ-NAV-3 | P1 | F1 | RESEARCH-005 | — | TestPrimarySurfacesSpeakTheUsersWords, report:docs/program/QA-REPORT-004.md#measures | done | brand line reads "TLS scanner and CBOM inventory", the short form of the PRD-005 §2 sentence (the space under the brand fits five words); the full sentence leads About and README |
| REQ-NAV-4 | P1 | F1 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.11 | done | count beside Systems in the menu and on the Decisions tab |
| REQ-HOME-1 | P0 | F2 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.0, script:testing/e2e/journey.mjs#F-M1 | done | input focused on load; Enter finds or adds the endpoint, scans and opens #/reports/N |
| REQ-HOME-2 | P0 | F2 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.2 | done |  |
| REQ-HOME-3 | P0 | F2 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.3 | done | a row with no result yet shows its scan status (failed, canceled, running) |
| REQ-HOME-4 | P0 | F2 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-01.0, script:testing/e2e/journey.mjs#E2E-12.1 | done |  |
| REQ-HOME-5 | P1 | F2 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.4 | done |  |
| REQ-RPT-1 | P0 | F3 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.5 | done | the TLS overview dashboard was removed; its counts are the fleet summary |
| REQ-RPT-2 | P0 | F3 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.5, script:testing/e2e/journey.mjs#F-M6 | done |  |
| REQ-RPT-3 | P0 | F3 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.9, script:testing/e2e/t1-phase.mjs#T1-M5 | done | Download opens one dialog (PDF, JSON, CBOM) |
| REQ-RPT-4 | P0 | F4 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.6 | done | checked at 1280x900, smaller than the 1440x900 the PRD names |
| REQ-RPT-5 | P0 | F4 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.7, script:testing/e2e/t1-phase.mjs#T1-E2E.6, script:testing/e2e/t1-phase.mjs#T1-E2E.17 | done | native details elements; Expand all / Collapse all |
| REQ-RPT-6 | P0 | F4 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.7, script:testing/e2e/journey.mjs#E2E-05.4 | done |  |
| REQ-RPT-7 | P0 | F4 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.8 | done |  |
| REQ-RPT-8 | P0 | F4 | RESEARCH-005 | — | report:docs/program/QA-REPORT-004.md#f-m3 | done | broken-chain 38.6 %, terrible-legacy 39.8 % (narrow margin), modern-hybrid 28.5 %; the two repeats removed (verdict sentence, IANA flag) stay visible in the section line and the IANA column |
| REQ-RPT-9 | P0 | F4 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.9, script:testing/e2e/t1-phase.mjs#T1-E2E.16 | done |  |
| REQ-INV-1 | P0 | F5 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#F-M4, TestInventoryIsTheMergedCBOM | done | deviation: four tiles (algorithms, quantum-vulnerable, certificates, sources); protocol counts are in the API summary, not a tile |
| REQ-INV-2 | P0 | F5 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#F-M4 | done | deviation: tabs Algorithms, Keys, Certificates, Protocols, Software, Sources ("TLS" is named Protocols; Keys added because keys are a CBOM asset type); suites and groups appear as algorithms, as in the CBOM |
| REQ-INV-3 | P0 | F5 | RESEARCH-005 | — | TestInventoryIsTheMergedCBOM | done | deviation: "where" lists endpoints, machines and imports (expandable), not systems; lastSeen per row; the source class is the place kind |
| REQ-INV-4 | P0 | F5 | RESEARCH-005 | — | TestInventoryIsTheMergedCBOM | done | source values endpoint, machine, import |
| REQ-INV-5 | P0 | F5 | RESEARCH-005 | — | TestInventoryIsTheMergedCBOM, TestOurOwnGoldenCBOMsValidateAgainstTheEmbeddedSchema | done | merged from the latest CBOM per endpoint (built from its scan) and per machine; 1.6 output strips every 1.7-only field; 413 above 20,000 components |
| REQ-INV-6 | P0 | F5 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.10, script:testing/e2e/journey.mjs#E2E-12.1, script:testing/e2e/journey.mjs#E2E-14.4, script:testing/e2e/journey.mjs#E2E-10.1 | done | machine upload and the collector how-to live in Sources, Machines |
| REQ-INV-7 | P1 | F5 | RESEARCH-005 | — | TestInventoryIsTheMergedCBOM | done | imported components keep an import-ID/ bom-ref prefix and the import as their place |
| REQ-FSYS-1 | P0 | F6 | RESEARCH-005 | — | script:testing/e2e/estate-phase.mjs#E2E-20.1 | done | tab "Migration order" |
| REQ-FSYS-2 | P0 | F6 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#E2E-F.11, script:testing/e2e/journey.mjs#F-M6 | done |  |
| REQ-FSYS-3 | P1 | F6 | RESEARCH-005 | — | script:testing/e2e/estate-phase.mjs#E2E-22.3 | done |  |
| REQ-LANG-1 | P0 | F7 | RESEARCH-005 | — | TestPrimarySurfacesSpeakTheUsersWords | done | checked files: index.html, scan.js, reports.js, inventory.js, systems.js; embedded older views keep some internal words (QA-REPORT-004 §5) |
| REQ-LANG-2 | P0 | F7 | RESEARCH-005 | — | TestPrimarySurfacesSpeakTheUsersWords | done | with a negative control |
| REQ-LANG-3 | P1 | F7 | RESEARCH-005 | — | report:docs/program/QA-REPORT-004.md#language | done | README first paragraph and the About hero line |
| REQ-UNF-1 | P0 | F2 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#F-M1 | done |  |
| REQ-UNF-2 | P0 | F5 | RESEARCH-005 | — | TestOpenAPIDescribesExactlyTheRegisteredRoutes, TestEveryOpenAPIOperationIsComplete | done | three GET routes added; none changed |
| REQ-UNF-3 | P0 | F8 | RESEARCH-005 | — | script:testing/e2e/journey.mjs#NFR-a11y.1, script:testing/e2e/journey.mjs#NFR-a11y.2, script:testing/e2e/journey.mjs#E2E-12.14, script:testing/e2e/t1-phase.mjs#T1-E2E.14 | done |  |
| REQ-UNF-4 | P0 | F5 | RESEARCH-005 | SR-02, SR-12 | TestNoInnerHTMLOrEval, TestPageHasNoInlineScriptOrStyle, script:testing/e2e/security.sh | done | inventory routes behind the token, Origin and Host checks (security.sh 75/75) |
| REQ-UNF-5 | P0 | F8 | RESEARCH-005 | — | report:docs/program/QA-REPORT-004.md#look | done | screenshots reviewed; the generic dashboard is gone |

## PRD-006 — Self-evident results, the CBOM up front, signature-driven inventory ([PRD-006](../product/PRD-006-self-evident-results-and-signatures.md); work packages R1 report, R2 evaluation, R3 signatures, R4 flow)

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-RV-1 | P0 | R1 | PRD-006 §1 | — | script:testing/e2e/journey.mjs#E2E-F.9 | done | tabs Summary, Configuration, Weaknesses, CBOM, History; ?tab=report/findings/details/tls land on the nearest tab |
| REQ-RV-2 | P0 | R1 | PRD-006 §1 | — | script:testing/e2e/journey.mjs#E2E-05.2, script:testing/e2e/journey.mjs#E2E-F.6 | done | why it matters per category, urgency per severity (D6) |
| REQ-RV-3 | P0 | R1 | PRD-006 §1 | — | script:testing/e2e/journey.mjs#E2E-R.1, script:testing/e2e/t1-phase.mjs#T1-E2E.14 | done | matrix rows SSLv2..TLS 1.3; suites by strength drawn as an SVG bar; the PDF carries the same table |
| REQ-RV-4 | P0 | R1 | PRD-006 §1 | — | script:testing/e2e/journey.mjs#E2E-05.4, script:testing/e2e/journey.mjs#E2E-05.5, script:testing/e2e/t1-phase.mjs#T1-E2E.16 | done | every check, found or not; attacks table; score breakdown; the PDF lists every check too |
| REQ-RV-5 | P0 | R1 | PRD-006 §1 | — | script:testing/e2e/journey.mjs#E2E-R.2 | done | components table, counts by type, CycloneDX 1.7 and 1.6 downloads, link to Inventory |
| REQ-RV-6 | P0 | R1 | PRD-006 §1 | — | script:testing/e2e/t1-phase.mjs#T1-E2E.14, script:testing/e2e/journey.mjs#NFR-a11y.2, script:testing/e2e/journey.mjs#E2E-F.7 | done |  |
| REQ-EV-1 | P0 | R2 | PRD-006 §1 | — | TestChecksListEveryRuleConsideredAndAgreeWithFindings | done | rules eval/5 |
| REQ-EV-2 | P0 | R2 | PRD-006 §1 | — | report:docs/program/QA-REPORT-005.md#reeval | done | Runner.ReevaluateOutdated on start; verified on a copy of the owner database (4 results to eval/5) |
| REQ-SG-1 | P0 | R3 | PRD-006 §1 | — | TestTheDatabaseIsValid | done | internal/signatures/signatures.json: 16 signatures (10 Windows, 6 Linux) and the SSH name map |
| REQ-SG-2 | P0 | R3 | PRD-006 §1 | — | TestValidationRefusesWhatAnEngineMustNotDo, TestTheDatabaseIsValid | done | no command capability exists; key paths, unknown capabilities or interpretations, bad patterns and stray parameters are refused |
| REQ-SG-3 | P0 | R3 | PRD-006 §1 | — | TestServedEnginesCarryTheirPlatformsSignatures, report:docs/program/QA-REPORT-005.md#engines | done | engines hold markers only; the PowerShell engine ran on Windows 11 (4 s); the shell engine is syntax-checked and run under Git Bash; real Linux not run here |
| REQ-SG-4 | P0 | R3 | PRD-006 §1 | — | TestInventoryScriptsAndFactsUpload, script:testing/e2e/journey.mjs#E2E-14.2 | done | GET /api/v1/collector/signatures; the how-to lists every signature: what, from where, how, why |
| REQ-SG-5 | P0 | R3 | PRD-006 §1 | — | TestSignatureFactsBecomeComponents, TestLinuxFactsBecomeTheCollectorsCBOM | done | library files through the knowledge base; Schannel, SSH, OpenSSL, crypto policy and programs as components; anything else as observed configuration |
| REQ-SG-6 | P1 | R3 | PRD-006 §1 | — | TestSignatureFactsBecomeComponents | done | one coverage line per signature, including "not present" |
| REQ-FL-1 | P0 | R4 | PRD-006 §1 | — | script:testing/e2e/journey.mjs#F-M2, script:testing/e2e/estate-phase.mjs#E2E-20.1 | done | Systems in the sidebar footer with its decision count |
| REQ-FL-2 | P1 | R4 | PRD-006 §1 | — | report:docs/program/QA-REPORT-005.md#flow | done | the CBOM tab links to Inventory; Inventory rows link to reports |

## PRD-007 · Launch 1.0 ([PRD-007](../product/PRD-007-launch-1-0.md); work packages WP-1 to WP-9; results in [QA-REPORT-007](QA-REPORT-007.md))

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-TR-1 | P0 | WP-1 | PRD-007 | — | TestPasswordChangeRotatesTheSession | done | every other session of the account ends; the browser that changed it is signed in again |
| REQ-TR-2 | P0 | WP-1 | PRD-007 | — | TestSessionCookieUsesTheHostPrefixOverHTTPS, script:testing/e2e/security.sh | done | __Host-ch_session over HTTPS (own listener or a trusted proxy saying so) |
| REQ-TR-3 | P0 | WP-1 | PRD-007 | — | TestSetupCodeExpires | done | 24 hours; the log line gives the time |
| REQ-TR-4 | P0 | WP-1 | PRD-007 | — | TestShellEngineIsHardened, script:testing/deploy/linux-script.sh | done | engine 2.0.1; Windows ACL read back in the test; facts file 0600 on Debian, UBI and Alpine |
| REQ-TR-5 | P1 | WP-1 | PRD-007 | — | TestOldBackupsArePruned | done | newest three kept; Open holds the notices until SetLogger |
| REQ-TR-6 | P0 | WP-1 | PRD-007 | — | FuzzParseFacts, FuzzImportSystemsCSV | done | CI fuzz job on Linux; locally the CSV target ran 272k execs clean, the facts target stalls on Windows (known Go issue) |
| REQ-TR-7 | P0 | WP-1 | PRD-007 | — | TestScriptsCommandMatchesTheServer, script:testing/e2e/launch-phase.mjs#E2E-14.5 | done | GoReleaser before-hook exports the scripts and inventory-scripts.sha256 into the checksums; not yet run in a release |
| REQ-TR-8 | P1 | WP-1 | PRD-007 | — | script:testing/e2e/launch-phase.mjs#E2E-14.5 | done | RemoteSigned after Unblock-File verified against a Mark-of-the-Web file on Windows 11 |
| REQ-TR-9 | P1 | WP-1 | PRD-007 | — | report:docs/program/QA-REPORT-007.md#tr9 | done | x/text v0.41.0; govulncheck: no vulnerabilities; SECURITY.md updated |
| REQ-SS-1 | P0 | WP-2 | PRD-007 | — | TestTheServerPassesItsOwnScan, script:testing/e2e/security.sh | done | six ECDHE AEAD suites in TLS 1.2; CBC and RSA key transport refused (openssl s_client) |
| REQ-SS-2 | P0 | WP-2 | PRD-007 | — | TestHSTSOnlyOverTLS, script:testing/e2e/security.sh | done | not sent on plain HTTP or for a forged X-Forwarded-Proto |
| REQ-SS-3 | P0 | WP-2 | PRD-007 | — | TestTheServerPassesItsOwnScan, script:testing/deploy/smoke.sh | done | L3 with only the test certificate findings and two inherent notes |
| REQ-BR-1 | P0 | WP-3 | PRD-007 | — | TestStyleTokensMatchDesign | done | DESIGN.md v2 token tables are parsed and compared with style.css, light and dark |
| REQ-BR-2 | P0 | WP-3 | PRD-007 | — | TestStyleTokensMatchDesign, script:testing/e2e/launch-phase.mjs#E2E-B.4 | done | Geist 1.4.2 and Newsreader (fontsource 5.2.8) woff2 with their OFL licences; Inter and JetBrains Mono removed |
| REQ-BR-3 | P0 | WP-3 | PRD-007 | — | TestLogosAreFlat | done | superseded by UX-REVIEW-008 S1: a plain flat padlock icon replaces concept B (owner); still flat, same files and test |
| REQ-BR-4 | P0 | WP-3 | PRD-007 | — | TestNoDecorativeGradients | done | only .skeleton and .progress-fill |
| REQ-BR-5 | P0 | WP-3 | PRD-007 | — | TestTokenContrast, script:testing/e2e/launch-phase.mjs#NFR-a11y.contrast | done | token pairs and rendered pages, light and dark; lowest rendered ratio 4.97:1 |
| REQ-BR-6 | P1 | WP-3 | PRD-007 | — | TestPDFCarriesTheLockup | done | flat navy cover, the mark drawn as polygons, by Offset Security, the standards line |
| REQ-ST-1 | P0 | WP-4 | PRD-007 | — | TestTheProductTellsItsStory, script:testing/e2e/auth-phase.mjs#E2E-B.1 | done | the panel stacks above the form on a phone (E2E-B.1m); since UX-REVIEW-008 S3 sign-in is off by default, so the panel shows once sign-in is on |
| REQ-ST-2 | P0 | WP-4 | PRD-007 | — | TestTheProductTellsItsStory, script:testing/e2e/launch-phase.mjs#E2E-B.2 | done | headline: Scan an endpoint for post-quantum readiness |
| REQ-ST-3 | P1 | WP-4 | PRD-007 | — | TestTheProductTellsItsStory, script:testing/e2e/launch-phase.mjs#E2E-B.3 | done | pillars, does and does not, standards, Offset credit and PQC practice link, then the reference |
| REQ-ST-4 | P1 | WP-4 | PRD-007 | — | TestHelpCarriesTheOneLiner | done | help, version and the image description label |
| REQ-ST-5 | P0 | WP-4 | PRD-007 | — | TestUICopyRules | done | comments stripped; banned words and letter grades checked too |
| REQ-CL-1 | P0 | WP-5 | PRD-007 | — | TestTLSScanPrintsTheVerdict, TestTLSScanSaysWhenATargetCouldNotBeScanned | done | verdict first; --details adds the raw report |
| REQ-CL-2 | P0 | WP-5 | PRD-007 | — | TestTLSScanJSONHasTheEvaluation | done | breaking change from the old array of reports: in the CHANGELOG |
| REQ-CL-3 | P0 | WP-5 | PRD-007 | — | TestFailOnConditions | done | exit 3; an unscannable target fails a policy |
| REQ-CL-4 | P1 | WP-5 | PRD-007 | — | TestReadmeLinksResolve, report:docs/CI.md | done | the Actions example needs a published release to run end to end |
| REQ-SX-1 | P0 | WP-6 | PRD-007 | — | TestSTARTTLSMatchesDirectTLS | done | all seven protocols match a direct scan of the same configuration |
| REQ-SX-2 | P0 | WP-6 | PRD-007 | — | TestSTARTTLSChoice | done | auto by port, none, a protocol, or a scheme (smtp://, submission://, ldaps://...) |
| REQ-SX-3 | P0 | WP-6 | PRD-007 | — | TestEndpointKeepsItsSTARTTLS, script:testing/e2e/launch-phase.mjs#E2E-X.1 | done | the HTTP area is reported not applicable, not not-checked |
| REQ-SX-4 | P0 | WP-6 | PRD-007 | — | TestSTARTTLSRefusalIsExplained | done | refusals answer in well under a second; a direct-TLS port asked for SMTP says so after the timeout |
| REQ-SX-5 | P1 | WP-6 | PRD-007 | — | script:testing/e2e/launch-phase.mjs#E2E-X.1, script:testing/e2e/screenshots.mjs | done | demo-targets base+11..base+17 |
| REQ-DP-1 | P0 | WP-7 | PRD-007 | — | script:testing/deploy/smoke.sh | done | 14/14 with Podman 6.0.2 inside its machine; CI runs it with Docker |
| REQ-DP-2 | P0 | WP-7 | PRD-007 | — | TestComposeFilesAreHardened, script:testing/deploy/smoke.sh | done | compose-caddy.yml not run here: the Caddy image was not among the approved downloads |
| REQ-DP-3 | P1 | WP-7 | PRD-007 | — | TestSystemdUnitIsSandboxed, report:docs/program/QA-REPORT-007.md#systemd | done | systemd-analyze verify and security 1.5 OK; the binary ran under the unit sandbox |
| REQ-DP-4 | P0 | WP-7 | PRD-007 | — | TestDBBackup, script:testing/deploy/smoke.sh | done | restore documented in docs/deploy.md |
| REQ-DP-5 | P0 | WP-7 | PRD-007 | — | script:testing/deploy/linux-script.sh | done | 26/26 on Debian 12, UBI 9.6 and Alpine 3.20 |
| REQ-DP-6 | P0 | WP-7 | PRD-007 | — | report:docs/engineering/RELEASE-CHECKLIST-1.0.md | done | for the owner |
| REQ-LM-1 | P0 | WP-8 | PRD-007 | — | TestReadmeLinksResolve | done | screenshots from demo data only |
| REQ-LM-2 | P1 | WP-8 | PRD-007 | — | TestReadmeLinksResolve, TestSiteMakesNoExternalRequests | done | seven pages; the Pages workflow runs once the repository is on GitHub |
| REQ-LM-3 | P1 | WP-8 | PRD-007 | — | script:testing/e2e/screenshots.mjs | done | docs/img: six light, two dark |
| REQ-LM-4 | P2 | WP-8 | PRD-007 | — | report:docs/launch/posts/README.md | done | for Offset to review |
| REQ-AC-1 | P0 | WP-9 | PRD-007 | — | TestScanScopeRefusesAtAddAndConnect, TestScanScopeParsingAndMatching, script:testing/e2e/security.sh | done | networks enforced on the real remote address of every connection |
| REQ-AC-2 | P0 | WP-9 | PRD-007 | — | TestEveryChangeIsAudited | done | a route in neither audit table fails the test |
| REQ-AC-3 | P0 | WP-9 | PRD-007 | — | TestAuditExportIsAdminOnly, script:testing/e2e/launch-phase.mjs#E2E-A.11 | done | formula-safe CSV; filters by person and kind |
| REQ-AC-4 | P1 | WP-9 | PRD-007 | — | TestScanRecordsWhoStartedIt, script:testing/e2e/launch-phase.mjs#E2E-A.13 | done | person, automation token or schedule; earlier scans show not recorded |

## PRD-008 · Post-quantum signatures in TLS, and SSH endpoints ([PRD-008](../product/PRD-008-pq-signatures-and-ssh.md); WP-A results in [QA-REPORT-008](QA-REPORT-008.md))

WP-B to WP-G (SSH) ship in the second pull request, amended 2026-10-13 per [STRATEGY-003](../strategy/STRATEGY-003-multi-protocol-product.md) (a page per protocol, baseline conformance). Results in QA-REPORT-008 §5 to §8.

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-PQS-1 | P0 | WP-A | PRD-008 | — | TestTLS13HellosOfferMLDSA | done | pinned against crypto/tls; TLS 1.2 hellos do not offer ML-DSA |
| REQ-PQS-2 | P0 | WP-A | PRD-008 | — | TestAnMLDSAOnlyServerIsSeen, TestAnMLDSAOnlyServerIsL4 | done | hermetic server picks its certificate before answering, as OpenSSL does; before the fix it read as no TLS 1.3, L0 |
| REQ-PQS-3 | P0 | WP-A | PRD-008 | — | TestSignatureStageListsAcceptedSchemes | done | 15 connections; each hello carries real key shares so a Go server cannot answer with HelloRetryRequest before choosing |
| REQ-PQS-4 | P0 | WP-A | PRD-008 | — | TestSignatureStageControlCatchesServersThatIgnoreTheList | done | control code point 0xFE01 (private use) |
| REQ-PQS-5 | P0 | WP-A | PRD-008 | — | TestDualCertificateServerReachesL4 | done | control accepted keeps L3; ML-DSA without a hybrid group stays L1 |
| REQ-PQS-6 | P0 | WP-A | PRD-008 | — | TestEndpointCBOMListsAcceptedSignatureAlgorithms, script:testing/e2e/pqs-phase.mjs#E2E-PQS.1 | done | report Configuration tab, PDF stage table and endpoint CBOM |
| REQ-PQS-7 | P0 | WP-A | PRD-008 | — | TestOldReportsEvaluateUnchanged | done | a report without the stage shows it as not collected |
| REQ-PQS-8 | P1 | WP-A | PRD-008 | — | script:testing/e2e/pqs-phase.mjs#E2E-PQS.1 | done | demo-targets base+18 (ML-DSA only) and base+19 (ECDSA + ML-DSA), both L4 in the journey |
| REQ-PQS-9 | P0 | WP-A | PRD-008 | — | TestDocsNameTheGoVersion | done | go.mod go 1.27.0; README, CONTRIBUTING and badge agree |
| REQ-SHP-1 | P0 | WP-B | PRD-008 | — | TestIdentificationIsParsed, FuzzIdentification | done | up to 20 preceding lines; SSH-1-only servers stop there |
| REQ-SHP-2 | P0 | WP-B | PRD-008 | — | TestKEXINITListsMatchTheServer, FuzzKEXINIT, oracle:testing/ssh/oracle.sh | done | lists AGREE with sshd -T on OpenSSH 9.2 and 10.0, three configurations each |
| REQ-SHP-3 | P0 | WP-B | PRD-008 | — | TestNegotiationCompletesTheHybridExchange, oracle:testing/ssh/oracle.sh | done | negotiated kex AGREEs with ssh -vv on 10.0; implemented: ML-KEM hybrid, curve25519, ECDH P-256/384/521, MODP group1/14/16 (not group18 or group exchange: such a server is judged on its lists, host keys inconclusive with the reason) |
| REQ-SHP-4 | P0 | WP-B | PRD-008 | — | TestHostKeysAreReadPerAlgorithm, oracle:testing/ssh/oracle.sh | done | fingerprints AGREE with ssh-keygen; every signature verified |
| REQ-SHP-5 | P1 | WP-B | PRD-008 | — | TestHostCertificatesAreParsed | done |  |
| REQ-SHP-6 | P0 | WP-B | PRD-008 | — | TestStagesSayWhatTheyCouldNotDo | done |  |
| REQ-SHP-7 | P0 | WP-B | PRD-008 | — | TestSSHScanRespectsTheGuardAndBudget, script:testing/e2e/security.sh | done | security.sh: ssh:// to the metadata address and to loopback refused |
| REQ-SHP-8 | P0 | WP-B | PRD-008 | — | FuzzKEXINIT, FuzzHostKeyBlob, FuzzKEXReply, FuzzIdentification | done |  |
| REQ-SHE-1 | P0 | WP-C | PRD-008 | — | TestSSHEvaluationHasTheSameShape, TestFleetSummaryByProtocol, TestFleetFindingsSpansAssetKinds | done |  |
| REQ-SHE-2 | P0 | WP-C | PRD-008 | — | TestSSHReadinessLevels | done |  |
| REQ-SHE-3 | P0 | WP-C | PRD-008 | — | TestSntrupCountsButIsNoted | done |  |
| REQ-SHE-4 | P0 | WP-C | PRD-008 | — | TestSSHRules, TestEverySSHRuleIsCited, TestUMAC64AloneIsLow | done | 18 rules; a 64-bit UMAC alone is Low |
| REQ-SHE-5 | P0 | WP-C | PRD-008 | — | TestSSHHasNoHygieneScore, TestFleetBandsCountTLSOnly, TestSSHServersAreNamedAndNotScored, script:testing/e2e/ssh-phase.mjs#E2E-H.2 | done | stored band empty, score -1; no screen, PDF or CLI shows a score |
| REQ-SHE-6 | P1 | WP-C | PRD-008 | — | TestSSHRemediationNamesTheDirective | done |  |
| REQ-SHE-7 | P1 | WP-C | PRD-008 | — | TestSSHDiff | done | the diff compares baseline verdicts, not scores |
| REQ-SHW-1 | P0 | WP-D | PRD-008 | — | TestSSHTargetsAreRecognised, script:testing/e2e/ssh-phase.mjs#E2E-H.1, script:testing/e2e/ssh-phase.mjs#E2E-H.1e | done | scan-box chip: Scan as TLS / SSH, a click switches it |
| REQ-SHW-2 | P0 | WP-D | PRD-008 | — | script:testing/e2e/ssh-phase.mjs#E2E-H.1c, script:testing/e2e/ssh-phase.mjs#E2E-H.1d | done | old #/endpoints/{id} links to SSH servers redirect |
| REQ-SHW-3 | P0 | WP-D | PRD-008 | — | TestSSHReportCopyHasNoTLSWords, script:testing/e2e/ssh-phase.mjs#E2E-H.2, script:testing/e2e/ssh-phase.mjs#E2E-H.2c | done | baseline tile and action item; Configuration leads with the baseline block |
| REQ-SHW-4 | P0 | WP-D | PRD-008 | — | TestFleetSummaryByProtocol, script:testing/e2e/ssh-phase.mjs#E2E-H.3, script:testing/e2e/ssh-phase.mjs#E2E-H.3c | done | Overview cards per protocol; the certificate-expiry figure folded into the TLS card |
| REQ-SHW-5 | P0 | WP-D | PRD-008 | — | TestSSHEndpointWorkflow | done |  |
| REQ-SHW-6 | P1 | WP-D | PRD-008 | — | script:testing/e2e/ssh-phase.mjs#E2E-H.4 | done |  |
| REQ-SHW-7 | P0 | WP-D | PRD-008 | — | script:testing/e2e/ssh-phase.mjs#E2E-H.3b | done | one filter: everywhere, TLS endpoints, SSH servers, machines |
| REQ-SHW-8 | P0 | WP-D | PRD-008 | — | TestTheProductTellsItsStory, TestHelpCarriesTheOneLiner, TestNoSurfaceSaysTLSScannerAlone | done |  |
| REQ-SHB-1 | P0 | WP-G | PRD-008 | — | TestEveryBaselineEntryIsCited | done |  |
| REQ-SHB-2 | P0 | WP-G | PRD-008 | — | TestCipherHorizonBaseline2026, oracle:testing/ssh/oracle.sh | done | stock OpenSSH 10 fails on its MACs only |
| REQ-SHB-3 | P0 | WP-G | PRD-008 | — | TestBaselineConformance, TestHardenedServerMeetsTheBaseline, TestBaselineChangesMarkTheirSection | done |  |
| REQ-SHB-4 | P0 | WP-G | PRD-008 | — | TestGeneratedSSHDConfig, oracle:testing/ssh/oracle.sh | done | comments on lines of their own; the header says lines go first |
| REQ-SHB-5 | P0 | WP-G | PRD-008 | — | TestBaselineIsStoredWithTheScan | done | migration 14 |
| REQ-SHB-6 | P0 | WP-G | PRD-008 | — | TestSSHFailOnBaseline, TestSSHBaselinesCommand | done |  |
| REQ-SHB-7 | P1 | WP-G | PRD-008 | — | — | deferred | BSI publishes TR-02102-4 only as image PDFs; the transcription found is of an older edition. Needs a verified transcription of the 2026-01 tables (owner) |
| REQ-SHB-8 | P0 | WP-G | PRD-008 | — | TestSSHPDF | done |  |
| REQ-SHO-1 | P0 | WP-E | PRD-008 | — | TestSSHCBOMIsSchemaValid, TestSSHCBOMMarksTheNegotiatedChoices | done |  |
| REQ-SHO-2 | P0 | WP-E | PRD-008 | — | TestSSHEndpointWorkflow | done | the inventory CBOM carries protocol/ssh/2.0 |
| REQ-SHO-3 | P0 | WP-E | PRD-008 | — | TestSSHPDF | done |  |
| REQ-SHO-4 | P0 | WP-E | PRD-008 | — | TestSSHScanPrintsTheVerdict, TestSSHFailOn | done |  |
| REQ-SHO-5 | P1 | WP-E | PRD-008 | — | TestSSHScanProjectsIntoTheGraph | done |  |
| REQ-SHO-6 | P1 | WP-E | PRD-008 | — | TestOpenAPIDescribesSSH, TestOpenAPIDescribesExactlyTheRegisteredRoutes | done |  |
| REQ-SHN-1 | P0 | WP-F | PRD-008 | — | TestHardenedServerMeetsTheBaseline, script:testing/e2e/ssh-phase.mjs#E2E-H.1b | done | base+20..27; base+27 meets the baseline |
| REQ-SHN-2 | P0 | WP-F | PRD-008 | — | oracle:testing/ssh/oracle.sh | done | 37 AGREE, 0 DISAGREE; the baseline lines pass sshd -t and the rescan meets the baseline on 9.2 and 10.0 |
| REQ-SHN-3 | P0 | WP-F | PRD-008 | — | report:docs/ssh-scanning.md | done | and methodology.md (SSH), CI.md, README |
| REQ-SHN-4 | P0 | WP-F | PRD-008 | — | report:docs/program/QA-REPORT-008.md | done |  |
| REQ-SHN-5 | P0 | WP-F | PRD-008 | — | FuzzIdentification, FuzzKEXINIT, FuzzHostKeyBlob, FuzzKEXReply | done | 3.2M to 5.2M executions each, clean |

## PRD-009 · Charts you can act on, quiet motion, a chosen port, a complete CBOM ([PRD-009](../product/PRD-009-interactive-charts-motion-port-cbom.md); results in [QA-REPORT-009](QA-REPORT-009.md))

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-CHT-1 | P0 | WP-1 | PRD-009 | — | script:testing/e2e/charts-phase.mjs#E2E-CHT-1 | done | one protocol at a level: the row is the link; both: two links |
| REQ-CHT-2 | P0 | WP-1 | PRD-009 | — | TestInventoryFiltersByQuantumAndPurpose, script:testing/e2e/charts-phase.mjs#E2E-CHT-2 | done | `name` (exact) added so a Replace-first row opens one item; the algorithms list says how many keys share the status |
| REQ-CHT-3 | P0 | WP-1 | PRD-009 | — | script:testing/e2e/charts-phase.mjs#E2E-CHT-3 | done | the ring counts algorithms and keys; the two lists add up to it |
| REQ-CHT-4 | P1 | WP-1 | PRD-009 | — | script:testing/e2e/charts-phase.mjs#E2E-CHT-4 | done | stretched-link cell; no link inside a link |
| REQ-CHT-5 | P1 | WP-1 | PRD-009 | — | script:testing/e2e/charts-phase.mjs#E2E-CHT-5 | done |  |
| REQ-CHT-6 | P0 | WP-1 | PRD-009 | — | TestChartsAreKeyboardReachable, script:testing/e2e/charts-phase.mjs#E2E-CHT-6 | done |  |
| REQ-MOT-1 | P1 | WP-2 | PRD-009 | — | script:testing/e2e/charts-phase.mjs#E2E-MOT-1 | done |  |
| REQ-MOT-2 | P2 | WP-2 | PRD-009 | — | TestCountUpIsUsedOnlyForFigures, script:testing/e2e/charts-phase.mjs#E2E-MOT-2 | done | ends on its value even when the tab is hidden |
| REQ-MOT-3 | P2 | WP-2 | PRD-009 | — | report:docs/product/UX-REVIEW-009-charts-and-motion.md | done |  |
| REQ-MOT-4 | P1 | WP-2 | PRD-009 | — | TestMotionRulesAreRespected, report:docs/product/UX-REVIEW-009-charts-and-motion.md | done |  |
| REQ-MOT-5 | P0 | WP-2 | PRD-009 | — | TestMotionRulesAreRespected, script:testing/e2e/charts-phase.mjs#E2E-MOT-R | done | `.progress-fill` width is the one stated exception |
| REQ-PORT-1 | P0 | WP-3 | PRD-009 | — | TestServePortFlag, TestServeAddrAndPortConflict, TestServeListensOnTheGivenPort | done |  |
| REQ-PORT-2 | P0 | WP-3 | PRD-009 | — | TestServePortFromEnvironment, TestHealthcheckFollowsPortEnvironment, TestServeAndHealthcheckFollowThePortEnvironment | done |  |
| REQ-PORT-3 | P0 | WP-3 | PRD-009 | — | TestServeBusyPortSaysWhatToDo, TestBusyPortMessageSuggestsTheNextPort | done | WSAEADDRINUSE on Windows, EADDRINUSE elsewhere |
| REQ-PORT-4 | P1 | WP-3 | PRD-009 | — | TestServiceURLFollowsPort, script:testing/deploy/smoke.sh#PORT | done |  |
| REQ-CBM-1 | P0 | WP-4 | PRD-009 | — | TestLegacySuiteCiphersAreAssets | done | CBOM-REVIEW-002 C-1 |
| REQ-CBM-2 | P0 | WP-4 | PRD-009 | — | TestNISTCurveGroupsAreAssets | done | C-2 |
| REQ-CBM-3 | P0 | WP-4 | PRD-009 | — | TestCertificateSignatureVariantHasOID | done | C-3 |
| REQ-CBM-4 | P1 | WP-4 | PRD-009 | — | TestCatalogueOIDsAreCited | done | C-4 |
| REQ-CBM-5 | P1 | WP-4 | PRD-009 | — | TestCertificateSerialAndFingerprintIn17 | done | C-5 |
| REQ-CBM-6 | P2 | WP-4 | PRD-009 | — | TestSuiteAlgorithmsAreUnique | done | C-6 |
| REQ-CBM-7 | P1 | WP-4 | PRD-009 | — | report:docs/product/CBOM-REVIEW-002-oids-and-completeness.md | done | docs/cbom-model.md, tls-scanning.md, exporting.md |

## PRD-010 · Classical strength for every detected algorithm ([PRD-010](../product/PRD-010-classical-strength.md); results in [QA-REPORT-010](QA-REPORT-010.md))

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-STR-1 | P0 | — | ENH-001 | — | TestEveryAlgorithmHasACitedStrength, TestGNFSReproducesNISTTables, TestECCStrengthReproducesSP800186, TestSymmetricAndHashStrengthsFollowSP80057 | done | curve rule corrected to SP 800-186's levels (K-233 is 112, not 120) |
| REQ-STR-2 | P0 | — | ENH-001 | — | TestSuiteStrengthIsTheWeakestPart, TestSingleDESIsInsecure, TestEverySuiteInTheRegistryIsRated | done | fixes #18 |
| REQ-STR-3 | P0 | — | ENH-001 | — | TestEvaluationCarriesStrength | done | eval/9 |
| REQ-STR-4 | P0 | — | ENH-001 | — | TestPDFAndEvaluationAgreeOnStrength, script:testing/e2e/strength-phase.mjs#E2E-STR-1 | done | the JS and Go heuristics are deleted |
| REQ-STR-5 | P1 | — | ENH-001 | — | TestDetailsShowSuiteStrength | done |  |
| REQ-STR-6 | P0 | — | ENH-001 | — | TestInventoryRowsCarryClassicalStrength, script:testing/e2e/strength-phase.mjs#E2E-STR-2 | done |  |
| REQ-STR-7 | P1 | — | ENH-001 | — | TestSSHAlgorithmsCarryStrength | done | RSA and DSA host keys by the presented key's size; SHA-1 signatures broken |
| REQ-STR-8 | P0 | — | ENH-001 | — | TestCBOMCarriesClassicalSecurityLevel, TestLegacyOutputIsPreserved | done | host goldens regenerated; the legacy test allows exactly this addition |
| REQ-STR-9 | P1 | — | ENH-001 | — | report:docs/methodology.md, script:testing/e2e/strength-phase.mjs#E2E-STR-3 | done | Help (the report's legend opens it at the topic), cbom-model, CHANGELOG, README |

## PRD-011 · Every algorithm by class, and a flow that explains itself ([PRD-011](../product/PRD-011-algorithm-classes-and-flow.md); results in [QA-REPORT-011](QA-REPORT-011.md))

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-CLS-1 | P0 | — | ENH-002 | — | TestEveryAlgorithmHasAClass | done | class from the CycloneDX primitive; combiner (hybrids) is asymmetric |
| REQ-CLS-2 | P0 | — | ENH-002 | — | TestSuiteHasItsHashPart, TestEverySuiteInTheRegistryIsRated | done | OD-1: counts as a part; never decides a word on today's numbers |
| REQ-CLS-3 | P0 | — | ENH-002 | — | TestSignatureAlgorithmIsHashAndKey, TestHashKDFStrengthFollowsTable3 | done | Go, OID and Java spellings |
| REQ-CLS-4 | P0 | — | ENH-002 | — | TestEvaluationListsAlgorithmsByClass | done | eval/10 |
| REQ-CLS-5 | P0 | — | ENH-002 | — | script:testing/e2e/classes-phase.mjs#E2E-CLS-1 | done | OD-2 was first card; PRD-013 moved it last (protocols first, owner comment) |
| REQ-CLS-6 | P0 | — | ENH-002 | — | script:testing/e2e/classes-phase.mjs#E2E-CLS-2 | done |  |
| REQ-CLS-7 | P1 | — | ENH-002 | — | TestInventoryFiltersByClass, script:testing/e2e/classes-phase.mjs#E2E-CLS-3 | done |  |
| REQ-CLS-8 | P1 | — | ENH-002 | — | TestPDFListsAlgorithmsByClass, TestDetailsShowAlgorithmsByClass | done | the CLI also lists each suite's parts |
| REQ-UXF-1 | P0 | — | UX-REVIEW-010 | — | TestBandsHaveTheirOwnWords, TestOldBandsAreMigrated | done | migration 15; old names read as new in stored evaluations |
| REQ-UXF-2 | P1 | — | UX-REVIEW-010 | — | script:testing/e2e/classes-phase.mjs#E2E-UXF-1 | done |  |
| REQ-UXF-3 | P1 | — | UX-REVIEW-010 | — | script:testing/e2e/classes-phase.mjs#E2E-UXF-1 | done | names the weakest suite; links stay on the suites row |
| REQ-UXF-4 | P2 | — | UX-REVIEW-010 | — | script:testing/e2e/classes-phase.mjs#E2E-UXF-2, script:testing/e2e/classes-phase.mjs#E2E-UXF-1 | done | the hygiene tile opened About this report: fixed |
| REQ-UXF-5 | P2 | — | UX-REVIEW-010 | — | script:testing/e2e/classes-phase.mjs#E2E-UXF-2 | done |  |
| REQ-CLS-9 | P1 | — | ENH-002 | — | report:docs/methodology.md | done | Help, CHANGELOG, README |

## PRD-012 · Open any certificate and read the whole X.509 document ([PRD-012](../product/PRD-012-certificate-viewer.md); results in [QA-REPORT-011](QA-REPORT-011.md))

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-XV-1 | P0 | — | ENH-003 | — | TestX509DecodeShowsEveryExtension, TestX509EndpointDecodesTheServedCertificate | done | internal/x509view |
| REQ-XV-2 | P0 | — | ENH-003 | — | FuzzX509Decode, TestX509DecodeRefusesWhatIsNotACertificate | done | at most 64 KiB decoded |
| REQ-XV-3 | P1 | — | ENH-003 | — | TestX509WithoutDERSaysSo | done | only endpoint scans keep DER |
| REQ-XV-4 | P0 | — | ENH-003 | — | script:testing/e2e/x509-phase.mjs#E2E-XV-1 | done | `#/certificates/{sha256}?scan=` |
| REQ-XV-5 | P0 | — | ENH-003 | — | script:testing/e2e/x509-phase.mjs#E2E-XV-2 | done | the panel is now *Quick look* |
| REQ-XV-6 | P1 | — | ENH-003 | — | TestPEMRoundTrip, script:testing/e2e/x509-phase.mjs#E2E-XV-3 | done |  |
| REQ-XV-7 | P0 | — | ENH-003 | — | script:testing/e2e/x509-phase.mjs#E2E-XV-4 | done | the hostile demo target (9450) |
| REQ-XV-8 | P1 | — | ENH-003 | — | script:testing/e2e/x509-phase.mjs#E2E-XV-5 | done |  |
| REQ-XV-9 | P2 | — | ENH-003 | — | report:docs/methodology.md | done | Help › Scan a TLS endpoint; openapi.json |

## PRD-013 · Instruments, not paragraphs ([PRD-013](../product/PRD-013-visual-rebuild.md); results in [QA-REPORT-012](QA-REPORT-012.md))

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-VIS-1 | P0 | — | UX-DESIGN-011 | — | TestInstrumentsAreSharedAndLabelled, script:testing/e2e/visual-phase.mjs#E2E-VIS-1 | done | viz.js; a question mark for "not classified", a dot for "no verdict" |
| REQ-VIS-2 | P0 | — | UX-DESIGN-011 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-2, script:testing/e2e/journey.mjs#E2E-05.2 | done | a fifth tile (Not checked) joins the strip's row |
| REQ-VIS-3 | P0 | — | UX-DESIGN-011 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-3, script:testing/e2e/strength-phase.mjs#E2E-STR-1, script:testing/e2e/classes-phase.mjs#E2E-CLS-2 | done | protocols first (owner comment on the concept); supersedes PRD-011 OD-2 |
| REQ-VIS-4 | P0 | — | UX-DESIGN-011 | — | script:testing/e2e/x509-phase.mjs#E2E-XV-1, script:testing/e2e/t1-phase.mjs#T1-E2E.8 | done |  |
| REQ-VIS-5 | P0 | — | UX-DESIGN-011 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-4, script:testing/e2e/t1-phase.mjs#T1-E2E.15 | done | HSTS shows the header as sent; an invalid one says browsers ignore it |
| REQ-VIS-6 | P0 | — | UX-DESIGN-011 | — | script:testing/e2e/classes-phase.mjs#E2E-CLS-1, script:testing/e2e/t1-phase.mjs#T1-E2E.7 | done | in-page anchors (#sec-…) are now allowed hrefs |
| REQ-VIS-7 | P0 | — | UX-DESIGN-011 | — | script:testing/e2e/x509-phase.mjs#E2E-XV-2 | done | an EC key with key encipherment is marked (RFC 8813) |
| REQ-VIS-8 | P1 | — | UX-DESIGN-011 | — | TestInventoryFiltersByStrength, script:testing/e2e/visual-phase.mjs#E2E-VIS-5 | done |  |
| REQ-VIS-9 | P2 | — | UX-DESIGN-011 | — | TestHeartbeatIsProbed | done | 0-RTT stays not probed |
| REQ-VIS-10 | P2 | — | UX-DESIGN-011 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-6 | done | the whole SSH report was rebuilt in PRD-014 (REQ-SSV-2) |
| REQ-VIS-11 | P0 | — | UX-DESIGN-011 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-7, script:testing/e2e/x509-phase.mjs#E2E-XV-5 | done | contrast measured on instrument text, light and dark |
| REQ-VIS-12 | P0 | — | UX-DESIGN-011 | — | report:docs/product/CRYPTO-REVIEW-001-visual-rebuild.md, report:docs/program/QA-REPORT-012.md | done |  |
| REQ-VIS-13 | P1 | — | UX-DESIGN-011 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-FOLD | done | owner request after PR #23 opened |

## PRD-014 · The SSH report, as instruments ([PRD-014](../product/PRD-014-ssh-instruments.md); results in [QA-REPORT-013](QA-REPORT-013.md))

| Requirement | Pri | WP | Source | SR | Evidence | Status | Notes |
|---|---|---|---|---|---|---|---|
| REQ-SSV-1 | P0 | — | UX-DESIGN-012 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-8 | done | six parts; About this report last |
| REQ-SSV-2 | P0 | — | UX-DESIGN-012 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-6, script:testing/e2e/ssh-phase.mjs#E2E-H.2 | done | no rank numbers: in SSH the client's order decides (RFC 4253 §7.1) |
| REQ-SSV-3 | P0 | — | UX-DESIGN-012 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-9 | done | a host key is drawn at the strength of its best signature |
| REQ-SSV-4 | P0 | — | UX-DESIGN-012 | — | script:testing/e2e/ssh-phase.mjs#E2E-H.2, script:testing/e2e/ssh-phase.mjs#E2E-H.2c, script:testing/e2e/visual-phase.mjs#E2E-VIS-8 | done | the change chips sit in their parts; the Baseline part leads to them |
| REQ-SSV-5 | P0 | — | UX-DESIGN-012 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-8 | done |  |
| REQ-SSV-6 | P1 | — | UX-DESIGN-012 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-8 | done | requirement tiles link to their source |
| REQ-SSV-7 | P1 | — | UX-DESIGN-012 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-10 | done | the host key tile's tone follows its strength (CRYPTO-REVIEW-002 fix 1) |
| REQ-SSV-8 | P0 | — | UX-DESIGN-012 | — | script:testing/e2e/visual-phase.mjs#E2E-VIS-7, script:testing/e2e/visual-phase.mjs#E2E-VIS-9, script:testing/e2e/ssh-phase.mjs#E2E-H.2b | done | contrast measured on the SSH instruments too |
| REQ-SSV-9 | P0 | — | UX-DESIGN-012 | — | report:docs/product/CRYPTO-REVIEW-002-ssh-instruments.md, report:docs/program/QA-REPORT-013.md | done |  |

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
