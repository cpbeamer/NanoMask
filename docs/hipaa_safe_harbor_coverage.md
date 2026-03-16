# HIPAA Safe Harbor Coverage Matrix

The HIPAA Safe Harbor method of de-identification requires the removal of 18 specific identifiers of the individual, their relatives, employers, or household members.

NanoMask implements advanced pattern recognition, context heuristics, and configuration flags to meet or exceed these requirements for streaming LLM traffic.

## 18 Identifiers Coverage

| ID | Description | Coverage Method | Compensating Control |
|----|-------------|-----------------|----------------------|
| 1 | Names | Supported via Aho-Corasick exact matching (`--entities-file`) and Fuzzy Match (`--fuzzy-entities`). | AI Guardrails (`phi_strict`) provides heuristic NER. |
| 2 | Geographic data smaller than State | Supported via `--enable-addresses`. Removes street, city, county. Validates and zero-outs restricted population ZIP-3s. Masks normal ZIPs to 3 digits. | Manual verification of custom `entities-file` for highly-specific local zones. |
| 3 | Dates related to an individual | Supported via `--enable-dates`. Replaces dates with `[DATE_REDACTED]` and aggregates ages over 89 to `90+`. | Context-hinting ensures valid clinical dates with 'DOB', 'admitted', etc. are strictly caught. |
| 4 | Phone numbers | Supported via `--enable-phone`. Validates US numbers against area/exchange codes. | |
| 5 | Fax numbers | Supported via `--enable-phone` combining phone formats and context heuristics (`Fax: `). | |
| 6 | Email addresses | Supported via `--enable-email`. Validates local-part and TLD length. | |
| 7 | Social Security Numbers | Supported universally. SIMD-accelerated detection. | |
| 8 | Medical record numbers (MRN) | Supported via `--enable-healthcare`. Uses clinical context hints. | |
| 9 | Health plan beneficiary numbers | Supported via `--enable-healthcare`. Uses clinical context hints. | |
| 10 | Account numbers | Supported via `--enable-accounts`. Identifies routing and account numbers by context. | |
| 11 | Certificate/license numbers | Supported via `--enable-licenses`. Validates DEA (algorithm), NPI (Luhn), and DLs by context. | |
| 12 | Vehicle IDs & serial numbers | Supported via `--enable-vehicle-ids`. VINs validated via modulo-11 check digit. | Basic License Plate heuristics included. |
| 13 | Device identifiers & serial numbers | Not fully heuristic. Relies on exact-match entity loading due to arbitrary formats (e.g. MAC, UUID). | |
| 14 | Web Universal Resource Locators (URLs) | Supported via `--enable-urls`. Matches HTTP/HTTPS and WWW prefixes. | |
| 15 | IP address numbers | Supported via `--enable-ip`. Handles IPv4 (with CIDR overrides) and IPv6. | |
| 16 | Biometric identifiers | Not processed (NanoMask is text-only). | |
| 17 | Full face photos | Not processed (NanoMask is text-only). | |
| 18 | Any other unique identifying number | Handled via custom entity loading and semantic caching schema capabilities. | Fallback: Proxy schemas enforce `REMOVE` on arbitrary tracking fields. |

## Compensating Controls

NanoMask does not solely run pattern regexes. Through the integration of deterministic dictionaries (`VersionedEntitySet`), schema-level JSON parsing (`Schema` rules), and fuzzy matching, organizations can establish layered defense in depth.

1. **Schema Action Layer**: Define specific JSON fields (e.g. `"date_of_birth"`) to trigger the `SCAN` or `REDACT` action, bypassing the need for unstructured pattern matching entirely.
2. **Entity Dictionaries**: Load thousands of patient names into the system efficiently.
3. **AI Guardrails Layer**: Offload "fuzzy" edge cases to upstream content filtering classifiers (`--guardrails-mode phi_strict`).
