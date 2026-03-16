# HIPAA Business Associate Agreement — Draft Template

> **IMPORTANT**: This is a draft template for discussion purposes. It must be reviewed by qualified legal counsel before execution. NanoMask is a self-hosted software product, not a hosted service — the BAA structure reflects the customer's role as the covered entity operating NanoMask within their own environment.

---

## Parties

This Business Associate Agreement ("BAA") is entered into by and between:

- **Covered Entity**: [Customer Name] ("Covered Entity")
- **Business Associate**: [NanoMask Vendor Entity Name] ("Business Associate")

Effective Date: [Date]

---

## 1. Definitions

Terms used but not defined in this BAA have the same meaning as in the HIPAA Privacy Rule (45 CFR Part 160 and Subparts A and E of Part 164) and the HIPAA Security Rule (45 CFR Parts 160 and 164, Subparts A and C), as amended by the HITECH Act.

- **Protected Health Information (PHI)**: Individually identifiable health information transmitted or maintained in any form or medium, as defined in 45 CFR § 160.103.
- **Electronic Protected Health Information (ePHI)**: PHI transmitted by or maintained in electronic media.

---

## 2. Permitted Uses And Disclosures

### 2.1 Service Scope

Business Associate provides NanoMask, a self-hosted privacy firewall software product that de-identifies PHI in HTTP traffic before it reaches upstream API services. The software is deployed and operated within the Covered Entity's infrastructure.

### 2.2 Permitted Uses

Business Associate may use or disclose PHI only as necessary to:

- (a) Provide technical support, software updates, and professional services related to NanoMask deployment and operation.
- (b) Fulfill obligations under this BAA and the underlying service agreement.

### 2.3 Prohibited Uses

Business Associate shall not:

- (a) Use or disclose PHI for any purpose other than as permitted by this BAA.
- (b) Use or disclose PHI in a manner that would violate HIPAA if done by the Covered Entity.
- (c) Sell PHI or use PHI for marketing without prior written authorization.

---

## 3. Safeguards

### 3.1 Technical Safeguards Provided By NanoMask

| HIPAA Requirement | NanoMask Control |
|-------------------|------------------|
| Access controls (§ 164.312(a)) | Admin API requires Bearer token, IP allowlist, optional read-only mode, rate limiting |
| Audit controls (§ 164.312(b)) | Structured NDJSON audit logging with redaction events, admin events, session IDs, timestamps |
| Integrity controls (§ 164.312(c)) | Multi-stage redaction pipeline ensures PHI is de-identified before egress; schema mode with `default_action: REDACT` provides strongest posture |
| Transmission security (§ 164.312(e)) | TLS 1.3 on upstream connections; ingress TLS via hardened ingress tier or built-in TLS |
| Encryption at rest | Not applicable — NanoMask is a proxy and does not persist PHI. Audit logs record metadata only, never PHI values. |

### 3.2 Administrative And Physical Safeguards

Administrative safeguards (workforce training, risk assessments, contingency planning) and physical safeguards (facility access, workstation security) are the responsibility of the Covered Entity as the operator of NanoMask within their own infrastructure.

### 3.3 Minimum Necessary Standard

Business Associate shall limit its access to PHI to the minimum necessary to accomplish the intended purpose of the engagement.

---

## 4. Breach Notification

### 4.1 Notification Obligation

Business Associate shall notify Covered Entity without unreasonable delay, and in no case later than **thirty (30) calendar days** after discovery of a breach of unsecured PHI.

### 4.2 Notification Content

Notification shall include, to the extent available:

- (a) Identification of each individual whose PHI has been or is reasonably believed to have been affected.
- (b) Description of the type of PHI involved.
- (c) Steps individuals should take to protect themselves.
- (d) Description of what Business Associate is doing to investigate, mitigate, and prevent recurrence.

### 4.3 Self-Hosted Clarification

Because NanoMask is deployed and operated within the Covered Entity's infrastructure, the Covered Entity is responsible for monitoring its own deployment for security events. Business Associate's breach notification obligation is limited to breaches arising from its own systems, services, or personnel accessing PHI during support or professional services engagements.

---

## 5. Return And Destruction Of PHI

### 5.1 Upon Termination

Upon termination of this BAA or the underlying service agreement, Business Associate shall:

- (a) Return or destroy all PHI received from or created on behalf of the Covered Entity, if feasible.
- (b) If return or destruction is not feasible, extend the protections of this BAA to the remaining PHI and limit further uses and disclosures to those purposes that make return or destruction infeasible.

### 5.2 Self-Hosted Clarification

NanoMask processes PHI in-memory during HTTP transactions and does not persist PHI to disk. Audit logs record redaction metadata (offsets, lengths, action types) but never PHI values. The Covered Entity retains control over all deployment infrastructure, log storage, and data retention.

---

## 6. Subcontractors

Business Associate shall require any subcontractors that create, receive, maintain, or transmit PHI on behalf of the Covered Entity to agree in writing to the same restrictions, conditions, and requirements imposed on Business Associate under this BAA.

---

## 7. Term And Termination

### 7.1 Term

This BAA is effective as of the Effective Date and continues for the term of the underlying service agreement unless terminated earlier as provided herein.

### 7.2 Termination For Cause

Either party may terminate this BAA if the other party materially breaches any provision and fails to cure such breach within **thirty (30) days** of written notice.

---

## 8. General Provisions

- This BAA supplements and is subject to the terms of the underlying service agreement.
- This BAA shall be governed by and construed in accordance with [applicable law].
- Any ambiguity in this BAA shall be resolved in favor of a meaning that permits compliance with HIPAA.

---

## Signatures

| | Covered Entity | Business Associate |
|---|---|---|
| **Name** | | |
| **Title** | | |
| **Signature** | | |
| **Date** | | |

---

## Revision History

| Date | Change |
|------|--------|
| 2026-03-13 | Initial draft HIPAA BAA template (NMV3-005) |
