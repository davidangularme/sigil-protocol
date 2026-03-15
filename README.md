# Sigil Protocol

**Adversarial Verification of Risk Detection via Cryptoeconomic Reasoning Bonds**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19027462.svg)](https://doi.org/10.5281/zenodo.19027462)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-363636.svg)](https://soliditylang.org/)
[![Base Mainnet](https://img.shields.io/badge/Base-Mainnet-0052FF.svg)](https://basescan.org/)

> *Signaling Integrity in Global Intelligence Layers*

Sigil extends the [Cortex Protocol](https://github.com/davidangularme/cortex-protocol) (DOI: [10.5281/zenodo.19003627](https://doi.org/10.5281/zenodo.19003627)) from general reasoning verification to the specific domain of **risk detection** — malware, fraud, vulnerabilities — by both AI agents and human analysts.

## The Problem

AI agents increasingly act as autonomous risk detectors. An antivirus engine reports a threat score; a SOAR platform generates an alert; a financial monitor flags a transaction. In every case:

- The **reasoning** behind the claim is invisible
- There is **no mechanism to challenge** a detection
- **No economic cost** is imposed for false positives or false negatives
- **Failure to detect** (the most dangerous failure mode) has zero accountability

## The Solution: Five Mechanisms

### 1. Risk Detection Decision Traces (10-field schema)

| Field | Purpose |
|-------|---------|
| `risk_type` | Classification (Malware, Fraud, Vulnerability, etc.) |
| `evidence_hash` | Immutable pointer to raw data |
| `detection_method` | How the risk was identified |
| `kill_chain_stage` | MITRE ATT&CK mapping |
| `counter_hypothesis` | Best benign explanation considered & rejected |
| `confidence_level` | Calibrated confidence (0-100%) + decay function |
| `threat_horizon` | When the risk claim expires |
| `remediation_suggestion` | Proposed action |
| `corroboration` | Independent detectors with non-redundant reasoning |
| `bond_amount` | Economic stake + challenge window |

### 2. Threat Horizon Scoping (THS)

Every risk claim includes a temporal validity window. Bond decays after 50% of horizon. Early mitigation triggers partial refunds. Prevents perpetual bonding of transient threats.

### 3. Confidence Decay Functions (CDF)

Three programmable decay profiles that degrade bond value over time:

- **Exponential**: `B(t) = B₀ · exp(-λ·t/τ)` — for rapidly evolving threats
- **Stepwise**: 100% → 50% → 0% at horizon milestones
- **Evidence-Conditional**: Bond decreases per counter-evidence event (patch, update)

### 4. Cross-Agent Corroboration Weighting (CACW)

Multiple independent detectors submit different Decision Traces for the same risk. Non-redundant reasoning paths get multiplicative bond weighting. Herd behavior is penalized; orthogonal detection logic is rewarded.

### 5. Inverse Reasoning Bond ⚡

The most novel contribution. Any agent can post a bond claiming *"this system is vulnerable and no one has flagged it"*, forcing a defender to justify the status quo. Creates **epistemic symmetry**: detecting *and failing to detect* both carry economic weight.

## Quick Start

```bash
# Install
npm install

# Compile
npm run compile

# Test (75 tests)
npm test

# Deploy locally with demo
npm run demo:local

# Run full lifecycle demo (all 5 mechanisms, 11 steps)
npm run demo:lifecycle

# Deploy to Base Sepolia
BASE_SEPOLIA_RPC_URL=<url> PRIVATE_KEY=<key> npm run deploy:base-sepolia

# Deploy to Base Mainnet
BASE_RPC_URL=<url> PRIVATE_KEY=<key> npm run deploy:base
```

## Architecture

```
contracts/
  SigilProtocol.sol     # Main contract: traces, duels, decay, corroboration, inverse bonds
scripts/
  deploy.js             # Deployment + optional demo
  demo-lifecycle.js     # 11-step interactive demo (all 5 mechanisms)
  deploy-base-sepolia.sh # Sepolia deployment guide
test/
  SigilProtocol.test.js # 75 tests covering all mechanisms
```

## Contract Interface

```solidity
// Submit a bonded risk detection trace
function submitRiskTrace(
    RiskType _riskType,
    bytes32 _evidenceHash,
    string calldata _detectionMethod,
    string calldata _killChainStage,
    string calldata _counterHypothesis,
    uint16 _confidenceLevel,        // 0-10000 bps
    DecayProfile _decayProfile,
    uint256 _threatHorizon,
    string calldata _remediationSuggestion,
    uint256 _challengeWindow,
    string calldata _reasoningChainHash
) external payable;

// Challenge a trace via Reasoning Duel
function initiateRiskDuel(
    uint256 _targetTraceId,
    string calldata _challengeReasoning,
    string calldata _challengedField
) external payable;

// Submit Inverse Bond: challenge absence of detection
function submitInverseBond(
    string calldata _riskClaim,
    bytes32 _evidenceHash,
    string calldata _systemTarget,
    uint256 _defenseWindow
) external payable;

// Defend against Inverse Bond with safety trace
function defendInverseBond(
    uint256 _inverseBondId,
    uint256 _defenseTraceId
) external;

// Compute current decayed bond value
function computeDecayedBond(uint256 _traceId) public view returns (uint256);

// Get agent reputation score
function getReputationScore(address _agent) external view returns (int256);
```

## Relationship to Cortex Protocol

| Feature | Cortex V4 | Sigil |
|---------|-----------|-------|
| Decision Traces | General reasoning (7 fields) | Risk detection (10 fields, kill chain, counter-hypothesis) |
| Bond Dynamics | Static bond | Confidence Decay Functions (3 profiles) |
| Temporal Semantics | None | Threat Horizon Scoping |
| Corroboration | Not modeled | CACW with non-redundancy verification |
| Absence Challenge | Not modeled | Inverse Reasoning Bond |
| Domain | General AI reasoning | Cybersecurity, fraud, AI safety red-teaming |

## Applications

- **SOC-as-a-Service**: Bonded AI alerts with analyst challenge rewards
- **AI Safety Red-Teaming**: Continuous adversarial market for vulnerability discovery
- **Autonomous Coding Agent Verification**: Bonded code safety assertions
- **Financial Compliance**: Bonded risk assessments with regulatory audit trails

## Authors

- **Frédéric David Blum** — Catalyst AI, Tel Aviv | ORCID: [0009-0009-2487-2974](https://orcid.org/0009-0009-2487-2974)
- **Claude Opus 4.6** — Anthropic

## Citations

```bibtex
@misc{blum2026sigil,
  title={Sigil: Adversarial Verification of Risk Detection via Cryptoeconomic Reasoning Bonds},
  author={Blum, Frédéric David and Claude Opus 4.6},
  year={2026},
  publisher={Zenodo},
  doi={10.5281/zenodo.19027462}
}

@misc{blum2026cortex,
  title={Cortex Protocol: Adversarial Reasoning Bonds as a Cryptoeconomic Truth Predicate for AI Agent Cognition},
  author={Blum, Frédéric David and Claude Opus 4.6},
  year={2026},
  publisher={Zenodo},
  doi={10.5281/zenodo.19003627}
}
```

## License

MIT — See [LICENSE](LICENSE)
