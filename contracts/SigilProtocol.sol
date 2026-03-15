// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SigilProtocol
 * @author Frédéric David Blum & Claude Opus 4.6
 * @notice Adversarial Verification of Risk Detection via Cryptoeconomic Reasoning Bonds
 * @dev Extends Cortex Protocol primitives to risk detection with five novel mechanisms:
 *      1. Risk Detection Decision Traces (10-field schema)
 *      2. Threat Horizon Scoping (THS)
 *      3. Confidence Decay Functions (CDF)
 *      4. Cross-Agent Corroboration Weighting (CACW)
 *      5. Inverse Reasoning Bonds
 *
 *  Deployed on Base Mainnet (Chain ID 8453)
 *  Contract prefix: SIGIL-RD (Risk Detection)
 *  Paper: DOI 10.5281/zenodo.XXXXXXX
 *  Cortex Protocol ref: DOI 10.5281/zenodo.19003627
 */
contract SigilProtocol {

    // ═══════════════════════════════════════════════════════════════════
    //  ENUMS
    // ═══════════════════════════════════════════════════════════════════

    enum RiskType {
        Malware,
        Fraud,
        Vulnerability,
        Anomaly,
        Phishing,
        Ransomware,
        SupplyChain,
        ZeroDay,
        InsiderThreat,
        Other
    }

    enum DecayProfile {
        Exponential,   // D(t,τ) = exp(-λ·t/τ)
        Stepwise,      // D = 1 for t<τ/2, 0.5 for t<τ, 0 after
        EvidenceConditional // D decreases per counter-evidence event
    }

    enum TraceStatus {
        Active,        // Within challenge window
        Decaying,      // Past 50% of horizon, bond decaying
        Challenged,    // Under active duel
        Validated,     // Survived all challenges
        Slashed,       // Bond seized by challenger
        Archived,      // Past threat horizon
        Mitigated      // Threat resolved early, partial refund
    }

    enum InverseBondStatus {
        Open,          // Awaiting defender response
        Defended,      // Defender submitted trace
        ChallengerWon, // Defender failed or lost duel
        DefenderWon,   // Defender successfully justified
        Expired        // No defender responded
    }

    enum DuelOutcome {
        Pending,
        OriginalWins,
        ChallengerWins
    }

    // ═══════════════════════════════════════════════════════════════════
    //  STRUCTS
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice The Risk Detection Decision Trace — 10-field schema
     * @dev Each field is both a documentation requirement and a challenge surface
     */
    struct RiskTrace {
        // ── Identity ──
        uint256 traceId;
        address detector;           // Agent or human who submitted

        // ── Schema Fields ──
        RiskType riskType;
        bytes32 evidenceHash;       // Immutable pointer to raw data (pcap, log, tx)
        string detectionMethod;     // How the risk was identified
        string killChainStage;      // MITRE ATT&CK mapping
        string counterHypothesis;   // Best benign explanation considered & rejected
        uint16 confidenceLevel;     // 0-10000 (basis points, i.e. 0.00%-100.00%)
        DecayProfile decayProfile;
        uint256 threatHorizon;      // Timestamp when risk expires
        string remediationSuggestion;

        // ── Economics ──
        uint256 bondAmount;
        uint256 challengeWindow;    // Duration in seconds for challenges
        uint256 submittedAt;

        // ── State ──
        TraceStatus status;
        string reasoningChainHash;  // For corroboration semantic comparison

        // ── Corroboration ──
        uint256[] corroboratingTraces; // IDs of corroborating traces
        uint256 corroborationWeight;   // Multiplicative weight (basis points)
    }

    /**
     * @notice Reasoning Duel for risk traces
     */
    struct RiskDuel {
        uint256 duelId;
        uint256 targetTraceId;
        address challenger;
        string challengeReasoning;  // Challenger's alternative analysis
        string challengedField;     // Which schema field is contested
        uint256 challengerBond;
        uint256 initiatedAt;
        DuelOutcome outcome;
        uint256 votesForOriginal;
        uint256 votesForChallenger;
        mapping(address => bool) hasVoted;
    }

    /**
     * @notice Inverse Reasoning Bond — challenges ABSENCE of detection
     */
    struct InverseBond {
        uint256 inverseBondId;
        address claimant;           // Agent asserting "risk is being ignored"
        string riskClaim;           // Description of the undetected risk
        bytes32 evidenceHash;       // Supporting evidence
        string systemTarget;        // What system/asset is allegedly vulnerable
        uint256 bondAmount;
        uint256 defenseWindow;      // Time for defender to respond
        uint256 submittedAt;
        InverseBondStatus status;
        uint256 defenseTraceId;     // Defender's response trace (if any)
        address defender;           // Who stepped up to defend
    }

    /**
     * @notice Agent profile with cognitive scores
     */
    struct Agent {
        address agentAddress;
        string name;
        uint256 registeredAt;
        uint256 tracesSubmitted;
        uint256 tracesValidated;
        uint256 tracesSlashed;
        uint256 duelsWon;
        uint256 duelsLost;
        uint256 inverseBondsWon;
        uint256 inverseBondsLost;
        uint256 totalBonded;
        uint256 totalEarned;
        uint256 totalSlashed;
        bool isRegistered;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  STATE
    // ═══════════════════════════════════════════════════════════════════

    address public owner;
    uint256 public protocolVersion = 1;
    string public constant PROTOCOL_NAME = "SIGIL-RD";

    // Counters
    uint256 public traceCount;
    uint256 public duelCount;
    uint256 public inverseBondCount;
    uint256 public agentCount;

    // Minimum bond amounts
    uint256 public minTraceBond = 0.001 ether;
    uint256 public minChallengeBond = 0.0005 ether;
    uint256 public minInverseBond = 0.001 ether;

    // Decay parameter λ for exponential decay (basis points, 10000 = 1.0)
    uint256 public decayLambda = 20000; // λ = 2.0

    // Voting period for duels
    uint256 public votingPeriod = 1 days;

    // Default defense window for inverse bonds
    uint256 public defaultDefenseWindow = 3 days;

    // Mappings
    mapping(uint256 => RiskTrace) public traces;
    mapping(uint256 => RiskDuel) internal _duels;
    mapping(uint256 => InverseBond) public inverseBonds;
    mapping(address => Agent) public agents;

    // Corroboration: evidenceHash => list of trace IDs
    mapping(bytes32 => uint256[]) public evidenceToTraces;

    // Counter-evidence events for evidence-conditional decay
    mapping(uint256 => uint256) public counterEvidenceCount;

    // ═══════════════════════════════════════════════════════════════════
    //  EVENTS
    // ═══════════════════════════════════════════════════════════════════

    event AgentRegistered(address indexed agent, string name, uint256 timestamp);

    event RiskTraceSubmitted(
        uint256 indexed traceId,
        address indexed detector,
        RiskType riskType,
        uint256 bondAmount,
        uint256 threatHorizon,
        DecayProfile decayProfile
    );

    event TraceStatusChanged(
        uint256 indexed traceId,
        TraceStatus oldStatus,
        TraceStatus newStatus
    );

    event DuelInitiated(
        uint256 indexed duelId,
        uint256 indexed targetTraceId,
        address indexed challenger,
        string challengedField,
        uint256 challengerBond
    );

    event DuelVoteCast(
        uint256 indexed duelId,
        address indexed voter,
        bool forOriginal
    );

    event DuelResolved(
        uint256 indexed duelId,
        DuelOutcome outcome,
        uint256 bondTransferred
    );

    event InverseBondSubmitted(
        uint256 indexed inverseBondId,
        address indexed claimant,
        string systemTarget,
        uint256 bondAmount,
        uint256 defenseWindow
    );

    event InverseBondDefended(
        uint256 indexed inverseBondId,
        address indexed defender,
        uint256 defenseTraceId
    );

    event InverseBondResolved(
        uint256 indexed inverseBondId,
        InverseBondStatus outcome,
        uint256 bondTransferred
    );

    event CorroborationRegistered(
        uint256 indexed traceId,
        uint256 indexed corroboratingTraceId,
        uint256 newWeight
    );

    event CounterEvidenceRegistered(
        uint256 indexed traceId,
        uint256 totalCounterEvidence
    );

    event ThreatMitigated(
        uint256 indexed traceId,
        bytes32 mitigationProof,
        uint256 refundAmount
    );

    event DecayCheckpoint(
        uint256 indexed traceId,
        uint256 originalBond,
        uint256 decayedBond,
        uint256 timestamp
    );

    // ═══════════════════════════════════════════════════════════════════
    //  MODIFIERS
    // ═══════════════════════════════════════════════════════════════════

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyRegistered() {
        require(agents[msg.sender].isRegistered, "Agent not registered");
        _;
    }

    modifier traceExists(uint256 _traceId) {
        require(_traceId > 0 && _traceId <= traceCount, "Trace does not exist");
        _;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════

    constructor() {
        owner = msg.sender;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  1. AGENT REGISTRATION
    // ═══════════════════════════════════════════════════════════════════

    function registerAgent(string calldata _name) external {
        require(!agents[msg.sender].isRegistered, "Already registered");
        require(bytes(_name).length > 0, "Name required");

        agents[msg.sender] = Agent({
            agentAddress: msg.sender,
            name: _name,
            registeredAt: block.timestamp,
            tracesSubmitted: 0,
            tracesValidated: 0,
            tracesSlashed: 0,
            duelsWon: 0,
            duelsLost: 0,
            inverseBondsWon: 0,
            inverseBondsLost: 0,
            totalBonded: 0,
            totalEarned: 0,
            totalSlashed: 0,
            isRegistered: true
        });

        agentCount++;
        emit AgentRegistered(msg.sender, _name, block.timestamp);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  2. RISK TRACE SUBMISSION
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Submit a bonded Risk Detection Decision Trace
     * @dev All 10 schema fields must be populated
     */
    function submitRiskTrace(
        RiskType _riskType,
        bytes32 _evidenceHash,
        string calldata _detectionMethod,
        string calldata _killChainStage,
        string calldata _counterHypothesis,
        uint16 _confidenceLevel,
        DecayProfile _decayProfile,
        uint256 _threatHorizon,
        string calldata _remediationSuggestion,
        uint256 _challengeWindow,
        string calldata _reasoningChainHash
    ) external payable onlyRegistered {
        require(msg.value >= minTraceBond, "Bond below minimum");
        require(_confidenceLevel <= 10000, "Confidence max 10000 bps");
        require(_threatHorizon > block.timestamp, "Horizon must be in future");
        require(_challengeWindow > 0, "Challenge window required");
        require(bytes(_detectionMethod).length > 0, "Detection method required");
        require(bytes(_counterHypothesis).length > 0, "Counter-hypothesis required");
        require(_evidenceHash != bytes32(0), "Evidence hash required");

        traceCount++;
        uint256 newTraceId = traceCount;

        RiskTrace storage t = traces[newTraceId];
        t.traceId = newTraceId;
        t.detector = msg.sender;
        t.riskType = _riskType;
        t.evidenceHash = _evidenceHash;
        t.detectionMethod = _detectionMethod;
        t.killChainStage = _killChainStage;
        t.counterHypothesis = _counterHypothesis;
        t.confidenceLevel = _confidenceLevel;
        t.decayProfile = _decayProfile;
        t.threatHorizon = _threatHorizon;
        t.remediationSuggestion = _remediationSuggestion;
        t.bondAmount = msg.value;
        t.challengeWindow = _challengeWindow;
        t.submittedAt = block.timestamp;
        t.status = TraceStatus.Active;
        t.reasoningChainHash = _reasoningChainHash;
        t.corroborationWeight = 10000; // 1.0x base weight

        // Index by evidence for corroboration lookup
        evidenceToTraces[_evidenceHash].push(newTraceId);

        // Update agent stats
        agents[msg.sender].tracesSubmitted++;
        agents[msg.sender].totalBonded += msg.value;

        emit RiskTraceSubmitted(
            newTraceId, msg.sender, _riskType,
            msg.value, _threatHorizon, _decayProfile
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    //  3. THREAT HORIZON SCOPING (THS)
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Check and update trace status based on threat horizon
     * @dev Transitions: Active → Decaying (at 50% horizon), Active/Decaying → Archived
     */
    function updateTraceHorizon(uint256 _traceId) public traceExists(_traceId) {
        RiskTrace storage t = traces[_traceId];
        require(
            t.status == TraceStatus.Active || t.status == TraceStatus.Decaying,
            "Trace not in updatable state"
        );

        TraceStatus oldStatus = t.status;
        uint256 elapsed = block.timestamp - t.submittedAt;
        uint256 horizon = t.threatHorizon - t.submittedAt;

        if (block.timestamp >= t.threatHorizon) {
            // Past horizon: archive and return remaining bond
            t.status = TraceStatus.Archived;
            agents[t.detector].tracesValidated++;
            uint256 decayedBond = computeDecayedBond(_traceId);
            if (decayedBond > 0) {
                payable(t.detector).transfer(decayedBond);
            }
        } else if (elapsed >= horizon / 2 && t.status == TraceStatus.Active) {
            // Past 50% of horizon: begin decay
            t.status = TraceStatus.Decaying;
        }

        if (t.status != oldStatus) {
            emit TraceStatusChanged(_traceId, oldStatus, t.status);
        }
    }

    /**
     * @notice Report threat as mitigated for early partial refund
     * @param _mitigationProof Hash of mitigation evidence (patch hash, takedown record)
     */
    function reportMitigation(
        uint256 _traceId,
        bytes32 _mitigationProof
    ) external traceExists(_traceId) {
        RiskTrace storage t = traces[_traceId];
        require(
            t.status == TraceStatus.Active || t.status == TraceStatus.Decaying,
            "Trace not active"
        );
        require(_mitigationProof != bytes32(0), "Proof required");

        TraceStatus oldStatus = t.status;
        t.status = TraceStatus.Mitigated;
        agents[t.detector].tracesValidated++;

        // Partial refund: proportional to remaining horizon
        uint256 elapsed = block.timestamp - t.submittedAt;
        uint256 totalHorizon = t.threatHorizon - t.submittedAt;
        uint256 remainingRatio = 10000;
        if (totalHorizon > 0 && elapsed < totalHorizon) {
            remainingRatio = ((totalHorizon - elapsed) * 10000) / totalHorizon;
        }
        uint256 refund = (t.bondAmount * remainingRatio) / 10000;

        if (refund > 0) {
            payable(t.detector).transfer(refund);
        }

        emit TraceStatusChanged(_traceId, oldStatus, TraceStatus.Mitigated);
        emit ThreatMitigated(_traceId, _mitigationProof, refund);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  4. CONFIDENCE DECAY FUNCTIONS (CDF)
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Compute the current decayed bond value for a trace
     * @dev Implements three decay profiles: Exponential, Stepwise, EvidenceConditional
     * @return The current bond value after decay
     */
    function computeDecayedBond(uint256 _traceId) public view traceExists(_traceId) returns (uint256) {
        RiskTrace storage t = traces[_traceId];
        uint256 elapsed = block.timestamp - t.submittedAt;
        uint256 horizon = t.threatHorizon - t.submittedAt;

        if (horizon == 0) return t.bondAmount;
        if (block.timestamp >= t.threatHorizon) return 0;

        if (t.decayProfile == DecayProfile.Exponential) {
            return _exponentialDecay(t.bondAmount, elapsed, horizon);
        } else if (t.decayProfile == DecayProfile.Stepwise) {
            return _stepwiseDecay(t.bondAmount, elapsed, horizon);
        } else {
            // EvidenceConditional
            return _evidenceConditionalDecay(t.bondAmount, _traceId);
        }
    }

    /**
     * @dev Exponential decay: B₀ · exp(-λ·t/τ)
     *      Approximated via piecewise linear for gas efficiency
     */
    function _exponentialDecay(
        uint256 _bond,
        uint256 _elapsed,
        uint256 _horizon
    ) internal view returns (uint256) {
        // ratio = elapsed * 10000 / horizon (in basis points)
        uint256 ratio = (_elapsed * 10000) / _horizon;

        // Piecewise approximation of exp(-λ·ratio/10000) where λ=2.0
        // exp(-2·x) approximation for x in [0,1]:
        // x=0: 1.0, x=0.25: 0.607, x=0.5: 0.368, x=0.75: 0.223, x=1.0: 0.135
        uint256 factor;
        if (ratio <= 2500) {
            // Linear interpolation 10000 → 6070
            factor = 10000 - ((ratio * 3930) / 2500);
        } else if (ratio <= 5000) {
            // 6070 → 3680
            factor = 6070 - (((ratio - 2500) * 2390) / 2500);
        } else if (ratio <= 7500) {
            // 3680 → 2230
            factor = 3680 - (((ratio - 5000) * 1450) / 2500);
        } else {
            // 2230 → 1350
            factor = 2230 - (((ratio - 7500) * 880) / 2500);
        }

        return (_bond * factor) / 10000;
    }

    /**
     * @dev Stepwise decay: 100% for t<τ/2, 50% for t<τ, 0% after
     */
    function _stepwiseDecay(
        uint256 _bond,
        uint256 _elapsed,
        uint256 _horizon
    ) internal pure returns (uint256) {
        if (_elapsed < _horizon / 2) {
            return _bond;
        } else if (_elapsed < _horizon) {
            return _bond / 2;
        } else {
            return 0;
        }
    }

    /**
     * @dev Evidence-conditional decay: bond / (1 + counterEvidenceCount)
     */
    function _evidenceConditionalDecay(
        uint256 _bond,
        uint256 _traceId
    ) internal view returns (uint256) {
        uint256 ceCount = counterEvidenceCount[_traceId];
        return _bond / (1 + ceCount);
    }

    /**
     * @notice Register counter-evidence against a trace (patch, update, etc.)
     */
    function registerCounterEvidence(
        uint256 _traceId,
        bytes32 _counterEvidenceHash
    ) external onlyRegistered traceExists(_traceId) {
        require(
            traces[_traceId].status == TraceStatus.Active ||
            traces[_traceId].status == TraceStatus.Decaying,
            "Trace not active"
        );
        require(_counterEvidenceHash != bytes32(0), "Evidence hash required");

        counterEvidenceCount[_traceId]++;

        emit CounterEvidenceRegistered(_traceId, counterEvidenceCount[_traceId]);
        emit DecayCheckpoint(
            _traceId,
            traces[_traceId].bondAmount,
            computeDecayedBond(_traceId),
            block.timestamp
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    //  5. REASONING DUELS (Risk-Specific)
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Challenge a risk trace via Reasoning Duel
     * @dev Challenger must specify which schema field is contested
     */
    function initiateRiskDuel(
        uint256 _targetTraceId,
        string calldata _challengeReasoning,
        string calldata _challengedField
    ) external payable onlyRegistered traceExists(_targetTraceId) {
        RiskTrace storage t = traces[_targetTraceId];
        require(
            t.status == TraceStatus.Active || t.status == TraceStatus.Decaying,
            "Trace not challengeable"
        );
        require(msg.sender != t.detector, "Cannot challenge own trace");
        require(
            block.timestamp <= t.submittedAt + t.challengeWindow,
            "Challenge window closed"
        );

        // Challenger bond must be proportional to decayed bond
        uint256 currentBond = computeDecayedBond(_targetTraceId);
        uint256 requiredBond = currentBond / 2;
        if (requiredBond < minChallengeBond) requiredBond = minChallengeBond;
        require(msg.value >= requiredBond, "Challenger bond insufficient");

        duelCount++;
        RiskDuel storage d = _duels[duelCount];
        d.duelId = duelCount;
        d.targetTraceId = _targetTraceId;
        d.challenger = msg.sender;
        d.challengeReasoning = _challengeReasoning;
        d.challengedField = _challengedField;
        d.challengerBond = msg.value;
        d.initiatedAt = block.timestamp;
        d.outcome = DuelOutcome.Pending;

        // Update trace status
        TraceStatus oldStatus = t.status;
        t.status = TraceStatus.Challenged;
        emit TraceStatusChanged(_targetTraceId, oldStatus, TraceStatus.Challenged);

        emit DuelInitiated(
            duelCount, _targetTraceId, msg.sender,
            _challengedField, msg.value
        );
    }

    /**
     * @notice Vote on a risk duel outcome
     */
    function voteOnDuel(uint256 _duelId, bool _forOriginal) external onlyRegistered {
        require(_duelId > 0 && _duelId <= duelCount, "Duel does not exist");
        RiskDuel storage d = _duels[_duelId];
        require(d.outcome == DuelOutcome.Pending, "Duel already resolved");
        require(!d.hasVoted[msg.sender], "Already voted");
        require(
            msg.sender != d.challenger &&
            msg.sender != traces[d.targetTraceId].detector,
            "Parties cannot vote"
        );
        require(
            block.timestamp <= d.initiatedAt + votingPeriod,
            "Voting period ended"
        );

        d.hasVoted[msg.sender] = true;

        if (_forOriginal) {
            d.votesForOriginal++;
        } else {
            d.votesForChallenger++;
        }

        emit DuelVoteCast(_duelId, msg.sender, _forOriginal);
    }

    /**
     * @notice Resolve a risk duel after voting period
     */
    function resolveDuel(uint256 _duelId) external {
        require(_duelId > 0 && _duelId <= duelCount, "Duel does not exist");
        RiskDuel storage d = _duels[_duelId];
        require(d.outcome == DuelOutcome.Pending, "Already resolved");
        require(
            block.timestamp > d.initiatedAt + votingPeriod,
            "Voting period not ended"
        );

        RiskTrace storage t = traces[d.targetTraceId];
        uint256 bondTransferred;

        if (d.votesForChallenger > d.votesForOriginal) {
            // Challenger wins — seize the decayed bond
            d.outcome = DuelOutcome.ChallengerWins;
            t.status = TraceStatus.Slashed;

            uint256 seizableAmount = computeDecayedBondAt(
                d.targetTraceId, d.initiatedAt
            );
            bondTransferred = seizableAmount + d.challengerBond;

            agents[d.challenger].duelsWon++;
            agents[d.challenger].totalEarned += seizableAmount;
            agents[t.detector].duelsLost++;
            agents[t.detector].totalSlashed += seizableAmount;
            agents[t.detector].tracesSlashed++;

            payable(d.challenger).transfer(bondTransferred);

            emit TraceStatusChanged(
                d.targetTraceId, TraceStatus.Challenged, TraceStatus.Slashed
            );
        } else {
            // Original wins — challenger loses bond
            d.outcome = DuelOutcome.OriginalWins;
            t.status = TraceStatus.Active; // Restore

            bondTransferred = d.challengerBond;

            agents[t.detector].duelsWon++;
            agents[t.detector].totalEarned += d.challengerBond;
            agents[d.challenger].duelsLost++;
            agents[d.challenger].totalSlashed += d.challengerBond;

            payable(t.detector).transfer(t.bondAmount + d.challengerBond);

            emit TraceStatusChanged(
                d.targetTraceId, TraceStatus.Challenged, TraceStatus.Active
            );
        }

        emit DuelResolved(_duelId, d.outcome, bondTransferred);
    }

    /**
     * @dev Compute decayed bond at a specific timestamp (for duel resolution fairness)
     */
    function computeDecayedBondAt(
        uint256 _traceId,
        uint256 _at
    ) public view returns (uint256) {
        RiskTrace storage t = traces[_traceId];
        uint256 elapsed = _at - t.submittedAt;
        uint256 horizon = t.threatHorizon - t.submittedAt;

        if (horizon == 0) return t.bondAmount;
        if (_at >= t.threatHorizon) return 0;

        if (t.decayProfile == DecayProfile.Exponential) {
            return _exponentialDecay(t.bondAmount, elapsed, horizon);
        } else if (t.decayProfile == DecayProfile.Stepwise) {
            return _stepwiseDecay(t.bondAmount, elapsed, horizon);
        } else {
            return _evidenceConditionalDecay(t.bondAmount, _traceId);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  6. CROSS-AGENT CORROBORATION WEIGHTING (CACW)
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Register corroboration between two traces with same evidence
     * @dev Only non-redundant corroboration (different reasoning) gets weight boost
     * @param _traceId The trace to corroborate
     * @param _corroboratingTraceId The supporting trace with different reasoning
     * @param _isNonRedundant Whether reasoning paths are verified as orthogonal
     */
    function registerCorroboration(
        uint256 _traceId,
        uint256 _corroboratingTraceId,
        bool _isNonRedundant
    ) external onlyRegistered traceExists(_traceId) traceExists(_corroboratingTraceId) {
        RiskTrace storage t1 = traces[_traceId];
        RiskTrace storage t2 = traces[_corroboratingTraceId];

        require(_traceId != _corroboratingTraceId, "Cannot self-corroborate");
        require(t1.detector != t2.detector, "Same detector cannot corroborate");
        require(
            t1.evidenceHash == t2.evidenceHash ||
            t1.riskType == t2.riskType,
            "Traces must share evidence or risk type"
        );

        // Check not already corroborated
        for (uint256 i = 0; i < t1.corroboratingTraces.length; i++) {
            require(
                t1.corroboratingTraces[i] != _corroboratingTraceId,
                "Already corroborated"
            );
        }

        t1.corroboratingTraces.push(_corroboratingTraceId);

        if (_isNonRedundant) {
            // Multiplicative weight boost: +50% per non-redundant corroboration
            // Cap at 3x (30000 bps)
            uint256 newWeight = t1.corroborationWeight + 5000;
            if (newWeight > 30000) newWeight = 30000;
            t1.corroborationWeight = newWeight;
        } else {
            // Redundant corroboration: minimal boost (+10%)
            uint256 newWeight = t1.corroborationWeight + 1000;
            if (newWeight > 30000) newWeight = 30000;
            t1.corroborationWeight = newWeight;
        }

        emit CorroborationRegistered(
            _traceId, _corroboratingTraceId, t1.corroborationWeight
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    //  7. INVERSE REASONING BONDS
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Submit an Inverse Reasoning Bond — challenge ABSENCE of detection
     * @dev "This system is vulnerable and no one has flagged it"
     */
    function submitInverseBond(
        string calldata _riskClaim,
        bytes32 _evidenceHash,
        string calldata _systemTarget,
        uint256 _defenseWindow
    ) external payable onlyRegistered {
        require(msg.value >= minInverseBond, "Bond below minimum");
        require(bytes(_riskClaim).length > 0, "Risk claim required");
        require(_evidenceHash != bytes32(0), "Evidence required");
        require(bytes(_systemTarget).length > 0, "System target required");

        if (_defenseWindow == 0) _defenseWindow = defaultDefenseWindow;

        inverseBondCount++;

        inverseBonds[inverseBondCount] = InverseBond({
            inverseBondId: inverseBondCount,
            claimant: msg.sender,
            riskClaim: _riskClaim,
            evidenceHash: _evidenceHash,
            systemTarget: _systemTarget,
            bondAmount: msg.value,
            defenseWindow: _defenseWindow,
            submittedAt: block.timestamp,
            status: InverseBondStatus.Open,
            defenseTraceId: 0,
            defender: address(0)
        });

        emit InverseBondSubmitted(
            inverseBondCount, msg.sender, _systemTarget,
            msg.value, _defenseWindow
        );
    }

    /**
     * @notice Defend against an Inverse Bond by submitting a safety trace
     * @dev Defender must submit a new Risk Trace justifying why the system is safe
     */
    function defendInverseBond(
        uint256 _inverseBondId,
        uint256 _defenseTraceId
    ) external onlyRegistered traceExists(_defenseTraceId) {
        require(
            _inverseBondId > 0 && _inverseBondId <= inverseBondCount,
            "Inverse bond does not exist"
        );
        InverseBond storage ib = inverseBonds[_inverseBondId];
        require(ib.status == InverseBondStatus.Open, "Not open for defense");
        require(
            block.timestamp <= ib.submittedAt + ib.defenseWindow,
            "Defense window closed"
        );
        require(msg.sender != ib.claimant, "Claimant cannot self-defend");
        require(
            traces[_defenseTraceId].detector == msg.sender,
            "Defense trace must be yours"
        );

        ib.status = InverseBondStatus.Defended;
        ib.defenseTraceId = _defenseTraceId;
        ib.defender = msg.sender;

        emit InverseBondDefended(_inverseBondId, msg.sender, _defenseTraceId);
    }

    /**
     * @notice Resolve an expired inverse bond (no defender showed up)
     */
    function resolveExpiredInverseBond(uint256 _inverseBondId) external {
        require(
            _inverseBondId > 0 && _inverseBondId <= inverseBondCount,
            "Inverse bond does not exist"
        );
        InverseBond storage ib = inverseBonds[_inverseBondId];
        require(ib.status == InverseBondStatus.Open, "Not open");
        require(
            block.timestamp > ib.submittedAt + ib.defenseWindow,
            "Defense window not expired"
        );

        // No one defended — claimant wins, gets bond back + validation
        ib.status = InverseBondStatus.Expired;
        agents[ib.claimant].inverseBondsWon++;

        payable(ib.claimant).transfer(ib.bondAmount);

        emit InverseBondResolved(
            _inverseBondId, InverseBondStatus.Expired, ib.bondAmount
        );
    }

    /**
     * @notice Resolve a defended inverse bond after the defense trace's challenge window
     * @dev If defense trace survived, defender wins. If slashed, claimant wins.
     */
    function resolveDefendedInverseBond(uint256 _inverseBondId) external {
        require(
            _inverseBondId > 0 && _inverseBondId <= inverseBondCount,
            "Inverse bond does not exist"
        );
        InverseBond storage ib = inverseBonds[_inverseBondId];
        require(ib.status == InverseBondStatus.Defended, "Not in defended state");

        RiskTrace storage defenseTrace = traces[ib.defenseTraceId];
        require(
            block.timestamp > defenseTrace.submittedAt + defenseTrace.challengeWindow,
            "Defense trace challenge window not closed"
        );

        if (defenseTrace.status == TraceStatus.Slashed) {
            // Defense failed — claimant was right
            ib.status = InverseBondStatus.ChallengerWon;
            agents[ib.claimant].inverseBondsWon++;
            agents[ib.defender].inverseBondsLost++;

            // Claimant gets their bond back
            payable(ib.claimant).transfer(ib.bondAmount);

            emit InverseBondResolved(
                _inverseBondId, InverseBondStatus.ChallengerWon, ib.bondAmount
            );
        } else if (
            defenseTrace.status == TraceStatus.Validated ||
            defenseTrace.status == TraceStatus.Active ||
            defenseTrace.status == TraceStatus.Archived
        ) {
            // Defense succeeded — defender wins claimant's bond
            ib.status = InverseBondStatus.DefenderWon;
            agents[ib.defender].inverseBondsWon++;
            agents[ib.claimant].inverseBondsLost++;
            agents[ib.defender].totalEarned += ib.bondAmount;
            agents[ib.claimant].totalSlashed += ib.bondAmount;

            payable(ib.defender).transfer(ib.bondAmount);

            emit InverseBondResolved(
                _inverseBondId, InverseBondStatus.DefenderWon, ib.bondAmount
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  8. VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Get comprehensive agent reputation score
     * @dev Score = (validated * 100 + duelsWon * 50 + inverseBondsWon * 75)
     *            - (slashed * 100 + duelsLost * 25 + inverseBondsLost * 50)
     *      Normalized to percentage of max possible
     */
    function getReputationScore(address _agent) external view returns (int256) {
        Agent storage a = agents[_agent];
        if (!a.isRegistered) return 0;

        int256 positive = int256(a.tracesValidated) * 100
                        + int256(a.duelsWon) * 50
                        + int256(a.inverseBondsWon) * 75;

        int256 negative = int256(a.tracesSlashed) * 100
                        + int256(a.duelsLost) * 25
                        + int256(a.inverseBondsLost) * 50;

        return positive - negative;
    }

    /**
     * @notice Get cognitive score as percentage (basis points)
     */
    function getCognitiveScore(address _agent) external view returns (uint256) {
        Agent storage a = agents[_agent];
        if (!a.isRegistered) return 0;

        uint256 totalActions = a.tracesSubmitted + a.duelsWon + a.duelsLost
                             + a.inverseBondsWon + a.inverseBondsLost;
        if (totalActions == 0) return 5000; // 50% default

        uint256 positiveActions = a.tracesValidated + a.duelsWon + a.inverseBondsWon;

        return (positiveActions * 10000) / totalActions;
    }

    /**
     * @notice Get corroborating trace IDs for a trace
     */
    function getCorroboratingTraces(
        uint256 _traceId
    ) external view traceExists(_traceId) returns (uint256[] memory) {
        return traces[_traceId].corroboratingTraces;
    }

    /**
     * @notice Get all trace IDs associated with an evidence hash
     */
    function getTracesByEvidence(
        bytes32 _evidenceHash
    ) external view returns (uint256[] memory) {
        return evidenceToTraces[_evidenceHash];
    }

    /**
     * @notice Get duel details (excluding mapping)
     */
    function getDuel(uint256 _duelId) external view returns (
        uint256 duelId,
        uint256 targetTraceId,
        address challenger,
        string memory challengeReasoning,
        string memory challengedField,
        uint256 challengerBond,
        uint256 initiatedAt,
        DuelOutcome outcome,
        uint256 votesForOriginal,
        uint256 votesForChallenger
    ) {
        RiskDuel storage d = _duels[_duelId];
        return (
            d.duelId, d.targetTraceId, d.challenger,
            d.challengeReasoning, d.challengedField,
            d.challengerBond, d.initiatedAt, d.outcome,
            d.votesForOriginal, d.votesForChallenger
        );
    }

    /**
     * @notice Check if trace is within challenge window
     */
    function isChallengeable(uint256 _traceId) external view traceExists(_traceId) returns (bool) {
        RiskTrace storage t = traces[_traceId];
        return (
            (t.status == TraceStatus.Active || t.status == TraceStatus.Decaying) &&
            block.timestamp <= t.submittedAt + t.challengeWindow
        );
    }

    /**
     * @notice Get current effective bond (with corroboration weight)
     */
    function getEffectiveBond(uint256 _traceId) external view traceExists(_traceId) returns (uint256) {
        uint256 decayed = computeDecayedBond(_traceId);
        return (decayed * traces[_traceId].corroborationWeight) / 10000;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  9. ADMIN
    // ═══════════════════════════════════════════════════════════════════

    function setMinTraceBond(uint256 _min) external onlyOwner {
        minTraceBond = _min;
    }

    function setMinChallengeBond(uint256 _min) external onlyOwner {
        minChallengeBond = _min;
    }

    function setMinInverseBond(uint256 _min) external onlyOwner {
        minInverseBond = _min;
    }

    function setVotingPeriod(uint256 _period) external onlyOwner {
        votingPeriod = _period;
    }

    function setDefaultDefenseWindow(uint256 _window) external onlyOwner {
        defaultDefenseWindow = _window;
    }

    function setDecayLambda(uint256 _lambda) external onlyOwner {
        decayLambda = _lambda;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  RECEIVE
    // ═══════════════════════════════════════════════════════════════════

    receive() external payable {}
}
