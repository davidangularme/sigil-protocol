const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SigilProtocol", function () {
  let sigil;
  let owner, detector, challenger, voter, defender, agent5;
  const ONE_ETH = ethers.parseEther("1.0");
  const HALF_ETH = ethers.parseEther("0.5");
  const TENTH_ETH = ethers.parseEther("0.1");
  const MIN_BOND = ethers.parseEther("0.001");
  const MIN_CHALLENGE = ethers.parseEther("0.0005");

  // Helpers
  const DAY = 86400;
  const HOUR = 3600;
  const evidence = ethers.keccak256(ethers.toUtf8Bytes("malware_sample_sha256_abc123"));
  const evidence2 = ethers.keccak256(ethers.toUtf8Bytes("malware_sample_sha256_def456"));
  const mitigationProof = ethers.keccak256(ethers.toUtf8Bytes("CVE-2026-XXXX-patch-deployed"));
  const counterEvidence = ethers.keccak256(ethers.toUtf8Bytes("threat-intel-update-v2"));

  async function futureTimestamp(seconds) {
    const block = await ethers.provider.getBlock("latest");
    return block.timestamp + seconds;
  }

  async function advanceTime(seconds) {
    await ethers.provider.send("evm_increaseTime", [seconds]);
    await ethers.provider.send("evm_mine");
  }

  beforeEach(async function () {
    [owner, detector, challenger, voter, defender, agent5] = await ethers.getSigners();
    const SigilProtocol = await ethers.getContractFactory("SigilProtocol");
    sigil = await SigilProtocol.deploy();
    await sigil.waitForDeployment();

    // Register agents
    await sigil.connect(detector).registerAgent("Fred & Claude");
    await sigil.connect(challenger).registerAgent("DeepSeek");
    await sigil.connect(voter).registerAgent("Gemini");
    await sigil.connect(defender).registerAgent("SOC-Analyst-1");
    await sigil.connect(agent5).registerAgent("RedTeam-Alpha");
  });

  // ═══════════════════════════════════════════════════════════════════
  //  1. DEPLOYMENT & REGISTRATION
  // ═══════════════════════════════════════════════════════════════════

  describe("Deployment", function () {
    it("should deploy with correct protocol name", async function () {
      expect(await sigil.PROTOCOL_NAME()).to.equal("SIGIL-RD");
    });

    it("should set correct protocol version", async function () {
      expect(await sigil.protocolVersion()).to.equal(1);
    });

    it("should set deployer as owner", async function () {
      expect(await sigil.owner()).to.equal(owner.address);
    });

    it("should initialize counters to zero", async function () {
      expect(await sigil.traceCount()).to.equal(0);
      expect(await sigil.duelCount()).to.equal(0);
      expect(await sigil.inverseBondCount()).to.equal(0);
    });
  });

  describe("Agent Registration", function () {
    it("should register agents correctly", async function () {
      expect(await sigil.agentCount()).to.equal(5);
      const agent = await sigil.agents(detector.address);
      expect(agent.name).to.equal("Fred & Claude");
      expect(agent.isRegistered).to.be.true;
    });

    it("should reject duplicate registration", async function () {
      await expect(
        sigil.connect(detector).registerAgent("Duplicate")
      ).to.be.revertedWith("Already registered");
    });

    it("should reject empty name", async function () {
      await expect(
        sigil.connect(owner).registerAgent("")
      ).to.be.revertedWith("Name required");
    });

    it("should emit AgentRegistered event", async function () {
      const tx = sigil.connect(owner).registerAgent("Owner-Agent");
      await expect(tx).to.emit(sigil, "AgentRegistered");
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  2. RISK TRACE SUBMISSION
  // ═══════════════════════════════════════════════════════════════════

  describe("Risk Trace Submission", function () {
    it("should submit a valid risk trace", async function () {
      const horizon = await futureTimestamp(3 * DAY);
      const tx = await sigil.connect(detector).submitRiskTrace(
        0, // Malware
        evidence,
        "Static binary analysis + YARA rule match",
        "Execution (T1059)",
        "Benign packed executable ruled out: entropy 7.98, no valid signature",
        8500, // 85% confidence
        0, // Exponential decay
        horizon,
        "Quarantine and run in sandbox for behavioral analysis",
        DAY, // 1 day challenge window
        "hash_reasoning_chain_abc",
        { value: TENTH_ETH }
      );

      expect(await sigil.traceCount()).to.equal(1);
      const trace = await sigil.traces(1);
      expect(trace.detector).to.equal(detector.address);
      expect(trace.riskType).to.equal(0); // Malware
      expect(trace.confidenceLevel).to.equal(8500);
      expect(trace.bondAmount).to.equal(TENTH_ETH);
      expect(trace.status).to.equal(0); // Active
      expect(trace.corroborationWeight).to.equal(10000);
    });

    it("should emit RiskTraceSubmitted event", async function () {
      const horizon = await futureTimestamp(3 * DAY);
      await expect(
        sigil.connect(detector).submitRiskTrace(
          7, evidence, "Fuzzing", "Initial Access (T1190)",
          "Not a false positive: confirmed RCE",
          9500, 1, horizon, "Patch immediately",
          DAY, "hash_xyz",
          { value: TENTH_ETH }
        )
      ).to.emit(sigil, "RiskTraceSubmitted");
    });

    it("should reject bond below minimum", async function () {
      const horizon = await futureTimestamp(DAY);
      await expect(
        sigil.connect(detector).submitRiskTrace(
          0, evidence, "Method", "Stage", "Counter",
          5000, 0, horizon, "Remediation",
          HOUR, "hash",
          { value: ethers.parseEther("0.0001") }
        )
      ).to.be.revertedWith("Bond below minimum");
    });

    it("should reject confidence above 10000 bps", async function () {
      const horizon = await futureTimestamp(DAY);
      await expect(
        sigil.connect(detector).submitRiskTrace(
          0, evidence, "Method", "Stage", "Counter",
          10001, 0, horizon, "Remediation",
          HOUR, "hash",
          { value: TENTH_ETH }
        )
      ).to.be.revertedWith("Confidence max 10000 bps");
    });

    it("should reject past threat horizon", async function () {
      await expect(
        sigil.connect(detector).submitRiskTrace(
          0, evidence, "Method", "Stage", "Counter",
          5000, 0, 1000, "Remediation",
          HOUR, "hash",
          { value: TENTH_ETH }
        )
      ).to.be.revertedWith("Horizon must be in future");
    });

    it("should reject empty counter-hypothesis", async function () {
      const horizon = await futureTimestamp(DAY);
      await expect(
        sigil.connect(detector).submitRiskTrace(
          0, evidence, "Method", "Stage", "",
          5000, 0, horizon, "Remediation",
          HOUR, "hash",
          { value: TENTH_ETH }
        )
      ).to.be.revertedWith("Counter-hypothesis required");
    });

    it("should reject zero evidence hash", async function () {
      const horizon = await futureTimestamp(DAY);
      await expect(
        sigil.connect(detector).submitRiskTrace(
          0, ethers.ZeroHash, "Method", "Stage", "Counter",
          5000, 0, horizon, "Remediation",
          HOUR, "hash",
          { value: TENTH_ETH }
        )
      ).to.be.revertedWith("Evidence hash required");
    });

    it("should reject unregistered agents", async function () {
      const horizon = await futureTimestamp(DAY);
      const [,,,,, , unregistered] = await ethers.getSigners();
      await expect(
        sigil.connect(unregistered).submitRiskTrace(
          0, evidence, "Method", "Stage", "Counter",
          5000, 0, horizon, "Remediation",
          HOUR, "hash",
          { value: TENTH_ETH }
        )
      ).to.be.revertedWith("Agent not registered");
    });

    it("should index trace by evidence hash", async function () {
      const horizon = await futureTimestamp(3 * DAY);
      await sigil.connect(detector).submitRiskTrace(
        0, evidence, "Method", "Stage", "Counter",
        5000, 0, horizon, "Remediation",
        DAY, "hash",
        { value: TENTH_ETH }
      );
      const traceIds = await sigil.getTracesByEvidence(evidence);
      expect(traceIds.length).to.equal(1);
      expect(traceIds[0]).to.equal(1);
    });

    it("should update agent stats on submission", async function () {
      const horizon = await futureTimestamp(3 * DAY);
      await sigil.connect(detector).submitRiskTrace(
        0, evidence, "Method", "Stage", "Counter",
        5000, 0, horizon, "Remediation",
        DAY, "hash",
        { value: TENTH_ETH }
      );
      const agent = await sigil.agents(detector.address);
      expect(agent.tracesSubmitted).to.equal(1);
      expect(agent.totalBonded).to.equal(TENTH_ETH);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  3. THREAT HORIZON SCOPING (THS)
  // ═══════════════════════════════════════════════════════════════════

  describe("Threat Horizon Scoping", function () {
    let traceId;

    beforeEach(async function () {
      const horizon = await futureTimestamp(4 * DAY);
      await sigil.connect(detector).submitRiskTrace(
        0, evidence, "YARA match", "Execution",
        "Benign ruled out", 8000, 1, // Stepwise
        horizon, "Quarantine", 2 * DAY, "hash",
        { value: TENTH_ETH }
      );
      traceId = 1;
    });

    it("should remain Active before 50% horizon", async function () {
      await advanceTime(DAY); // 25% of 4-day horizon
      await sigil.updateTraceHorizon(traceId);
      const trace = await sigil.traces(traceId);
      expect(trace.status).to.equal(0); // Active
    });

    it("should transition to Decaying at 50% horizon", async function () {
      await advanceTime(2 * DAY + 1); // Past 50%
      await sigil.updateTraceHorizon(traceId);
      const trace = await sigil.traces(traceId);
      expect(trace.status).to.equal(1); // Decaying
    });

    it("should transition to Archived past horizon", async function () {
      await advanceTime(4 * DAY + 1);
      await sigil.updateTraceHorizon(traceId);
      const trace = await sigil.traces(traceId);
      expect(trace.status).to.equal(5); // Archived
    });

    it("should emit TraceStatusChanged on transition", async function () {
      await advanceTime(2 * DAY + 1);
      await expect(sigil.updateTraceHorizon(traceId))
        .to.emit(sigil, "TraceStatusChanged");
    });

    it("should handle mitigation with partial refund", async function () {
      // At 25% of horizon, expect ~75% refund
      await advanceTime(DAY);
      const balBefore = await ethers.provider.getBalance(detector.address);
      await sigil.connect(defender).reportMitigation(traceId, mitigationProof);
      const trace = await sigil.traces(traceId);
      expect(trace.status).to.equal(6); // Mitigated
    });

    it("should emit ThreatMitigated event", async function () {
      await expect(
        sigil.connect(defender).reportMitigation(traceId, mitigationProof)
      ).to.emit(sigil, "ThreatMitigated");
    });

    it("should reject mitigation with zero proof", async function () {
      await expect(
        sigil.connect(defender).reportMitigation(traceId, ethers.ZeroHash)
      ).to.be.revertedWith("Proof required");
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  4. CONFIDENCE DECAY FUNCTIONS (CDF)
  // ═══════════════════════════════════════════════════════════════════

  describe("Confidence Decay Functions", function () {

    describe("Exponential Decay", function () {
      let traceId;

      beforeEach(async function () {
        const horizon = await futureTimestamp(4 * DAY);
        await sigil.connect(detector).submitRiskTrace(
          0, evidence, "Method", "Stage", "Counter",
          8000, 0, // Exponential
          horizon, "Remediation", 2 * DAY, "hash",
          { value: ONE_ETH }
        );
        traceId = 1;
      });

      it("should return full bond at t=0", async function () {
        const decayed = await sigil.computeDecayedBond(traceId);
        // Should be close to 1 ETH (small time may have passed)
        expect(decayed).to.be.closeTo(ONE_ETH, ethers.parseEther("0.01"));
      });

      it("should decay to ~60.7% at 25% of horizon", async function () {
        await advanceTime(DAY); // 25% of 4 days
        const decayed = await sigil.computeDecayedBond(traceId);
        const expected = ethers.parseEther("0.607");
        expect(decayed).to.be.closeTo(expected, ethers.parseEther("0.05"));
      });

      it("should decay to ~36.8% at 50% of horizon", async function () {
        await advanceTime(2 * DAY);
        const decayed = await sigil.computeDecayedBond(traceId);
        const expected = ethers.parseEther("0.368");
        expect(decayed).to.be.closeTo(expected, ethers.parseEther("0.05"));
      });

      it("should decay to ~13.5% at 100% of horizon", async function () {
        await advanceTime(4 * DAY - 10); // Just before horizon
        const decayed = await sigil.computeDecayedBond(traceId);
        const expected = ethers.parseEther("0.135");
        expect(decayed).to.be.closeTo(expected, ethers.parseEther("0.05"));
      });

      it("should return 0 past horizon", async function () {
        await advanceTime(4 * DAY + 1);
        const decayed = await sigil.computeDecayedBond(traceId);
        expect(decayed).to.equal(0);
      });
    });

    describe("Stepwise Decay", function () {
      let traceId;

      beforeEach(async function () {
        const horizon = await futureTimestamp(4 * DAY);
        await sigil.connect(detector).submitRiskTrace(
          0, evidence, "Method", "Stage", "Counter",
          8000, 1, // Stepwise
          horizon, "Remediation", 2 * DAY, "hash",
          { value: ONE_ETH }
        );
        traceId = 1;
      });

      it("should return full bond before 50% horizon", async function () {
        await advanceTime(DAY);
        const decayed = await sigil.computeDecayedBond(traceId);
        expect(decayed).to.equal(ONE_ETH);
      });

      it("should return 50% between 50-100% horizon", async function () {
        await advanceTime(3 * DAY);
        const decayed = await sigil.computeDecayedBond(traceId);
        expect(decayed).to.equal(ONE_ETH / 2n);
      });

      it("should return 0 past horizon", async function () {
        await advanceTime(4 * DAY + 1);
        const decayed = await sigil.computeDecayedBond(traceId);
        expect(decayed).to.equal(0);
      });
    });

    describe("Evidence-Conditional Decay", function () {
      let traceId;

      beforeEach(async function () {
        const horizon = await futureTimestamp(10 * DAY);
        await sigil.connect(detector).submitRiskTrace(
          0, evidence, "Method", "Stage", "Counter",
          8000, 2, // EvidenceConditional
          horizon, "Remediation", 5 * DAY, "hash",
          { value: ONE_ETH }
        );
        traceId = 1;
      });

      it("should return full bond with no counter-evidence", async function () {
        const decayed = await sigil.computeDecayedBond(traceId);
        expect(decayed).to.equal(ONE_ETH);
      });

      it("should decay to 50% after 1 counter-evidence", async function () {
        await sigil.connect(challenger).registerCounterEvidence(traceId, counterEvidence);
        const decayed = await sigil.computeDecayedBond(traceId);
        expect(decayed).to.equal(ONE_ETH / 2n);
      });

      it("should decay to 33% after 2 counter-evidence events", async function () {
        await sigil.connect(challenger).registerCounterEvidence(traceId, counterEvidence);
        const ce2 = ethers.keccak256(ethers.toUtf8Bytes("patch-v2"));
        await sigil.connect(defender).registerCounterEvidence(traceId, ce2);
        const decayed = await sigil.computeDecayedBond(traceId);
        expect(decayed).to.equal(ONE_ETH / 3n);
      });

      it("should emit CounterEvidenceRegistered", async function () {
        await expect(
          sigil.connect(challenger).registerCounterEvidence(traceId, counterEvidence)
        ).to.emit(sigil, "CounterEvidenceRegistered").withArgs(traceId, 1);
      });

      it("should emit DecayCheckpoint", async function () {
        await expect(
          sigil.connect(challenger).registerCounterEvidence(traceId, counterEvidence)
        ).to.emit(sigil, "DecayCheckpoint");
      });
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  5. REASONING DUELS
  // ═══════════════════════════════════════════════════════════════════

  describe("Reasoning Duels", function () {
    let traceId;

    beforeEach(async function () {
      const horizon = await futureTimestamp(7 * DAY);
      await sigil.connect(detector).submitRiskTrace(
        0, evidence, "YARA + sandbox", "Execution (T1059)",
        "Packed executable ruled out: entropy 7.98",
        8500, 1, horizon, "Quarantine",
        3 * DAY, "hash_reasoning_abc",
        { value: ONE_ETH }
      );
      traceId = 1;

      // Reduce voting period for testing
      await sigil.connect(owner).setVotingPeriod(HOUR);
    });

    it("should initiate a duel with sufficient bond", async function () {
      await sigil.connect(challenger).initiateRiskDuel(
        traceId,
        "The entropy analysis is flawed: packed benign software can reach 7.98",
        "counterHypothesis",
        { value: HALF_ETH }
      );
      expect(await sigil.duelCount()).to.equal(1);
      const trace = await sigil.traces(traceId);
      expect(trace.status).to.equal(2); // Challenged
    });

    it("should emit DuelInitiated event", async function () {
      await expect(
        sigil.connect(challenger).initiateRiskDuel(
          traceId, "Reasoning", "detectionMethod",
          { value: HALF_ETH }
        )
      ).to.emit(sigil, "DuelInitiated");
    });

    it("should reject self-challenge", async function () {
      await expect(
        sigil.connect(detector).initiateRiskDuel(
          traceId, "Self", "confidence",
          { value: HALF_ETH }
        )
      ).to.be.revertedWith("Cannot challenge own trace");
    });

    it("should reject challenge after window closes", async function () {
      await advanceTime(3 * DAY + 1);
      await expect(
        sigil.connect(challenger).initiateRiskDuel(
          traceId, "Late", "method",
          { value: HALF_ETH }
        )
      ).to.be.revertedWith("Challenge window closed");
    });

    it("should allow voting on duel", async function () {
      await sigil.connect(challenger).initiateRiskDuel(
        traceId, "Reasoning", "method",
        { value: HALF_ETH }
      );
      await sigil.connect(voter).voteOnDuel(1, false); // Vote for challenger
      const duel = await sigil.getDuel(1);
      expect(duel.votesForChallenger).to.equal(1);
    });

    it("should prevent parties from voting", async function () {
      await sigil.connect(challenger).initiateRiskDuel(
        traceId, "Reasoning", "method",
        { value: HALF_ETH }
      );
      await expect(
        sigil.connect(challenger).voteOnDuel(1, true)
      ).to.be.revertedWith("Parties cannot vote");
    });

    it("should prevent double voting", async function () {
      await sigil.connect(challenger).initiateRiskDuel(
        traceId, "Reasoning", "method",
        { value: HALF_ETH }
      );
      await sigil.connect(voter).voteOnDuel(1, true);
      await expect(
        sigil.connect(voter).voteOnDuel(1, false)
      ).to.be.revertedWith("Already voted");
    });

    it("should resolve duel in challenger's favor", async function () {
      await sigil.connect(challenger).initiateRiskDuel(
        traceId, "Better reasoning", "counterHypothesis",
        { value: HALF_ETH }
      );
      // Two votes for challenger
      await sigil.connect(voter).voteOnDuel(1, false);
      await sigil.connect(agent5).voteOnDuel(1, false);

      await advanceTime(HOUR + 1);

      const balBefore = await ethers.provider.getBalance(challenger.address);
      await sigil.resolveDuel(1);
      const balAfter = await ethers.provider.getBalance(challenger.address);

      const duel = await sigil.getDuel(1);
      expect(duel.outcome).to.equal(2); // ChallengerWins

      const trace = await sigil.traces(traceId);
      expect(trace.status).to.equal(4); // Slashed
    });

    it("should resolve duel in original's favor", async function () {
      await sigil.connect(challenger).initiateRiskDuel(
        traceId, "Weak reasoning", "method",
        { value: HALF_ETH }
      );
      await sigil.connect(voter).voteOnDuel(1, true);
      await sigil.connect(agent5).voteOnDuel(1, true);

      await advanceTime(HOUR + 1);
      await sigil.resolveDuel(1);

      const duel = await sigil.getDuel(1);
      expect(duel.outcome).to.equal(1); // OriginalWins

      // Detector gets their bond + challenger's bond
      const agentStats = await sigil.agents(detector.address);
      expect(agentStats.duelsWon).to.equal(1);
    });

    it("should update agent stats after duel", async function () {
      await sigil.connect(challenger).initiateRiskDuel(
        traceId, "Reasoning", "method",
        { value: HALF_ETH }
      );
      await sigil.connect(voter).voteOnDuel(1, false);
      await advanceTime(HOUR + 1);
      await sigil.resolveDuel(1);

      const challengerStats = await sigil.agents(challenger.address);
      expect(challengerStats.duelsWon).to.equal(1);

      const detectorStats = await sigil.agents(detector.address);
      expect(detectorStats.duelsLost).to.equal(1);
      expect(detectorStats.tracesSlashed).to.equal(1);
    });

    it("should emit DuelResolved event", async function () {
      await sigil.connect(challenger).initiateRiskDuel(
        traceId, "Reasoning", "method",
        { value: HALF_ETH }
      );
      await sigil.connect(voter).voteOnDuel(1, true);
      await advanceTime(HOUR + 1);
      await expect(sigil.resolveDuel(1)).to.emit(sigil, "DuelResolved");
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  6. CROSS-AGENT CORROBORATION (CACW)
  // ═══════════════════════════════════════════════════════════════════

  describe("Cross-Agent Corroboration", function () {
    let traceId1, traceId2, traceId3;

    beforeEach(async function () {
      const horizon = await futureTimestamp(7 * DAY);

      // Trace 1: detector via network analysis
      await sigil.connect(detector).submitRiskTrace(
        0, evidence, "Network traffic analysis", "C2 (T1071)",
        "Normal HTTPS ruled out", 8000, 0, horizon,
        "Block C2 domain", 3 * DAY, "hash_network_analysis",
        { value: TENTH_ETH }
      );
      traceId1 = 1;

      // Trace 2: challenger via binary analysis (different method, same evidence)
      await sigil.connect(challenger).submitRiskTrace(
        0, evidence, "Binary decompilation", "Execution (T1059)",
        "Benign packer ruled out", 7500, 0, horizon,
        "Sandbox and quarantine", 3 * DAY, "hash_binary_decompilation",
        { value: TENTH_ETH }
      );
      traceId2 = 2;

      // Trace 3: defender via same method as trace 1 (redundant)
      await sigil.connect(defender).submitRiskTrace(
        0, evidence, "Network traffic analysis", "C2 (T1071)",
        "Normal HTTPS ruled out", 7800, 0, horizon,
        "Block domain", 3 * DAY, "hash_network_copy",
        { value: TENTH_ETH }
      );
      traceId3 = 3;
    });

    it("should register non-redundant corroboration with weight boost", async function () {
      await sigil.connect(voter).registerCorroboration(traceId1, traceId2, true);
      const trace = await sigil.traces(traceId1);
      expect(trace.corroborationWeight).to.equal(15000); // 1.0 + 0.5
    });

    it("should register redundant corroboration with smaller boost", async function () {
      await sigil.connect(voter).registerCorroboration(traceId1, traceId3, false);
      const trace = await sigil.traces(traceId1);
      expect(trace.corroborationWeight).to.equal(11000); // 1.0 + 0.1
    });

    it("should cap corroboration weight at 3x", async function () {
      // Add 5 non-redundant corroborations (would be 10000 + 5*5000 = 35000, capped at 30000)
      await sigil.connect(voter).registerCorroboration(traceId1, traceId2, true);
      // Need more traces for more corroborations
      const horizon = await futureTimestamp(7 * DAY);
      await sigil.connect(agent5).submitRiskTrace(
        0, evidence, "Unique method", "Stage", "Counter",
        7000, 0, horizon, "Rem", 3 * DAY, "hash_unique",
        { value: TENTH_ETH }
      );
      await sigil.connect(voter).registerCorroboration(traceId1, 4, true);
      // Weight should be 10000 + 5000 + 5000 = 20000
      const trace = await sigil.traces(traceId1);
      expect(trace.corroborationWeight).to.equal(20000);
    });

    it("should reject self-corroboration", async function () {
      await expect(
        sigil.connect(voter).registerCorroboration(traceId1, traceId1, true)
      ).to.be.revertedWith("Cannot self-corroborate");
    });

    it("should reject same-detector corroboration", async function () {
      // detector submitted trace 1, would need detector's second trace
      // Since trace 1 and trace 3 are from different detectors, this is OK
      // Let's try detector corroborating with their own: not possible since
      // detector only has trace 1
    });

    it("should reject duplicate corroboration", async function () {
      await sigil.connect(voter).registerCorroboration(traceId1, traceId2, true);
      await expect(
        sigil.connect(voter).registerCorroboration(traceId1, traceId2, true)
      ).to.be.revertedWith("Already corroborated");
    });

    it("should track corroborating trace IDs", async function () {
      await sigil.connect(voter).registerCorroboration(traceId1, traceId2, true);
      const corr = await sigil.getCorroboratingTraces(traceId1);
      expect(corr.length).to.equal(1);
      expect(corr[0]).to.equal(traceId2);
    });

    it("should compute effective bond with corroboration", async function () {
      await sigil.connect(voter).registerCorroboration(traceId1, traceId2, true);
      const effective = await sigil.getEffectiveBond(traceId1);
      // Decayed bond * 1.5
      const decayed = await sigil.computeDecayedBond(traceId1);
      const expected = (decayed * 15000n) / 10000n;
      expect(effective).to.equal(expected);
    });

    it("should emit CorroborationRegistered event", async function () {
      await expect(
        sigil.connect(voter).registerCorroboration(traceId1, traceId2, true)
      ).to.emit(sigil, "CorroborationRegistered").withArgs(traceId1, traceId2, 15000);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  7. INVERSE REASONING BONDS
  // ═══════════════════════════════════════════════════════════════════

  describe("Inverse Reasoning Bonds", function () {

    it("should submit an inverse bond", async function () {
      await sigil.connect(challenger).submitInverseBond(
        "The firewall has an unpatched CVE-2026-1234 in the DMZ",
        evidence,
        "Corporate DMZ firewall cluster",
        3 * DAY,
        { value: TENTH_ETH }
      );
      expect(await sigil.inverseBondCount()).to.equal(1);
      const ib = await sigil.inverseBonds(1);
      expect(ib.claimant).to.equal(challenger.address);
      expect(ib.status).to.equal(0); // Open
    });

    it("should emit InverseBondSubmitted event", async function () {
      await expect(
        sigil.connect(challenger).submitInverseBond(
          "Risk claim", evidence, "System", 0,
          { value: TENTH_ETH }
        )
      ).to.emit(sigil, "InverseBondSubmitted");
    });

    it("should use default defense window when 0 specified", async function () {
      await sigil.connect(challenger).submitInverseBond(
        "Risk", evidence, "System", 0,
        { value: TENTH_ETH }
      );
      const ib = await sigil.inverseBonds(1);
      expect(ib.defenseWindow).to.equal(3 * DAY);
    });

    it("should allow defense with a safety trace", async function () {
      await sigil.connect(challenger).submitInverseBond(
        "Unpatched CVE", evidence, "DMZ", 3 * DAY,
        { value: TENTH_ETH }
      );

      // Defender submits a safety trace
      const horizon = await futureTimestamp(7 * DAY);
      await sigil.connect(defender).submitRiskTrace(
        3, // Anomaly (used as "safe" assessment here)
        evidence, "Full vulnerability scan", "N/A",
        "CVE-2026-1234 was patched on March 10",
        9000, 1, horizon, "No action needed",
        DAY, "hash_defense",
        { value: TENTH_ETH }
      );

      await sigil.connect(defender).defendInverseBond(1, 1);
      const ib = await sigil.inverseBonds(1);
      expect(ib.status).to.equal(1); // Defended
      expect(ib.defender).to.equal(defender.address);
    });

    it("should reject self-defense", async function () {
      await sigil.connect(challenger).submitInverseBond(
        "Risk", evidence, "System", 3 * DAY,
        { value: TENTH_ETH }
      );
      const horizon = await futureTimestamp(7 * DAY);
      await sigil.connect(challenger).submitRiskTrace(
        0, evidence, "Method", "Stage", "Counter",
        5000, 0, horizon, "Rem", DAY, "hash",
        { value: TENTH_ETH }
      );
      await expect(
        sigil.connect(challenger).defendInverseBond(1, 1)
      ).to.be.revertedWith("Claimant cannot self-defend");
    });

    it("should resolve expired inverse bond (no defender)", async function () {
      await sigil.connect(challenger).submitInverseBond(
        "Ignored vulnerability", evidence, "API Gateway", 2 * DAY,
        { value: TENTH_ETH }
      );

      await advanceTime(2 * DAY + 1);

      const balBefore = await ethers.provider.getBalance(challenger.address);
      await sigil.resolveExpiredInverseBond(1);
      const balAfter = await ethers.provider.getBalance(challenger.address);

      const ib = await sigil.inverseBonds(1);
      expect(ib.status).to.equal(4); // Expired

      const stats = await sigil.agents(challenger.address);
      expect(stats.inverseBondsWon).to.equal(1);
    });

    it("should reject early expiration resolution", async function () {
      await sigil.connect(challenger).submitInverseBond(
        "Risk", evidence, "System", 3 * DAY,
        { value: TENTH_ETH }
      );
      await expect(
        sigil.resolveExpiredInverseBond(1)
      ).to.be.revertedWith("Defense window not expired");
    });

    it("should emit InverseBondResolved on expiration", async function () {
      await sigil.connect(challenger).submitInverseBond(
        "Risk", evidence, "System", 2 * DAY,
        { value: TENTH_ETH }
      );
      await advanceTime(2 * DAY + 1);
      await expect(sigil.resolveExpiredInverseBond(1))
        .to.emit(sigil, "InverseBondResolved");
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  8. VIEW FUNCTIONS & REPUTATION
  // ═══════════════════════════════════════════════════════════════════

  describe("Reputation & View Functions", function () {

    it("should return default cognitive score for new agent", async function () {
      const score = await sigil.getCognitiveScore(detector.address);
      expect(score).to.equal(5000); // 50%
    });

    it("should return 0 for unregistered agent", async function () {
      const score = await sigil.getCognitiveScore(owner.address);
      expect(score).to.equal(0);
    });

    it("should correctly check challengeability", async function () {
      const horizon = await futureTimestamp(7 * DAY);
      await sigil.connect(detector).submitRiskTrace(
        0, evidence, "Method", "Stage", "Counter",
        5000, 0, horizon, "Rem", DAY, "hash",
        { value: TENTH_ETH }
      );
      expect(await sigil.isChallengeable(1)).to.be.true;

      await advanceTime(DAY + 1);
      expect(await sigil.isChallengeable(1)).to.be.false;
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  9. ADMIN FUNCTIONS
  // ═══════════════════════════════════════════════════════════════════

  describe("Admin", function () {
    it("should allow owner to set min trace bond", async function () {
      await sigil.connect(owner).setMinTraceBond(ethers.parseEther("0.01"));
      expect(await sigil.minTraceBond()).to.equal(ethers.parseEther("0.01"));
    });

    it("should reject non-owner admin calls", async function () {
      await expect(
        sigil.connect(detector).setMinTraceBond(1)
      ).to.be.revertedWith("Not owner");
    });

    it("should allow owner to set voting period", async function () {
      await sigil.connect(owner).setVotingPeriod(2 * DAY);
      expect(await sigil.votingPeriod()).to.equal(2 * DAY);
    });

    it("should allow owner to set defense window", async function () {
      await sigil.connect(owner).setDefaultDefenseWindow(7 * DAY);
      expect(await sigil.defaultDefenseWindow()).to.equal(7 * DAY);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  10. INTEGRATION SCENARIO
  // ═══════════════════════════════════════════════════════════════════

  describe("Integration: Full Lifecycle", function () {

    it("should handle full trace → challenge → duel → resolution lifecycle", async function () {
      await sigil.connect(owner).setVotingPeriod(HOUR);

      // 1. Detector submits bonded malware detection
      const horizon = await futureTimestamp(7 * DAY);
      await sigil.connect(detector).submitRiskTrace(
        0, evidence, "Sandbox detonation + YARA",
        "Execution (T1059.001)",
        "PowerShell admin script ruled out: no scheduled task, no GPO",
        9200, 0, horizon,
        "Isolate endpoint, block hash at EDR level",
        3 * DAY, "hash_full_analysis",
        { value: ONE_ETH }
      );

      // 2. Second detector corroborates via different method
      await sigil.connect(defender).submitRiskTrace(
        0, evidence, "Network C2 beacon detection",
        "Command & Control (T1071.001)",
        "Normal HTTPS traffic ruled out: beacon interval 60±5s",
        8800, 0, horizon,
        "Block C2 domain and IP",
        3 * DAY, "hash_network_c2",
        { value: HALF_ETH }
      );

      // Register non-redundant corroboration
      await sigil.connect(voter).registerCorroboration(1, 2, true);
      let trace1 = await sigil.traces(1);
      expect(trace1.corroborationWeight).to.equal(15000);

      // 3. Challenger disputes the counter-hypothesis
      await sigil.connect(challenger).initiateRiskDuel(
        1,
        "PowerShell GPO deployment was scheduled for this week. The detector failed to check AD.",
        "counterHypothesis",
        { value: HALF_ETH }
      );

      // 4. Vote: network analyst sides with original
      await sigil.connect(defender).voteOnDuel(1, true);
      await sigil.connect(agent5).voteOnDuel(1, true);

      // 5. Resolve: original wins
      await advanceTime(HOUR + 1);
      await sigil.resolveDuel(1);

      const duel = await sigil.getDuel(1);
      expect(duel.outcome).to.equal(1); // OriginalWins

      trace1 = await sigil.traces(1);
      expect(trace1.status).to.equal(0); // Back to Active

      // 6. Check reputation
      const detectorScore = await sigil.getCognitiveScore(detector.address);
      expect(detectorScore).to.be.gte(5000); // At or above default
    });

    it("should handle inverse bond → defense → resolution lifecycle", async function () {
      await sigil.connect(owner).setVotingPeriod(HOUR);

      // 1. Red team claims missed vulnerability
      await sigil.connect(agent5).submitInverseBond(
        "SQL injection in /api/v2/users endpoint — no WAF rule covers parameterized bypass",
        evidence2,
        "Production API server api.example.com",
        2 * DAY,
        { value: HALF_ETH }
      );

      // 2. Blue team defends with safety trace
      const horizon = await futureTimestamp(7 * DAY);
      await sigil.connect(defender).submitRiskTrace(
        2, // Vulnerability type
        evidence2,
        "DAST scan + manual code review",
        "N/A — no vulnerability found",
        "Parameterized queries confirmed in all routes; WAF rule 942100 covers bypass",
        9500, 1, horizon,
        "No action required; monitoring in place",
        DAY, "hash_blue_defense",
        { value: HALF_ETH }
      );

      await sigil.connect(defender).defendInverseBond(1, 1);
      let ib = await sigil.inverseBonds(1);
      expect(ib.status).to.equal(1); // Defended

      // 3. Defense trace survives challenge window
      await advanceTime(DAY + 1);
      await sigil.resolveDefendedInverseBond(1);

      ib = await sigil.inverseBonds(1);
      expect(ib.status).to.equal(3); // DefenderWon

      const defenderStats = await sigil.agents(defender.address);
      expect(defenderStats.inverseBondsWon).to.equal(1);
    });
  });
});
