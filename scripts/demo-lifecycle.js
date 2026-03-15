const hre = require("hardhat");
const { ethers } = hre;

// ═══════════════════════════════════════════════════════════════════
//  SIGIL PROTOCOL — Full Lifecycle Interactive Demo
//  Runs on Base Sepolia (or local Hardhat network)
//
//  Demonstrates:
//    1. Agent registration (3 agents)
//    2. Risk trace submission (malware detection, bonded)
//    3. Corroborating trace (different method, same threat)
//    4. Cross-Agent Corroboration registration
//    5. Confidence Decay checkpoint
//    6. Counter-evidence registration
//    7. Reasoning Duel (challenge + vote + resolution)
//    8. Inverse Reasoning Bond (challenge absence of detection)
//    9. Inverse Bond defense
//   10. Inverse Bond resolution
//   11. Final reputation scores
//
//  Usage:
//    Local:   npx hardhat run scripts/demo-lifecycle.js
//    Sepolia: npx hardhat run scripts/demo-lifecycle.js --network baseSepolia
// ═══════════════════════════════════════════════════════════════════

const COLORS = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
};

function banner(text) {
  const line = "═".repeat(60);
  console.log(`\n${COLORS.cyan}${line}${COLORS.reset}`);
  console.log(`${COLORS.bright}${COLORS.cyan}  ${text}${COLORS.reset}`);
  console.log(`${COLORS.cyan}${line}${COLORS.reset}\n`);
}

function step(num, text) {
  console.log(`${COLORS.yellow}[Step ${num}/11]${COLORS.reset} ${COLORS.bright}${text}${COLORS.reset}`);
}

function info(text) {
  console.log(`  ${COLORS.dim}→ ${text}${COLORS.reset}`);
}

function success(text) {
  console.log(`  ${COLORS.green}✓ ${text}${COLORS.reset}`);
}

function warn(text) {
  console.log(`  ${COLORS.red}✗ ${text}${COLORS.reset}`);
}

function data(label, value) {
  console.log(`  ${COLORS.blue}${label}:${COLORS.reset} ${value}`);
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForTx(tx, label) {
  info(`Waiting for tx: ${label}...`);
  const receipt = await tx.wait();
  success(`${label} confirmed (gas: ${receipt.gasUsed.toString()})`);
  return receipt;
}

// For testnet: use time manipulation if local, or real waits if testnet
async function advanceTimeIfLocal(seconds) {
  const network = await ethers.provider.getNetwork();
  if (network.chainId === 31337n) {
    await ethers.provider.send("evm_increaseTime", [seconds]);
    await ethers.provider.send("evm_mine");
    info(`Advanced time by ${seconds}s (local network)`);
  } else {
    info(`On live network — time-dependent steps will be noted but not waited`);
  }
}

async function main() {
  banner("SIGIL-RD: Full Lifecycle Demo");

  const network = await ethers.provider.getNetwork();
  const isLocal = network.chainId === 31337n;
  data("Network", isLocal ? "Hardhat Local" : `Chain ID ${network.chainId}`);

  // ── Get signers ──
  // On local: multiple signers available
  // On testnet: single deployer acts all roles via contract calls
  const signers = await ethers.getSigners();
  const deployer = signers[0];

  data("Deployer", deployer.address);
  data("Balance", ethers.formatEther(await ethers.provider.getBalance(deployer.address)) + " ETH");

  // ── Deploy contract ──
  banner("Deploying Sigil Protocol");

  const SigilProtocol = await ethers.getContractFactory("SigilProtocol");
  const sigil = await SigilProtocol.deploy();
  await sigil.waitForDeployment();
  const contractAddr = await sigil.getAddress();

  success(`Contract deployed at: ${contractAddr}`);
  data("Protocol", await sigil.PROTOCOL_NAME());
  data("Version", (await sigil.protocolVersion()).toString());

  // Reduce voting period for demo (only on local)
  if (isLocal) {
    await sigil.setVotingPeriod(60); // 60 seconds
    info("Voting period set to 60s for demo");
  }

  // ═══════════════════════════════════════════════════════════════
  //  STEP 1: Register Agents
  // ═══════════════════════════════════════════════════════════════

  step(1, "Registering Agents");

  if (isLocal && signers.length >= 4) {
    // Local: use separate signers for each role
    var detector = signers[0];
    var challenger = signers[1];
    var voter = signers[2];
    var redTeam = signers[3];

    await waitForTx(
      await sigil.connect(detector).registerAgent("Fred & Claude (SOC-Lead)"),
      "Register detector"
    );
    await waitForTx(
      await sigil.connect(challenger).registerAgent("DeepSeek (Threat-Analyst)"),
      "Register challenger"
    );
    await waitForTx(
      await sigil.connect(voter).registerAgent("Gemini (Peer-Reviewer)"),
      "Register voter"
    );
    await waitForTx(
      await sigil.connect(redTeam).registerAgent("RedTeam-Alpha (Offensive)"),
      "Register red team"
    );
  } else {
    // Testnet: single deployer registers as main agent
    var detector = deployer;
    await waitForTx(
      await sigil.connect(detector).registerAgent("Fred & Claude (SOC-Lead)"),
      "Register primary agent"
    );
    info("On testnet: single agent demo (multi-agent requires multiple funded wallets)");
    // For multi-agent on testnet, we'd need multiple funded wallets
    // The demo below will adapt
  }

  data("Total agents", (await sigil.agentCount()).toString());
  console.log();

  // ═══════════════════════════════════════════════════════════════
  //  STEP 2: Submit Malware Detection Trace
  // ═══════════════════════════════════════════════════════════════

  step(2, "Submitting Bonded Malware Detection Trace");

  const evidenceHash = ethers.keccak256(
    ethers.toUtf8Bytes("SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  );
  const horizon = Math.floor(Date.now() / 1000) + 7 * 86400; // 7 days

  const trace1Tx = await sigil.connect(detector).submitRiskTrace(
    0,  // RiskType.Malware
    evidenceHash,
    "YARA rule match (APT29_Loader_v3) + Sandbox detonation: C2 callback to 185.xx.xx.xx:443",
    "Execution (T1059.001) — PowerShell with encoded command",
    "Benign hypothesis rejected: (1) No scheduled GPO deployment for this host, (2) Certificate chain invalid, (3) Entropy 7.98 exceeds packed-legitimate threshold of 7.5",
    9200, // 92% confidence
    0,    // Exponential decay
    horizon,
    "IMMEDIATE: Isolate endpoint from network. Block hash at EDR. Submit IOCs to ISAC feed. Preserve memory dump for forensics.",
    isLocal ? 3 * 86400 : 3 * 86400, // 3 days challenge window
    ethers.keccak256(ethers.toUtf8Bytes("reasoning_chain_sandbox_yara_c2_analysis")),
    { value: ethers.parseEther("0.01") }
  );
  await waitForTx(trace1Tx, "Submit malware trace (Trace #1)");

  const trace1 = await sigil.traces(1);
  data("Trace ID", "1");
  data("Risk Type", "Malware");
  data("Confidence", "92.00%");
  data("Bond", ethers.formatEther(trace1.bondAmount) + " ETH");
  data("Decay Profile", "Exponential");
  data("Kill Chain", "Execution (T1059.001)");
  data("Threat Horizon", new Date(Number(trace1.threatHorizon) * 1000).toISOString());
  console.log();

  // ═══════════════════════════════════════════════════════════════
  //  STEP 3: Corroborating Trace (Different Method)
  // ═══════════════════════════════════════════════════════════════

  step(3, "Submitting Corroborating Trace (Network C2 Beacon Detection)");

  if (isLocal && signers.length >= 4) {
    const trace2Tx = await sigil.connect(redTeam).submitRiskTrace(
      0,  // Same: Malware
      evidenceHash, // Same evidence
      "Network beacon detection: periodic HTTPS POST to 185.xx.xx.xx every 60±5s, JA3 fingerprint matches known APT29 tooling",
      "Command and Control (T1071.001) — HTTPS beacon",
      "Normal HTTPS traffic rejected: (1) Beacon interval 60±5s too regular for human, (2) JA3 hash matches known C2, (3) POST payload entropy 7.2 indicates encrypted exfil",
      8800, // 88% confidence
      0,    // Exponential
      horizon,
      "Block C2 IP at firewall. Deploy JA3 signature to NDR. Monitor for lateral movement.",
      isLocal ? 3 * 86400 : 3 * 86400,
      ethers.keccak256(ethers.toUtf8Bytes("reasoning_chain_network_beacon_ja3")),
      { value: ethers.parseEther("0.008") }
    );
    await waitForTx(trace2Tx, "Submit corroborating trace (Trace #2)");

    data("Trace ID", "2");
    data("Method", "Network C2 beacon detection (orthogonal to sandbox analysis)");
    data("Confidence", "88.00%");
    data("Bond", "0.008 ETH");
    console.log();

    // ═══════════════════════════════════════════════════════════════
    //  STEP 4: Register Cross-Agent Corroboration
    // ═══════════════════════════════════════════════════════════════

    step(4, "Registering Non-Redundant Corroboration (CACW)");

    const corrTx = await sigil.connect(voter).registerCorroboration(
      1,    // Trace #1
      2,    // Corroborated by Trace #2
      true  // Non-redundant (different detection methods)
    );
    await waitForTx(corrTx, "Register corroboration");

    const trace1Updated = await sigil.traces(1);
    data("Corroboration Weight", (Number(trace1Updated.corroborationWeight) / 100).toFixed(1) + "%");
    data("Effective Bond", ethers.formatEther(await sigil.getEffectiveBond(1)) + " ETH");
    success("Two orthogonal detection methods corroborate: sandbox + network analysis");
    console.log();
  } else {
    info("Skipping corroboration on testnet (requires second funded wallet)");
    console.log();
  }

  // ═══════════════════════════════════════════════════════════════
  //  STEP 5: Check Confidence Decay
  // ═══════════════════════════════════════════════════════════════

  step(5, "Confidence Decay Checkpoint");

  const bondAtStart = await sigil.computeDecayedBond(1);
  data("Bond at t=0", ethers.formatEther(bondAtStart) + " ETH");

  if (isLocal) {
    // Advance 1 day (simulated)
    await advanceTimeIfLocal(86400);
    const bondAt1Day = await sigil.computeDecayedBond(1);
    data("Bond at t=1 day", ethers.formatEther(bondAt1Day) + " ETH");
    const decayPct = ((1 - Number(ethers.formatEther(bondAt1Day)) / Number(ethers.formatEther(bondAtStart))) * 100).toFixed(1);
    data("Decay", decayPct + "% (exponential)");
  } else {
    info("Exponential decay will reduce bond over the 7-day threat horizon");
    info("Formula: B(t) = B₀ · exp(-2·t/τ)");
  }
  console.log();

  // ═══════════════════════════════════════════════════════════════
  //  STEP 6: Register Counter-Evidence
  // ═══════════════════════════════════════════════════════════════

  step(6, "Registering Counter-Evidence (Vendor Advisory)");

  if (isLocal && signers.length >= 3) {
    // Switch trace to evidence-conditional for demo, or just show counter-evidence on current
    const ceTx = await sigil.connect(challenger).registerCounterEvidence(
      1,
      ethers.keccak256(ethers.toUtf8Bytes("vendor_advisory_2026_03_15_partial_mitigation"))
    );
    await waitForTx(ceTx, "Register counter-evidence");

    const ceCount = await sigil.counterEvidenceCount(1);
    data("Counter-evidence events", ceCount.toString());
    info("Vendor published advisory: partial mitigation available via signature update");
    info("Bond remains exponential-decayed (evidence-conditional only affects DecayProfile.EvidenceConditional)");
  } else {
    info("Counter-evidence registration available — decreases bond for evidence-conditional decay profiles");
  }
  console.log();

  // ═══════════════════════════════════════════════════════════════
  //  STEP 7: Reasoning Duel
  // ═══════════════════════════════════════════════════════════════

  if (isLocal && signers.length >= 4) {
    step(7, "Initiating Reasoning Duel (Challenge on counter_hypothesis)");

    const duelTx = await sigil.connect(challenger).initiateRiskDuel(
      1, // Challenge Trace #1
      "The counter-hypothesis dismissal is insufficient. PowerShell encoded commands are deployed via SCCM in this environment weekly. The detector failed to check: (1) SCCM deployment schedule for target host, (2) Whether the encoded command matches known SCCM patterns, (3) Whether the certificate chain matches internal CA. I re-executed the analysis and found the encoded command matches SCCM pattern ID 7.",
      "counterHypothesis",
      { value: ethers.parseEther("0.005") }
    );
    await waitForTx(duelTx, "Initiate reasoning duel (Duel #1)");

    const trace1Status = await sigil.traces(1);
    data("Trace #1 status", "Challenged");
    data("Duel ID", "1");
    data("Challenged field", "counterHypothesis");
    data("Challenger bond", "0.005 ETH");
    console.log();

    // ── Vote ──
    step(7, "Voting on Reasoning Duel");

    // Voter and RedTeam both support original (detector checked SCCM, challenger missed that)
    await waitForTx(
      await sigil.connect(voter).voteOnDuel(1, true),
      "Voter votes FOR original"
    );
    await waitForTx(
      await sigil.connect(redTeam).voteOnDuel(1, true),
      "RedTeam votes FOR original"
    );

    const duelBefore = await sigil.getDuel(1);
    data("Votes for original", duelBefore.votesForOriginal.toString());
    data("Votes for challenger", duelBefore.votesForChallenger.toString());
    console.log();

    // ── Resolve ──
    step(7, "Resolving Reasoning Duel");

    await advanceTimeIfLocal(120); // Past voting period

    const resolveTx = await sigil.resolveDuel(1);
    await waitForTx(resolveTx, "Resolve duel");

    const duelAfter = await sigil.getDuel(1);
    if (duelAfter.outcome === 1n) {
      success("ORIGINAL WINS — Detector's counter-hypothesis was sufficient");
      info("Challenger's bond (0.005 ETH) transferred to detector");
    } else {
      warn("CHALLENGER WINS — Detector's reasoning was flawed");
      info("Detector's bond seized by challenger");
    }

    const detectorStats = await sigil.agents(detector.address);
    data("Detector duels won", detectorStats.duelsWon.toString());
    data("Challenger duels lost", (await sigil.agents(challenger.address)).duelsLost.toString());
  } else {
    step(7, "Reasoning Duel");
    info("Requires multiple funded wallets on testnet — demonstrated locally");
  }
  console.log();

  // ═══════════════════════════════════════════════════════════════
  //  STEP 8: Inverse Reasoning Bond
  // ═══════════════════════════════════════════════════════════════

  step(8, "Submitting Inverse Reasoning Bond (Challenge Absence of Detection)");

  if (isLocal && signers.length >= 4) {
    const ibTx = await sigil.connect(redTeam).submitInverseBond(
      "SQL injection vulnerability in /api/v2/users endpoint. The parameterized query bypass via UNION-based injection with nested encoding has been publicly disclosed (CVE-2026-31415) but no SOC alert exists. The WAF rule 942100 does not cover double-URL-encoded payloads. Evidence: successful exploitation in staging environment with identical configuration.",
      ethers.keccak256(ethers.toUtf8Bytes("CVE-2026-31415_staging_exploit_pcap")),
      "Production API: api.catalyst.internal (10.0.1.50:443)",
      isLocal ? 120 : 2 * 86400, // 2 min (local) or 2 days
      { value: ethers.parseEther("0.015") }
    );
    await waitForTx(ibTx, "Submit inverse bond (IB #1)");

    const ib = await sigil.inverseBonds(1);
    data("Inverse Bond ID", "1");
    data("Claimant", "RedTeam-Alpha");
    data("System Target", "Production API: api.catalyst.internal");
    data("Bond", ethers.formatEther(ib.bondAmount) + " ETH");
    data("Status", "Open — awaiting defense");
    data("Defense Window", isLocal ? "120s" : "2 days");
    console.log();

    // ═══════════════════════════════════════════════════════════════
    //  STEP 9: Defend Inverse Bond
    // ═══════════════════════════════════════════════════════════════

    step(9, "Defending Inverse Bond (Blue Team Safety Trace)");

    // Defender submits a safety trace
    const defenseTraceTx = await sigil.connect(challenger).submitRiskTrace(
      2, // Vulnerability
      ethers.keccak256(ethers.toUtf8Bytes("CVE-2026-31415_staging_exploit_pcap")),
      "DAST scan (Burp Suite Pro) + manual code review of /api/v2/users handler",
      "N/A — no active exploitation in production",
      "RedTeam's staging exploit does NOT reproduce in production: (1) Production uses parameterized ORM (SQLAlchemy 2.x), staging still on raw SQL driver (legacy config), (2) WAF rule 942100 updated to v3.2 on March 12 covering double-URL encoding, (3) Network segmentation prevents staging→prod lateral path",
      9500, // 95% confidence this is safe
      1,    // Stepwise decay
      horizon,
      "No action required. Staging environment to be migrated to ORM by March 20. Monitoring in place.",
      isLocal ? 60 : 86400,
      ethers.keccak256(ethers.toUtf8Bytes("reasoning_chain_blue_team_defense")),
      { value: ethers.parseEther("0.008") }
    );
    await waitForTx(defenseTraceTx, "Submit defense trace (Trace #3)");

    // Get the trace ID (should be 3)
    const defenseTraceId = await sigil.traceCount();

    // Defend the inverse bond with this trace
    const defendTx = await sigil.connect(challenger).defendInverseBond(
      1,             // Inverse Bond #1
      defenseTraceId // Defense Trace
    );
    await waitForTx(defendTx, "Defend inverse bond");

    const ibDefended = await sigil.inverseBonds(1);
    data("Inverse Bond Status", "Defended");
    data("Defender", "DeepSeek (Threat-Analyst)");
    data("Defense Trace ID", defenseTraceId.toString());
    success("Blue team provided structured reasoning why system is safe");
    console.log();

    // ═══════════════════════════════════════════════════════════════
    //  STEP 10: Resolve Inverse Bond
    // ═══════════════════════════════════════════════════════════════

    step(10, "Resolving Inverse Bond");

    // Wait for defense trace challenge window to expire
    await advanceTimeIfLocal(120);

    const resolveIbTx = await sigil.resolveDefendedInverseBond(1);
    await waitForTx(resolveIbTx, "Resolve inverse bond");

    const ibFinal = await sigil.inverseBonds(1);
    if (ibFinal.status === 3n) {
      success("DEFENDER WINS — Blue team successfully justified system safety");
      info("RedTeam's bond (0.015 ETH) transferred to defender as reward");
    } else if (ibFinal.status === 2n) {
      warn("CHALLENGER WINS — Defense was insufficient or slashed");
      info("RedTeam gets their bond back + validation credit");
    }
  } else {
    step(8, "Inverse Reasoning Bond");
    info("Submitting inverse bond with single wallet...");

    const ibTx = await sigil.connect(detector).submitInverseBond(
      "SQL injection in /api/v2/users — CVE-2026-31415 undetected",
      ethers.keccak256(ethers.toUtf8Bytes("CVE-2026-31415_exploit")),
      "Production API api.catalyst.internal",
      2 * 86400,
      { value: ethers.parseEther("0.005") }
    );
    await waitForTx(ibTx, "Submit inverse bond");
    success("Inverse bond submitted — awaiting defender on-chain");
    info("Defense window: 2 days. Any registered agent can defend.");

    step(9, "Defend & Resolve");
    info("Requires a different wallet to defend — run with multiple funded wallets");
    step(10, "Resolution");
    info("Skipped on single-wallet testnet demo");
  }
  console.log();

  // ═══════════════════════════════════════════════════════════════
  //  STEP 11: Final Reputation Scores
  // ═══════════════════════════════════════════════════════════════

  step(11, "Final Reputation & Cognitive Scores");
  console.log();

  const agentAddresses = isLocal && signers.length >= 4
    ? [detector.address, challenger.address, voter.address, redTeam.address]
    : [detector.address];

  const agentNames = isLocal && signers.length >= 4
    ? ["Fred & Claude (SOC-Lead)", "DeepSeek (Threat-Analyst)", "Gemini (Peer-Reviewer)", "RedTeam-Alpha"]
    : ["Fred & Claude (SOC-Lead)"];

  for (let i = 0; i < agentAddresses.length; i++) {
    const addr = agentAddresses[i];
    const agent = await sigil.agents(addr);
    const reputation = await sigil.getReputationScore(addr);
    const cognitive = await sigil.getCognitiveScore(addr);

    console.log(`  ${COLORS.bright}${agentNames[i]}${COLORS.reset}`);
    data("    Address", addr.slice(0, 10) + "...");
    data("    Traces submitted", agent.tracesSubmitted.toString());
    data("    Traces validated", agent.tracesValidated.toString());
    data("    Traces slashed", agent.tracesSlashed.toString());
    data("    Duels won/lost", `${agent.duelsWon}/${agent.duelsLost}`);
    data("    Inverse bonds won/lost", `${agent.inverseBondsWon}/${agent.inverseBondsLost}`);
    data("    Total bonded", ethers.formatEther(agent.totalBonded) + " ETH");
    data("    Total earned", ethers.formatEther(agent.totalEarned) + " ETH");
    data("    Total slashed", ethers.formatEther(agent.totalSlashed) + " ETH");
    data("    Reputation score", reputation.toString());
    data("    Cognitive score", (Number(cognitive) / 100).toFixed(1) + "%");
    console.log();
  }

  // ═══════════════════════════════════════════════════════════════
  //  SUMMARY
  // ═══════════════════════════════════════════════════════════════

  banner("Demo Complete");

  data("Contract", contractAddr);
  data("Traces submitted", (await sigil.traceCount()).toString());
  data("Duels conducted", (await sigil.duelCount()).toString());
  data("Inverse bonds", (await sigil.inverseBondCount()).toString());
  data("Agents registered", (await sigil.agentCount()).toString());
  console.log();

  if (!isLocal) {
    console.log(`  ${COLORS.bright}View on BaseScan:${COLORS.reset}`);
    console.log(`  https://sepolia.basescan.org/address/${contractAddr}`);
    console.log();
    console.log(`  ${COLORS.bright}Verify contract:${COLORS.reset}`);
    console.log(`  npx hardhat verify --network baseSepolia ${contractAddr}`);
    console.log();
  }

  console.log(`  ${COLORS.bright}Mechanisms demonstrated:${COLORS.reset}`);
  console.log(`  ${COLORS.green}✓${COLORS.reset} Risk Detection Decision Traces (10-field schema)`);
  console.log(`  ${COLORS.green}✓${COLORS.reset} Threat Horizon Scoping (THS)`);
  console.log(`  ${COLORS.green}✓${COLORS.reset} Confidence Decay Functions (Exponential)`);
  console.log(`  ${COLORS.green}✓${COLORS.reset} Counter-Evidence Registration`);
  if (isLocal && signers.length >= 4) {
    console.log(`  ${COLORS.green}✓${COLORS.reset} Cross-Agent Corroboration Weighting (CACW)`);
    console.log(`  ${COLORS.green}✓${COLORS.reset} Reasoning Duel (challenge → vote → resolution)`);
    console.log(`  ${COLORS.green}✓${COLORS.reset} Inverse Reasoning Bond (submit → defend → resolve)`);
  } else {
    console.log(`  ${COLORS.yellow}○${COLORS.reset} Cross-Agent Corroboration (requires multi-wallet)`);
    console.log(`  ${COLORS.yellow}○${COLORS.reset} Reasoning Duel (requires multi-wallet)`);
    console.log(`  ${COLORS.green}✓${COLORS.reset} Inverse Reasoning Bond (submitted, defense pending)`);
  }
  console.log(`  ${COLORS.green}✓${COLORS.reset} Reputation & Cognitive Scoring`);
  console.log();

  console.log(`${COLORS.cyan}  Sigil doesn't just verify risk detection —${COLORS.reset}`);
  console.log(`${COLORS.cyan}  it pressurizes the truth surface of entire systems.${COLORS.reset}`);
  console.log();
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
