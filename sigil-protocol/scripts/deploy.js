const hre = require("hardhat");

async function main() {
  console.log("═══════════════════════════════════════════════════");
  console.log("  SIGIL-RD: Deploying Sigil Protocol");
  console.log("  Adversarial Verification of Risk Detection");
  console.log("═══════════════════════════════════════════════════\n");

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deployer:", deployer.address);
  console.log("Balance:", hre.ethers.formatEther(
    await hre.ethers.provider.getBalance(deployer.address)
  ), "ETH\n");

  // Deploy
  const SigilProtocol = await hre.ethers.getContractFactory("SigilProtocol");
  const sigil = await SigilProtocol.deploy();
  await sigil.waitForDeployment();

  const address = await sigil.getAddress();
  console.log("SigilProtocol deployed to:", address);
  console.log("Protocol name:", await sigil.PROTOCOL_NAME());
  console.log("Protocol version:", (await sigil.protocolVersion()).toString());

  // Register deployer as first agent
  const tx = await sigil.registerAgent("Fred & Claude");
  await tx.wait();
  console.log("\nRegistered deployer as agent: Fred & Claude");

  // Verify configuration
  console.log("\n── Configuration ──");
  console.log("Min trace bond:", hre.ethers.formatEther(await sigil.minTraceBond()), "ETH");
  console.log("Min challenge bond:", hre.ethers.formatEther(await sigil.minChallengeBond()), "ETH");
  console.log("Min inverse bond:", hre.ethers.formatEther(await sigil.minInverseBond()), "ETH");
  console.log("Voting period:", (await sigil.votingPeriod()).toString(), "seconds");
  console.log("Default defense window:", (await sigil.defaultDefenseWindow()).toString(), "seconds");
  console.log("Decay lambda:", (await sigil.decayLambda()).toString(), "bps");

  console.log("\n═══════════════════════════════════════════════════");
  console.log("  Deployment complete. Ready for adversarial");
  console.log("  verification of risk detection.");
  console.log("═══════════════════════════════════════════════════");

  // Demo: Submit a sample trace
  if (process.env.DEMO === "true") {
    console.log("\n── Demo: Submitting sample risk trace ──");
    const horizon = Math.floor(Date.now() / 1000) + 7 * 86400;
    const evidenceHash = hre.ethers.keccak256(
      hre.ethers.toUtf8Bytes("demo_malware_sample_sha256")
    );

    const traceTx = await sigil.submitRiskTrace(
      0, // Malware
      evidenceHash,
      "YARA rule match + sandbox detonation",
      "Execution (T1059.001)",
      "Benign packed executable ruled out: entropy 7.98, invalid certificate chain",
      8500, // 85% confidence
      0, // Exponential decay
      horizon,
      "Quarantine endpoint, block hash at EDR, submit to threat intel feed",
      3 * 86400, // 3-day challenge window
      "demo_reasoning_hash",
      { value: hre.ethers.parseEther("0.01") }
    );
    await traceTx.wait();
    console.log("Sample trace submitted. Trace ID: 1");
    console.log("Bond: 0.01 ETH | Confidence: 85% | Decay: Exponential");
    console.log("Threat horizon:", new Date(horizon * 1000).toISOString());
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
