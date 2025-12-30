// ╔════════════════════════════════════════════════════════════════════════════╗
// ║     SCRIPT PENGUJIAN KEAMANAN - REPLAY ATTACK (SISTEM KONVENSIONAL)       ║
// ║                     Password + TOTP (2FA)                                 ║
// ╠════════════════════════════════════════════════════════════════════════════╣
// ║  Referensi Standar:                                                       ║
// ║  - OWASP Testing Guide v4.2 (Web Security Testing)                         ║
// ║  - NIST SP 800-63B (Replay Resistance)                                     ║
// ║  - RFC 6238 (TOTP)                                                        ║
// ╠════════════════════════════════════════════════════════════════════════════╣
// ║  Tujuan Script:                                                           ║
// ║  Menguji apakah sistem konvensional (password + TOTP) mampu               ║
// ║  mencegah replay attack pada tahap verifikasi TOTP dan sesi login.        ║
// ╚════════════════════════════════════════════════════════════════════════════╝

const axios = require("axios");
const speakeasy = require("speakeasy");
const readline = require("readline");
const fs = require("fs");

// ============================================================================
// KONFIGURASI
// ============================================================================

// Contoh local: "http://localhost:3001/api"
const API_URL = "http://localhost:3001/api";

// Jumlah iterasi per skenario
const ITERATIONS = 100;

// Delay kecil untuk simulasi replay setelah sniffing (ms)
const REPLAY_DELAY_MS = 100;

// ============================================================================
// STRUKTUR HASIL
// ============================================================================

const testResults = {
  replayVerifySameTempToken: { blocked: 0, passed: 0, errors: 0 }, // Skenario 1
  replayVerifySamePacketDelay: { blocked: 0, passed: 0, errors: 0 }, // Skenario 2
  replayTOTPSameWindowNewTempToken: { blocked: 0, passed: 0, errors: 0 }, // Skenario 3
  replayTOTPExpired: { blocked: 0, passed: 0, errors: 0 }, // Skenario 4
};

function resetTestResults() {
  for (const k of Object.keys(testResults)) {
    testResults[k] = { blocked: 0, passed: 0, errors: 0 };
  }
}

// ============================================================================
// HELPER
// ============================================================================

function showProgress(current, total, scenarioName) {
  const percent = Math.floor((current / total) * 100);
  const filled = Math.floor(percent / 5);
  const bar = "█".repeat(filled) + "░".repeat(20 - filled);
  process.stdout.write(
    `\r  [${bar}] ${percent}% - ${scenarioName} (${current}/${total})`
  );
}

async function setupTestUser(suffix = "") {
  const username = `test_user_${Date.now()}${suffix}`;
  const password = "SecurePassword123!";

  // register → ambil secret TOTP (base32)
  const r = await axios.post(`${API_URL}/register`, { username, password });

  // Sesuaikan field secret dari server:
  // - jika server kamu pakai { manualSecret }, pakai ini
  const totpSecret = r.data.manualSecret;

  if (!totpSecret) {
    throw new Error(
      "Register tidak mengembalikan manualSecret. Pastikan endpoint /register mengembalikan secret base32."
    );
  }

  return { username, password, totpSecret };
}

/**
 * loginStep1() → dapat tempToken (session sementara untuk tahap TOTP)
 */
async function loginStep1({ username, password }) {
  const r = await axios.post(`${API_URL}/login`, { username, password });
  const tempToken = r.data.tempToken;
  if (!tempToken)
    throw new Error("Login step 1 tidak mengembalikan tempToken.");
  return tempToken;
}

/**
 * verifyTotp() → kirim { tempToken, totpCode }
 */
async function verifyTotp({ tempToken, totpCode }) {
  return axios.post(`${API_URL}/verify-totp`, { tempToken, totpCode });
}

/**
 * captureVerifyPacket() mensimulasikan attacker sniffing paket valid pada tahap /verify-totp
 * Return: { packet, originalResult }
 */
async function captureVerifyPacket(userData) {
  const tempToken = await loginStep1(userData);
  const totpCode = speakeasy.totp({
    secret: userData.totpSecret,
    encoding: "base32",
  });

  const packet = { tempToken, totpCode };
  const original = await verifyTotp(packet);
  return { packet, originalResult: original.data };
}

// ============================================================================
// SKENARIO
// ============================================================================

/**
 * SKENARIO 1: Replay paket /verify-totp yang sama (tempToken sama)
 * Expected (aman): BLOCKED, karena tempToken harus invalid setelah sukses.
 */
async function testReplayVerifySameTempToken(userData, iteration) {
  try {
    const { packet } = await captureVerifyPacket(userData);

    // replay paket yang sama
    const replayRes = await verifyTotp(packet);

    if (replayRes.data?.success) {
      testResults.replayVerifySameTempToken.passed++;
      return {
        iteration,
        status: "PASSED",
        detail: "Replay verify accepted (tempToken reused)",
      };
    } else {
      testResults.replayVerifySameTempToken.blocked++;
      return {
        iteration,
        status: "BLOCKED",
        detail: replayRes.data?.error || "Replay rejected",
      };
    }
  } catch (err) {
    if (err.response) {
      testResults.replayVerifySameTempToken.blocked++;
      return {
        iteration,
        status: "BLOCKED",
        detail: err.response.data?.error || "Rejected",
      };
    }
    testResults.replayVerifySameTempToken.errors++;
    return { iteration, status: "ERROR", detail: err.message };
  }
}

/**
 * SKENARIO 2: Replay paket /verify-totp yang sama + delay singkat
 * Expected (aman): tetap BLOCKED.
 */
async function testReplayVerifySamePacketDelay(userData, iteration) {
  try {
    const { packet } = await captureVerifyPacket(userData);

    await new Promise((r) => setTimeout(r, REPLAY_DELAY_MS));
    const replayRes = await verifyTotp(packet);

    if (replayRes.data?.success) {
      testResults.replayVerifySamePacketDelay.passed++;
      return {
        iteration,
        status: "PASSED",
        detail: "Replay accepted after delay",
      };
    } else {
      testResults.replayVerifySamePacketDelay.blocked++;
      return {
        iteration,
        status: "BLOCKED",
        detail: replayRes.data?.error || "Replay rejected",
      };
    }
  } catch (err) {
    if (err.response) {
      testResults.replayVerifySamePacketDelay.blocked++;
      return {
        iteration,
        status: "BLOCKED",
        detail: err.response.data?.error || "Rejected",
      };
    }
    testResults.replayVerifySamePacketDelay.errors++;
    return { iteration, status: "ERROR", detail: err.message };
  }
}

/**
 * SKENARIO 3: Replay TOTP yang sama dalam window yang sama, tapi dengan tempToken BARU
 *
 * Alur:
 *  - login1 -> tempToken1
 *  - pakai totpCode X -> verify sukses
 *  - login2 -> tempToken2 (baru)
 *  - kirim lagi totpCode X -> apakah diterima?
 *
 * Catatan:
 *  - Banyak sistem konvensional HANYA memvalidasi window waktu (RFC 6238),
 *    tanpa "nonce tracking". Jika begitu, skenario ini bisa PASSED (rentan replay).
 */
async function testReplayTOTPSameWindowNewTempToken(userData, iteration) {
  try {
    // buat 1 kode TOTP yang akan di-reuse
    const capturedTOTP = speakeasy.totp({
      secret: userData.totpSecret,
      encoding: "base32",
    });

    // login & verify pertama
    const tempToken1 = await loginStep1(userData);
    const first = await verifyTotp({
      tempToken: tempToken1,
      totpCode: capturedTOTP,
    });

    if (!first.data?.success) {
      testResults.replayTOTPSameWindowNewTempToken.errors++;
      return {
        iteration,
        status: "ERROR",
        detail: first.data?.error || "First verify failed",
      };
    }

    // login lagi untuk dapat tempToken baru (masih dalam window yang sama)
    const tempToken2 = await loginStep1(userData);

    // replay totp yang sama dengan tempToken baru
    const replay = await verifyTotp({
      tempToken: tempToken2,
      totpCode: capturedTOTP,
    });

    if (replay.data?.success) {
      testResults.replayTOTPSameWindowNewTempToken.passed++;
      return {
        iteration,
        status: "PASSED",
        detail: "Same TOTP reused with new tempToken",
      };
    } else {
      testResults.replayTOTPSameWindowNewTempToken.blocked++;
      return {
        iteration,
        status: "BLOCKED",
        detail: replay.data?.error || "TOTP reuse rejected",
      };
    }
  } catch (err) {
    if (err.response) {
      testResults.replayTOTPSameWindowNewTempToken.blocked++;
      return {
        iteration,
        status: "BLOCKED",
        detail: err.response.data?.error || "Rejected",
      };
    }
    testResults.replayTOTPSameWindowNewTempToken.errors++;
    return { iteration, status: "ERROR", detail: err.message };
  }
}

/**
 * SKENARIO 4: TOTP expired (> 90 detik), pakai tempToken fresh
 * Expected: BLOCKED.
 */
async function testReplayTOTPExpired(userData, iteration) {
  try {
    const tempToken = await loginStep1(userData);

    const pastTime = Math.floor((Date.now() - 120000) / 1000); // 2 menit lalu
    const expiredTOTP = speakeasy.totp({
      secret: userData.totpSecret,
      encoding: "base32",
      time: pastTime,
    });

    const res = await verifyTotp({ tempToken, totpCode: expiredTOTP });

    if (res.data?.success) {
      testResults.replayTOTPExpired.passed++;
      return { iteration, status: "PASSED", detail: "Expired TOTP accepted" };
    } else {
      testResults.replayTOTPExpired.blocked++;
      return {
        iteration,
        status: "BLOCKED",
        detail: res.data?.error || "Expired rejected",
      };
    }
  } catch (err) {
    if (err.response) {
      testResults.replayTOTPExpired.blocked++;
      return {
        iteration,
        status: "BLOCKED",
        detail: err.response.data?.error || "Rejected",
      };
    }
    testResults.replayTOTPExpired.errors++;
    return { iteration, status: "ERROR", detail: err.message };
  }
}

// ============================================================================
// RUNNERS
// ============================================================================

async function runScenario(name, suffixPrefix, fn, resultKey) {
  console.log(
    "\n┌─────────────────────────────────────────────────────────────────┐"
  );
  console.log(`│ Skenario: ${name.padEnd(55)}│`);
  console.log(
    "│ Pelaku: Adversary Client                                        │"
  );
  console.log(
    "│ Iterasi: 100x                                                   │"
  );
  console.log(
    "└─────────────────────────────────────────────────────────────────┘\n"
  );

  for (let i = 1; i <= ITERATIONS; i++) {
    const userData = await setupTestUser(`_${suffixPrefix}_${i}`);
    await fn(userData, i);
    showProgress(i, ITERATIONS, name);
  }
  console.log("\n");

  const blocked = testResults[resultKey].blocked;
  const passed = testResults[resultKey].passed;
  const errors = testResults[resultKey].errors;
  const rate = ((blocked / ITERATIONS) * 100).toFixed(0);

  console.log(`  Hasil: ${rate}% ditolak (${blocked}/${ITERATIONS})`);
  console.log(`  Passed: ${passed}, Errors: ${errors}`);
}

function printResults(scenariosRun) {
  console.log("\n" + "═".repeat(66));
  console.log("              HASIL PENGUJIAN REPLAY ATTACK (KONVENSIONAL)");
  console.log("═".repeat(66) + "\n");

  let totalTests = 0;
  let totalBlocked = 0;
  let totalPassed = 0;
  let totalErrors = 0;

  const rows = [];

  function addRow(title, key) {
    const blocked = testResults[key].blocked;
    const passed = testResults[key].passed;
    const errors = testResults[key].errors;
    const rate = ((blocked / ITERATIONS) * 100).toFixed(0);

    rows.push({ title, blockedRate: `${rate}%`, blocked, passed, errors });
    totalTests += ITERATIONS;
    totalBlocked += blocked;
    totalPassed += passed;
    totalErrors += errors;
  }

  for (const s of scenariosRun) {
    if (s === 1)
      addRow(
        "Replay /verify-totp (tempToken sama)",
        "replayVerifySameTempToken"
      );
    if (s === 2)
      addRow("Replay /verify-totp + delay", "replayVerifySamePacketDelay");
    if (s === 3)
      addRow(
        "Reuse TOTP window sama (tempToken baru)",
        "replayTOTPSameWindowNewTempToken"
      );
    if (s === 4) addRow("TOTP expired (>90 detik)", "replayTOTPExpired");
  }

  console.log(
    "┌──────────────────────────────────────────────┬────────┬────────┬────────┬────────┐"
  );
  console.log(
    "│ Skenario                                      │Blocked │Passed  │Errors  │Rate    │"
  );
  console.log(
    "├──────────────────────────────────────────────┼────────┼────────┼────────┼────────┤"
  );
  for (const r of rows) {
    console.log(
      `│ ${r.title.padEnd(44)} │ ${String(r.blocked).padStart(6)} │ ${String(
        r.passed
      ).padStart(6)} │ ${String(r.errors).padStart(
        6
      )} │ ${r.blockedRate.padStart(6)} │`
    );
  }
  console.log(
    "└──────────────────────────────────────────────┴────────┴────────┴────────┴────────┘"
  );

  const successRate = totalTests
    ? ((totalBlocked / totalTests) * 100).toFixed(2)
    : "0.00";

  console.log("\n" + "─".repeat(66));
  console.log("RINGKASAN");
  console.log("─".repeat(66));
  console.log(`Total Pengujian   : ${totalTests}`);
  console.log(`Ditolak (Blocked) : ${totalBlocked} (${successRate}%)`);
  console.log(`Berhasil (Passed) : ${totalPassed}`);
  console.log(`Error             : ${totalErrors}`);

  const outputPath = "./replay-attack-results-conventional.json";
  fs.writeFileSync(
    outputPath,
    JSON.stringify(
      {
        testDate: new Date().toISOString(),
        apiUrl: API_URL,
        iterations: ITERATIONS,
        scenariosRun,
        results: testResults,
        summary: {
          totalTests,
          totalBlocked,
          totalPassed,
          totalErrors,
          successRate: Number(successRate),
        },
      },
      null,
      2
    )
  );
  console.log(`\nHasil disimpan ke: ${outputPath}\n`);
}

// ============================================================================
// MENU
// ============================================================================

function showMenu() {
  console.log(
    "\n╔═════════════════════════════════════════════════════════════════╗"
  );
  console.log(
    "║     PENGUJIAN REPLAY ATTACK - SISTEM KONVENSIONAL (PASS+TOTP)   ║"
  );
  console.log(
    "║     100 Iterasi per Skenario                                    ║"
  );
  console.log(
    "╚═════════════════════════════════════════════════════════════════╝\n"
  );

  console.log(`Target API: ${API_URL}`);
  console.log("Pastikan server konvensional berjalan.\n");

  console.log("  PILIH SKENARIO:\n");
  console.log(
    "  [1] Replay /verify-totp (tempToken sama)        (Expected: ditolak)"
  );
  console.log(
    "  [2] Replay /verify-totp + delay                 (Expected: ditolak)"
  );
  console.log(
    "  [3] Reuse TOTP dalam window sama (tempToken baru) (Bisa rentan)"
  );
  console.log(
    "  [4] TOTP expired (>90 detik)                    (Expected: ditolak)"
  );
  console.log("  [5] Jalankan SEMUA");
  console.log("  [0] Keluar\n");
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  const question = (p) => new Promise((resolve) => rl.question(p, resolve));

  let running = true;

  while (running) {
    showMenu();
    const choice = (await question("Masukkan pilihan (0-5): ")).trim();
    const scenariosRun = [];
    resetTestResults();

    try {
      if (choice === "1") {
        await runScenario(
          "Replay verify (tempToken sama)",
          "s1",
          testReplayVerifySameTempToken,
          "replayVerifySameTempToken"
        );
        scenariosRun.push(1);
        printResults(scenariosRun);
      } else if (choice === "2") {
        await runScenario(
          "Replay verify + delay",
          "s2",
          testReplayVerifySamePacketDelay,
          "replayVerifySamePacketDelay"
        );
        scenariosRun.push(2);
        printResults(scenariosRun);
      } else if (choice === "3") {
        await runScenario(
          "Reuse TOTP window sama (tempToken baru)",
          "s3",
          testReplayTOTPSameWindowNewTempToken,
          "replayTOTPSameWindowNewTempToken"
        );
        scenariosRun.push(3);
        printResults(scenariosRun);
      } else if (choice === "4") {
        await runScenario(
          "TOTP expired",
          "s4",
          testReplayTOTPExpired,
          "replayTOTPExpired"
        );
        scenariosRun.push(4);
        printResults(scenariosRun);
      } else if (choice === "5") {
        console.log("\n▶ MENJALANKAN SEMUA SKENARIO...\n");
        await runScenario(
          "Replay verify (tempToken sama)",
          "s1",
          testReplayVerifySameTempToken,
          "replayVerifySameTempToken"
        );
        scenariosRun.push(1);

        await runScenario(
          "Replay verify + delay",
          "s2",
          testReplayVerifySamePacketDelay,
          "replayVerifySamePacketDelay"
        );
        scenariosRun.push(2);

        await runScenario(
          "Reuse TOTP window sama (tempToken baru)",
          "s3",
          testReplayTOTPSameWindowNewTempToken,
          "replayTOTPSameWindowNewTempToken"
        );
        scenariosRun.push(3);

        await runScenario(
          "TOTP expired",
          "s4",
          testReplayTOTPExpired,
          "replayTOTPExpired"
        );
        scenariosRun.push(4);

        printResults(scenariosRun);
      } else if (choice === "0") {
        console.log("\nKeluar.\n");
        running = false;
      } else {
        console.log("\n⚠ Pilihan tidak valid.\n");
      }
    } catch (e) {
      console.log("\n⚠ Gagal menjalankan skenario:", e.message, "\n");
    }

    if (running && choice !== "0") {
      await question("Tekan ENTER untuk kembali ke menu...");
    }
  }

  rl.close();
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = { main };
