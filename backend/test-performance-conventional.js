// ╔════════════════════════════════════════════════════════════════════════════╗
// ║        SCRIPT PENGUJIAN PERFORMA - SISTEM KONVENSIONAL (PASS+TOTP)        ║
// ║                     100 Iterasi per Operasi                               ║
// ╠════════════════════════════════════════════════════════════════════════════╣
// ║  Tujuan Script:                                                            ║
// ║  Mengukur waktu respons (response time) setiap operasi dalam sistem        ║
// ║  autentikasi konvensional (Password + TOTP) untuk analisis Bab 4 skripsi.  ║
// ║                                                                            ║
// ║  Output yang Dihasilkan:                                                   ║
// ║  - Tabel: Hasil Pengukuran Waktu Respons (n=100)                           ║
// ║  - Tabel: Hasil Pengujian Konkurensi (100 users)                           ║
// ║  - Tabel: Distribusi Overhead Komputasi (estimasi)                         ║
// ║                                                                            ║
// ║  Metrik yang Diukur: Mean, Min, Max, Median, P95                           ║
// ╚════════════════════════════════════════════════════════════════════════════╝

// ============================================================================
// BAGIAN 1: IMPORT DEPENDENCIES
// ============================================================================

const axios = require("axios");
const speakeasy = require("speakeasy");
const fs = require("fs");
const { performance } = require("perf_hooks");

// ============================================================================
// BAGIAN 2: KONFIGURASI
// ============================================================================

// Untuk local testing: "http://localhost:3001/api"
const API_URL = "http://localhost:3001/api";

const ITERATIONS = 100;
const CONCURRENT_USERS = 100;

// ============================================================================
// BAGIAN 3: FUNGSI STATISTIK
// ============================================================================

function stats(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const sum = arr.reduce((a, b) => a + b, 0);

  return {
    mean: (sum / arr.length).toFixed(2),
    min: Math.min(...arr).toFixed(2),
    max: Math.max(...arr).toFixed(2),
    median: sorted[Math.floor(sorted.length / 2)].toFixed(2),
    p95: sorted[Math.floor(sorted.length * 0.95)].toFixed(2),
  };
}

// ============================================================================
// BAGIAN 4: HELPER - SETUP USER
// ============================================================================

/**
 * setupUser(suffix)
 * Register user baru -> dapat secret TOTP (base32)
 *
 * Endpoint konvensional yang diasumsikan:
 * POST /api/register { username, password } -> { success, manualSecret }
 */
async function setupUser(suffix) {
  const username = `conv_${Date.now()}_${suffix}`;
  const password = "TestPass123!";

  const res = await axios.post(`${API_URL}/register`, { username, password });

  const totpSecret = res.data.manualSecret;
  if (!totpSecret) {
    throw new Error(
      "Register tidak mengembalikan manualSecret. Pastikan /register return secret base32."
    );
  }

  return { username, password, totpSecret };
}

/**
 * loginStep1(user) -> tempToken
 * POST /api/login { username, password } -> { success, tempToken }
 */
async function loginStep1(user) {
  const res = await axios.post(`${API_URL}/login`, {
    username: user.username,
    password: user.password,
  });

  const tempToken = res.data.tempToken;
  if (!tempToken) throw new Error("Login tidak mengembalikan tempToken.");
  return tempToken;
}

/**
 * verifyTotp(tempToken, totpCode)
 * POST /api/verify-totp { tempToken, totpCode } -> { success, token }
 */
async function verifyTotp(tempToken, totpCode) {
  return axios.post(`${API_URL}/verify-totp`, { tempToken, totpCode });
}

// ============================================================================
// BAGIAN 5: TEST FUNCTIONS (PERF-01 s/d PERF-06)
// ============================================================================

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ PERF-01: TOTP Generation (Client-side)                                    ║
// ╠═══════════════════════════════════════════════════════════════════════════╣
// ║ MENGUKUR: Waktu generate kode TOTP di sisi client                          ║
// ║ NETWORK: Tidak ada (pure computation)                                     ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
async function testTotpGeneration() {
  console.log("\n[PERF-01] TOTP Generation (client-side)");

  // secret dummy untuk mengukur komputasi speakeasy
  const dummySecret = speakeasy.generateSecret({ length: 20 }).base32;

  const times = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const start = performance.now();

    speakeasy.totp({
      secret: dummySecret,
      encoding: "base32",
    });

    times.push(performance.now() - start);
  }

  const r = stats(times);
  console.log(`  Mean: ${r.mean} ms | Min: ${r.min} ms | Max: ${r.max} ms`);
  return r;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ PERF-02: Registration Total                                               ║
// ╠═══════════════════════════════════════════════════════════════════════════╣
// ║ MENGUKUR: Waktu total request registrasi (round-trip)                     ║
// ║ Endpoint: POST /api/register                                              ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
async function testRegistration() {
  console.log("\n[PERF-02] Registration Total");

  const times = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const username = `reg_${Date.now()}_${i}`;
    const password = "TestPass123!";

    const start = performance.now();
    await axios.post(`${API_URL}/register`, { username, password });
    times.push(performance.now() - start);

    process.stdout.write(`\r  Progress: ${i + 1}/${ITERATIONS}`);
  }

  const r = stats(times);
  console.log(`\n  Mean: ${r.mean} ms | Min: ${r.min} ms | Max: ${r.max} ms`);
  return r;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ PERF-03: Login Step 1 (Password Verification)                             ║
// ╠═══════════════════════════════════════════════════════════════════════════╣
// ║ MENGUKUR: Waktu request login tahap 1 (password)                          ║
// ║ Endpoint: POST /api/login                                                 ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
async function testLoginStep1() {
  console.log("\n[PERF-03] Login Step 1 (password request)");

  // Setup user sekali
  const user = await setupUser("ls1");

  const times = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const start = performance.now();
    await axios.post(`${API_URL}/login`, {
      username: user.username,
      password: user.password,
    });
    times.push(performance.now() - start);

    process.stdout.write(`\r  Progress: ${i + 1}/${ITERATIONS}`);
  }

  const r = stats(times);
  console.log(`\n  Mean: ${r.mean} ms | Min: ${r.min} ms | Max: ${r.max} ms`);
  return r;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ PERF-04: Server Verification (TOTP Verification Request)                  ║
// ╠═══════════════════════════════════════════════════════════════════════════╣
// ║ MENGUKUR: Waktu request verifikasi TOTP (network + server processing)     ║
// ║ Endpoint: POST /api/verify-totp                                           ║
// ║ CATATAN:                                                                  ║
// ║ - Per iterasi: login step1 (ambil tempToken) lalu verify-totp             ║
// ║ - Timer hanya mengukur verify-totp (bukan login step1)                    ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
async function testServerVerification() {
  console.log("\n[PERF-04] Server Verification (TOTP verify request)");

  const user = await setupUser("sv");
  const times = [];

  for (let i = 0; i < ITERATIONS; i++) {
    // login step1 (tidak termasuk waktu yang diukur)
    const tempToken = await loginStep1(user);

    const totpCode = speakeasy.totp({
      secret: user.totpSecret,
      encoding: "base32",
    });

    const start = performance.now();
    await verifyTotp(tempToken, totpCode);
    times.push(performance.now() - start);

    process.stdout.write(`\r  Progress: ${i + 1}/${ITERATIONS}`);
  }

  const r = stats(times);
  console.log(`\n  Mean: ${r.mean} ms | Min: ${r.min} ms | Max: ${r.max} ms`);
  return r;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ PERF-05: Complete Login (End-to-End)                                      ║
// ╠═══════════════════════════════════════════════════════════════════════════╣
// ║ MENGUKUR: Total waktu login dari perspektif user:                          ║
// ║ - POST /api/login (password)                                              ║
// ║ - Generate TOTP (client)                                                  ║
// ║ - POST /api/verify-totp                                                   ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
async function testCompleteLogin() {
  console.log("\n[PERF-05] Complete Login (end-to-end)");

  const user = await setupUser("cl");
  const times = [];

  for (let i = 0; i < ITERATIONS; i++) {
    const start = performance.now();

    const tempToken = await loginStep1(user);

    const totpCode = speakeasy.totp({
      secret: user.totpSecret,
      encoding: "base32",
    });

    await verifyTotp(tempToken, totpCode);

    times.push(performance.now() - start);
    process.stdout.write(`\r  Progress: ${i + 1}/${ITERATIONS}`);
  }

  const r = stats(times);
  console.log(`\n  Mean: ${r.mean} ms | Min: ${r.min} ms | Max: ${r.max} ms`);
  return r;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ PERF-06: Concurrent Login (100 Users Simultaneously)                      ║
// ╠═══════════════════════════════════════════════════════════════════════════╣
// ║ MENGUKUR: Performa sistem saat 100 user login bersamaan                   ║
// ║ - Setup 100 user                                                          ║
// ║ - Semua user melakukan login end-to-end secara paralel                     ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
async function testConcurrent() {
  console.log("\n[PERF-06] Concurrent Login (100 users simultaneously)");
  console.log("  Setting up 100 users...");

  const users = [];
  for (let i = 0; i < CONCURRENT_USERS; i++) {
    users.push(await setupUser(`con_${i}`));
    process.stdout.write(`\r  Setup: ${i + 1}/${CONCURRENT_USERS}`);
  }
  console.log("\n  Running concurrent login...\n");

  const promises = users.map(async (user, index) => {
    const requestStart = performance.now();
    try {
      const tempToken = await loginStep1(user);

      const totpCode = speakeasy.totp({
        secret: user.totpSecret,
        encoding: "base32",
      });

      const res = await verifyTotp(tempToken, totpCode);

      const requestTime = performance.now() - requestStart;
      return {
        user: index + 1,
        success: !!res.data?.success,
        responseTime: requestTime,
      };
    } catch (error) {
      const requestTime = performance.now() - requestStart;
      return {
        user: index + 1,
        success: false,
        responseTime: requestTime,
        error: error.message,
      };
    }
  });

  const results = await Promise.all(promises);

  const responseTimes = results.map((r) => r.responseTime);
  const successCount = results.filter((r) => r.success).length;
  const r = stats(responseTimes);

  console.log("  ─────────────────────────────────────────────────");
  console.log(`  Total Users:         ${CONCURRENT_USERS}`);
  console.log(`  Success Rate:        ${successCount}/${CONCURRENT_USERS}`);
  console.log("  ─────────────────────────────────────────────────");
  console.log(`  Avg Response Time:   ${r.mean} ms`);
  console.log(`  Min Response Time:   ${r.min} ms`);
  console.log(`  Max Response Time:   ${r.max} ms`);
  console.log(`  Median:              ${r.median} ms`);
  console.log(`  95th Percentile:     ${r.p95} ms`);
  console.log("  ─────────────────────────────────────────────────");

  return {
    totalUsers: CONCURRENT_USERS,
    success: successCount,
    failed: CONCURRENT_USERS - successCount,
    responseTime: r,
  };
}

// ============================================================================
// BAGIAN 6: OVERHEAD CALCULATION (ESTIMASI)
// ============================================================================

/**
 * Metodologi estimasi (mirip referensi):
 * - Client-side computation: TOTP generation (pure computation)
 * - Server-side computation (estimasi):
 *   Complete Login - Login Step1
 *   (anggap Login Step1 merepresentasikan "baseline roundtrip + bcrypt check",
 *    sedangkan sisanya dominan verify-totp + processing)
 *
 * Catatan: Ini ESTIMASI, karena network + server compute sulit dipisah tanpa profiling.
 */
function calculateOverhead(results) {
  console.log("\n[OVERHEAD] Distribusi Overhead Komputasi (Estimasi)");

  const clientSide = parseFloat(results.totpGen.mean);

  const completeLoginTotal = parseFloat(results.completeLogin.mean);
  const loginStep1Total = parseFloat(results.loginStep1.mean);

  const verifyPartApprox = Math.max(0, completeLoginTotal - loginStep1Total);

  const total = clientSide + verifyPartApprox;
  const clientPercent =
    total > 0 ? ((clientSide / total) * 100).toFixed(1) : "0.0";
  const serverPercent =
    total > 0 ? ((verifyPartApprox / total) * 100).toFixed(1) : "0.0";

  console.log("  ─────────────────────────────────────────────────");
  console.log(
    `  Client-side (TOTP gen): ${clientSide.toFixed(2)} ms (${clientPercent}%)`
  );
  console.log("  ─────────────────────────────────────────────────");
  console.log(
    `  Server-side (approx):   ${verifyPartApprox.toFixed(
      2
    )} ms (${serverPercent}%)`
  );
  console.log(`    - Estimated from: CompleteLogin - LoginStep1`);
  console.log(`    - CompleteLogin:      ${completeLoginTotal.toFixed(2)} ms`);
  console.log(`    - LoginStep1:         ${loginStep1Total.toFixed(2)} ms`);
  console.log("  ─────────────────────────────────────────────────");
  console.log(`  Total (approx):         ${total.toFixed(2)} ms`);
  console.log("  ─────────────────────────────────────────────────");

  return {
    clientSide: {
      total: clientSide.toFixed(2),
      percent: clientPercent,
      totpGen: results.totpGen.mean,
    },
    serverSide: { total: verifyPartApprox.toFixed(2), percent: serverPercent },
    grandTotal: total.toFixed(2),
  };
}

// ============================================================================
// BAGIAN 7: MAIN FUNCTION
// ============================================================================

async function main() {
  console.log("═".repeat(60));
  console.log("  PERFORMANCE TESTING - CONVENTIONAL (PASSWORD + TOTP)");
  console.log("═".repeat(60));
  console.log(`  Target: ${API_URL}`);
  console.log(`  Iterations per test: ${ITERATIONS}`);
  console.log(`  Concurrent Users: ${CONCURRENT_USERS}`);
  console.log("═".repeat(60));

  const results = {
    totpGen: await testTotpGeneration(), // PERF-01
    registration: await testRegistration(), // PERF-02
    loginStep1: await testLoginStep1(), // PERF-03
    serverVerification: await testServerVerification(), // PERF-04
    completeLogin: await testCompleteLogin(), // PERF-05
    concurrent: await testConcurrent(), // PERF-06
  };

  const overhead = calculateOverhead(results);

  // ========================================================================
  // SUMMARY - Format tabel (mirip referensi)
  // ========================================================================
  console.log("\n" + "═".repeat(60));
  console.log("  SUMMARY");
  console.log("═".repeat(60));

  // TABEL: Waktu Respons (n=100)
  console.log("\n  [Tabel] Hasil Pengukuran Waktu Respons (n=100)");
  console.log("  ─────────────────────────────────────────────────");
  console.log(
    `  | Operasi                 | Mean (ms) | Min    | Max    | Median | P95    |`
  );
  console.log(
    `  |-------------------------|-----------|--------|--------|--------|--------|`
  );
  console.log(
    `  | TOTP Generation         | ${results.totpGen.mean.padStart(
      9
    )} | ${results.totpGen.min.padStart(6)} | ${results.totpGen.max.padStart(
      6
    )} | ${results.totpGen.median.padStart(6)} | ${results.totpGen.p95.padStart(
      6
    )} |`
  );
  console.log(
    `  | Registration Total      | ${results.registration.mean.padStart(
      9
    )} | ${results.registration.min.padStart(
      6
    )} | ${results.registration.max.padStart(
      6
    )} | ${results.registration.median.padStart(
      6
    )} | ${results.registration.p95.padStart(6)} |`
  );
  console.log(
    `  | Login Step 1 (Password) | ${results.loginStep1.mean.padStart(
      9
    )} | ${results.loginStep1.min.padStart(
      6
    )} | ${results.loginStep1.max.padStart(
      6
    )} | ${results.loginStep1.median.padStart(
      6
    )} | ${results.loginStep1.p95.padStart(6)} |`
  );
  console.log(
    `  | Verify TOTP (Server)    | ${results.serverVerification.mean.padStart(
      9
    )} | ${results.serverVerification.min.padStart(
      6
    )} | ${results.serverVerification.max.padStart(
      6
    )} | ${results.serverVerification.median.padStart(
      6
    )} | ${results.serverVerification.p95.padStart(6)} |`
  );
  console.log(
    `  | Complete Login (E2E)    | ${results.completeLogin.mean.padStart(
      9
    )} | ${results.completeLogin.min.padStart(
      6
    )} | ${results.completeLogin.max.padStart(
      6
    )} | ${results.completeLogin.median.padStart(
      6
    )} | ${results.completeLogin.p95.padStart(6)} |`
  );
  console.log("  ─────────────────────────────────────────────────");

  // TABEL: Konkurensi (100 users)
  console.log("\n  [Tabel] Hasil Pengujian Konkurensi (100 users)");
  console.log("  ─────────────────────────────────────────────────");
  console.log(`  | Metrik               | Hasil                    |`);
  console.log(`  |----------------------|--------------------------|`);
  console.log(
    `  | Success Rate         | ${results.concurrent.success}/${results.concurrent.totalUsers}                    |`
  );
  console.log(
    `  | Avg Response Time    | ${results.concurrent.responseTime.mean} ms                 |`
  );
  console.log(
    `  | Min Response Time    | ${results.concurrent.responseTime.min} ms                 |`
  );
  console.log(
    `  | Max Response Time    | ${results.concurrent.responseTime.max} ms                 |`
  );
  console.log(
    `  | Median               | ${results.concurrent.responseTime.median} ms                 |`
  );
  console.log(
    `  | P95                  | ${results.concurrent.responseTime.p95} ms                 |`
  );
  console.log("  ─────────────────────────────────────────────────");

  // TABEL: Overhead (estimasi)
  console.log("\n  [Tabel] Distribusi Overhead Komputasi (Estimasi)");
  console.log("  ─────────────────────────────────────────────────");
  console.log(`  | Komponen             | Waktu (ms) | Persentase |`);
  console.log(`  |----------------------|------------|------------|`);
  console.log(
    `  | Client-side          | ${overhead.clientSide.total.padStart(
      10
    )} | ${overhead.clientSide.percent.padStart(9)}% |`
  );
  console.log(
    `  | Server-side          | ${overhead.serverSide.total.padStart(
      10
    )} | ${overhead.serverSide.percent.padStart(9)}% |`
  );
  console.log(
    `  | Total                | ${overhead.grandTotal.padStart(
      10
    )} |      100%  |`
  );
  console.log("  ─────────────────────────────────────────────────");

  console.log("\n" + "═".repeat(60));

  // SIMPAN HASIL KE JSON
  const outputData = {
    date: new Date().toISOString(),
    config: {
      apiUrl: API_URL,
      iterations: ITERATIONS,
      concurrentUsers: CONCURRENT_USERS,
    },
    results: {
      responseTimeTable: {
        totpGeneration: results.totpGen,
        registration: results.registration,
        loginStep1: results.loginStep1,
        verifyTotp: results.serverVerification,
        completeLogin: results.completeLogin,
      },
      concurrencyTable: {
        successRate: `${results.concurrent.success}/${results.concurrent.totalUsers}`,
        responseTime: results.concurrent.responseTime,
      },
      overheadTable: overhead,
    },
  };

  fs.writeFileSync(
    "performance-results-conventional.json",
    JSON.stringify(outputData, null, 2)
  );

  console.log("\n✓ Results saved to performance-results-conventional.json");
}

// ENTRY POINT
main().catch(console.error);
