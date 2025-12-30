require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
const path = require("path");

app.use(express.json());

// demo storage (RAM)
const users = {};
const tempSessions = {};
const TEMP_TTL_MS = 2 * 60 * 1000;

function cleanupTempSessions() {
  const now = Date.now();
  for (const k of Object.keys(tempSessions)) {
    if (now - tempSessions[k].createdAt > TEMP_TTL_MS) delete tempSessions[k];
  }
}

function makeTempToken() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2);
}

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res
        .status(400)
        .json({ success: false, error: "username & password wajib diisi" });
    }
    if (users[username]) {
      return res
        .status(400)
        .json({ success: false, error: "username sudah terdaftar" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const secret = speakeasy.generateSecret({
      name: `SimpleTOTP (${username})`,
      length: 20,
    });

    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

    users[username] = {
      passwordHash,
      totpSecretBase32: secret.base32,
    };

    return res.json({ success: true, qrCode, manualSecret: secret.base32 });
  } catch (e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

// LOGIN step 1 (password)
app.post("/api/login", async (req, res) => {
  try {
    cleanupTempSessions();
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res
        .status(400)
        .json({ success: false, error: "username & password wajib diisi" });
    }

    const user = users[username];
    if (!user)
      return res.status(401).json({ success: false, error: "login gagal" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok)
      return res.status(401).json({ success: false, error: "login gagal" });

    const tempToken = makeTempToken();
    tempSessions[tempToken] = { username, createdAt: Date.now() };

    return res.json({
      success: true,
      tempToken,
      message: "Password valid. Masukkan kode TOTP.",
    });
  } catch (e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

// LOGIN step 2 (TOTP)
app.post("/api/verify-totp", (req, res) => {
  try {
    cleanupTempSessions();
    const { tempToken, totpCode } = req.body || {};
    if (!tempToken || !totpCode) {
      return res
        .status(400)
        .json({ success: false, error: "tempToken & totpCode wajib diisi" });
    }

    const session = tempSessions[tempToken];
    if (!session)
      return res
        .status(401)
        .json({ success: false, error: "session login tidak valid/expired" });

    const user = users[session.username];
    if (!user)
      return res
        .status(401)
        .json({ success: false, error: "user tidak ditemukan" });

    const totpValid = speakeasy.totp.verify({
      secret: user.totpSecretBase32,
      encoding: "base32",
      token: String(totpCode),
      window: 1,
    });

    if (!totpValid)
      return res
        .status(401)
        .json({ success: false, error: "kode TOTP salah/expired" });

    delete tempSessions[tempToken];

    const token = jwt.sign(
      { username: session.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    return res.json({ success: true, token });
  } catch (e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

// protected demo endpoint
app.get("/api/me", (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!token) return res.status(401).json({ error: "no token" });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    return res.json({ username: payload.username });
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
});

const path = require("path");

// Serve React build (production)
app.use(express.static(path.join(__dirname, "../frontend/build")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/build", "index.html"));
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});
