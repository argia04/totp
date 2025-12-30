import React, { useState } from "react";
import axios from "axios";

const API = "";

export default function App() {
  const [mode, setMode] = useState("register"); // register | login | totp | success
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [qrCode, setQrCode] = useState("");
  const [manualSecret, setManualSecret] = useState("");

  const [tempToken, setTempToken] = useState("");
  const [totpCode, setTotpCode] = useState("");

  const [jwtToken, setJwtToken] = useState("");
  const [me, setMe] = useState(null);

  const [msg, setMsg] = useState("");

  async function register() {
    try {
      setMsg("");
      const r = await axios.post(`${API}/api/register`, { username, password });
      setQrCode(r.data.qrCode);
      setManualSecret(r.data.manualSecret);
      setMode("register");
      setMsg("Registrasi berhasil. Scan QR di Authenticator.");
    } catch (e) {
      setMsg(e.response?.data?.error || e.message);
    }
  }

  async function login() {
    try {
      setMsg("");
      const r = await axios.post(`${API}/api/login`, { username, password });
      setTempToken(r.data.tempToken);
      setMode("totp");
      setMsg(r.data.message || "Masukkan TOTP.");
    } catch (e) {
      setMsg(e.response?.data?.error || e.message);
    }
  }

  async function verifyTotp() {
    try {
      setMsg("");
      const r = await axios.post(`${API}/api/verify-totp`, {
        tempToken,
        totpCode,
      });
      setJwtToken(r.data.token);
      setMode("success");
      setMsg("Login sukses ✅");
    } catch (e) {
      setMsg(e.response?.data?.error || e.message);
    }
  }

  async function fetchMe() {
    try {
      setMsg("");
      const r = await axios.get(`${API}/api/me`, {
        headers: { Authorization: `Bearer ${jwtToken}` },
      });
      setMe(r.data);
    } catch (e) {
      setMsg(e.response?.data?.error || e.message);
    }
  }

  return (
    <div style={{ maxWidth: 520, margin: "40px auto", fontFamily: "Arial" }}>
      <h2>Simple Auth (Password + TOTP)</h2>

      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <button onClick={() => setMode("register")}>Register</button>
        <button onClick={() => setMode("login")}>Login</button>
      </div>

      {msg && <div style={{ marginBottom: 12 }}>{msg}</div>}

      {(mode === "register" || mode === "login") && (
        <>
          <div style={{ display: "grid", gap: 8 }}>
            <input
              placeholder="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              placeholder="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
            {mode === "register" ? (
              <button onClick={register}>Daftar</button>
            ) : (
              <button onClick={login}>Login (Step 1)</button>
            )}
          </div>

          {mode === "register" && qrCode && (
            <div style={{ marginTop: 18 }}>
              <h4>Scan QR (Google/Microsoft Authenticator)</h4>
              <img src={qrCode} alt="qr" style={{ width: 220 }} />
              <p style={{ wordBreak: "break-all" }}>
                Manual secret (Base32): <b>{manualSecret}</b>
              </p>
            </div>
          )}
        </>
      )}

      {mode === "totp" && (
        <>
          <h4>Login Step 2: Masukkan kode TOTP</h4>
          <input
            placeholder="6 digit TOTP"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
          />
          <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
            <button onClick={verifyTotp}>Verifikasi TOTP</button>
            <button onClick={() => setMode("login")}>Kembali</button>
          </div>
        </>
      )}

      {mode === "success" && (
        <>
          <h4>Berhasil Login</h4>
          <p style={{ wordBreak: "break-all" }}>
            JWT: <code>{jwtToken}</code>
          </p>
          <button onClick={fetchMe}>GET /api/me</button>
          {me && (
            <pre
              style={{
                background: "#111",
                color: "#0f0",
                padding: 12,
                marginTop: 12,
              }}
            >
              {JSON.stringify(me, null, 2)}
            </pre>
          )}
        </>
      )}
    </div>
  );
}
