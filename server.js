const tls = require("tls");
const express = require("express");

const app = express();

app.get("/", (_req, res) => res.status(200).send("ok"));

// 証明書のフィールドは値が複数あると配列になるので文字列にそろえる
function pick(v) {
  if (Array.isArray(v)) return v.join(", ");
  return v || null;
}

app.get("/check", (req, res) => {
  const domain = String(req.query.domain || "").trim();
  const port = parseInt(String(req.query.port || "443"), 10);

  if (!domain) return res.status(400).json({ success: false, error: "domain required" });
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    return res.status(400).json({ success: false, error: "invalid port" });
  }

  // 응답은 한 번만 (timeout / error / 성공이 겹쳐도 서버가 안 죽게)
  let done = false;
  const reply = (status, body) => {
    if (done || res.headersSent) return;
    done = true;
    socket.destroy();
    res.status(status).json(body);
  };

  const socket = tls.connect(
    { host: domain, port, servername: domain, minVersion: "TLSv1.2", rejectUnauthorized: false },
    () => {
      try {
        const cert = socket.getPeerCertificate();

        if (!cert || !cert.valid_to) {
          return reply(502, { success: false, error: "no peer certificate" });
        }

        const validTo = cert.valid_to;
        const validFrom = cert.valid_from;
        const remainDays = Math.floor((new Date(validTo).getTime() - Date.now()) / 86400000);
        const issuer = cert.issuer || {};

        return reply(200, {
          success: true,
          domain,
          port,
          valid_to: validTo,
          valid_from: validFrom,
          remain_days: remainDays,
          issuer_cn: pick(issuer.CN), // ★追加: 発行元の一般名
          issuer_o: pick(issuer.O)    // ★追加: 発行元の組織
        });
      } catch (e) {
        return reply(500, { success: false, error: String(e?.message || e) });
      }
    }
  );

  socket.setTimeout(8000, () => reply(504, { success: false, error: "timeout" }));
  socket.on("error", (err) => reply(502, { success: false, error: err.message }));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on ${PORT}`));
