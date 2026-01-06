const tls = require("tls");
const express = require("express");

const app = express();

app.get("/", (_req, res) => res.status(200).send("ok"));

app.get("/check", (req, res) => {
  const domain = String(req.query.domain || "").trim();
  const port = parseInt(String(req.query.port || "443"), 10);

  if (!domain) return res.status(400).json({ success: false, error: "domain required" });
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    return res.status(400).json({ success: false, error: "invalid port" });
  }

  const socket = tls.connect(
    { host: domain, port, servername: domain, minVersion: "TLSv1.2", rejectUnauthorized: false },
    () => {
      try {
        const cert = socket.getPeerCertificate();
        socket.destroy();

        if (!cert || !cert.valid_to) {
          return res.status(502).json({ success: false, error: "no peer certificate" });
        }

        const validTo = cert.valid_to;
        const validFrom = cert.valid_from;
        const remainDays = Math.floor((new Date(validTo).getTime() - Date.now()) / 86400000);

        return res.json({
          success: true,
          domain,
          port,
          valid_to: validTo,
          valid_from: validFrom,
          remain_days: remainDays
        });
      } catch (e) {
        socket.destroy();
        return res.status(500).json({ success: false, error: String(e?.message || e) });
      }
    }
  );

  socket.setTimeout(8000, () => {
    socket.destroy();
    return res.status(504).json({ success: false, error: "timeout" });
  });

  socket.on("error", (err) => res.status(502).json({ success: false, error: err.message }));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on ${PORT}`));
