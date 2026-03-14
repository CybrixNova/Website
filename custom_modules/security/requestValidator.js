const db = require('../sql/db_connector');
const { minimatch } = require("minimatch");

function requestValidator(req, res, next) {
    const ip = req.ip;
    const threshold = 3;

    // Allow owners and admins to bypass honeypot checks
    if(res.locals.user.level === 'Owner' || res.locals.user.level === 'Admin'){
        return next();
    }

    const banned_routes = [
        "/wp-admin*",
        "/*.env*",
        "/env.sample",
        "/env.example",
        "/wp-*",
        "/install.php",
        "/installer.php",
        "/config*",
        "*wlwmanifest.xml",
        ".well-known*",
        "*.php"
    ];

    const path = decodeURIComponent(req.path);

    const isHoneypot = banned_routes.some(pattern =>
        minimatch(path, pattern, { nocase: true })
    );

    if (isHoneypot) {
        console.warn(`[HONEYPOT] ${ip} attempted ${path}`);

        db.query(
            `INSERT INTO banned_ips (ip, hits, reason)
             VALUES (?, 1, ?)
             ON DUPLICATE KEY UPDATE hits = hits + 1`,
            [ip, "Security system flagged this IP as malicious"]
        );

        res.locals.banReason = "Suspicious activity detected";
        return res.status(404).render("./error/backdoor");
    }

    db.query("SELECT * FROM banned_ips WHERE ip = ?", [ip], (err, result) => {
        if (err) {
            console.error("DB error:", err);
            return res.status(500).send("Server error");
        }

        const record = result[0];

        if (record && record.hits >= threshold) {
            res.locals.banReason = record.reason;
            return res.status(404).render("./error/backdoor");
        }

        next();
    });
}

module.exports = requestValidator;