const db = require('../sql/db_connector');

function userManager(req, res, next) {
    const token = req.cookies?.SessionToken;

    if (!token) {
        res.locals.user = { level: 'Guest' };
        return next();
    }

    db.query(
        "SELECT * FROM userSessions WHERE sessionToken = ?",
        [token],
        (err, sessions) => {
            if (err) {
                console.error("DB error in middleware:", err);
                return res.status(500).send("Server error");
            }

            if (sessions.length === 0) {
                res.locals.user = { level: 'Guest' };
                return next();
            }

            db.query(
                "SELECT * FROM users WHERE id = ?",
                [sessions[0].userId],
                (err, users) => {
                    if (err) {
                        console.error("DB error in middleware:", err);
                        return res.status(500).send("Server error");
                    }

                    res.locals.user = users[0] || { level: 'Guest' };
                    return next();
                }
            );
        }
    );
}

module.exports = userManager;