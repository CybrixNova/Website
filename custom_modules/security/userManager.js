const db = require('../sql/db_connector');

function userManager(req, res, next) {
    const token = req.cookies?.SessionToken;

    if (!token) {
        res.locals.user = { level: 'Guest' }; // ensure always defined
        res.locals.user.level = 'Guest'; // default to Guest level
        return next();
    }

    db.query("SELECT * FROM users WHERE sessionToken = ?", [token], (err, result) => {
        if (err) {
            console.error("DB error in middleware:", err);
            return res.status(500).send("Server error");
        }

        if (result.length === 0) {
            res.locals.user = null;
            return next();
        }

        // ✅ Now available in templates
        res.locals.user = result[0];
        next();
    });
}

module.exports = userManager;
