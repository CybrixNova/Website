const express =  require('express');
const axios = require('axios');

const admin = express.Router()


const db = require('../custom_modules/sql/db_connector')



// === Middleware: check admin ===
function requireAdmin(req, res, next) {
  const user = res.locals.user;

  if (!user) {
    res.redirect('/users/login')
  }

  if (user.level == 'admin' || user.level == 'Owner') {
  next();

  }else{
    res.redirect('/');
  }

}


admin.use(requireAdmin)

admin.get('/', (req, res)=>{
    res.render('admin/admin')
});

admin.get('/PageBuilder', (req, res)=>{
            db.query("SELECT * FROM pages", (err, result) => {
        if (err) {
            console.error("DB error in middleware:", err);
            return res.status(500).send("Server error");
        }



        res.locals.pages = result

        res.render('admin/pageBuilder');


    })
})


admin.get('/pagebuilder/edit/:id', (req, res)=>{
    
                db.query("SELECT * FROM pages WHERE ID=?", [req.params.id], (err, result) => {
        if (err) {
            console.error("DB error in middleware:", err);
            return res.status(500).send("Server error");
        }

        if(result.length === 0){
            res.render('error/404');
        }else{
        res.locals.page = result[0]

        res.render('admin/pageBuilderEditor');
        }

        res.locals.pages = result



    })
})

admin.post('/pagebuilder/edit/:id', (req, res)=>{
                db.query("UPDATE pages SET title=?, url=?, content=? WHERE ID = ?", [req.body.title, req.body.url, req.body.content, req.params.id], function (err2) {
                if (err2) {
                    return res.send("DATABASE ERROR " + err2);
                }



                res.redirect('/admin/pagebuilder'); // or wherever you want after login
            });
})

admin.get('/pagebuilder/new', (req, res)=>{
    res.render('admin/pageBuilderCreator')
})

admin.post('/pagebuilder/new', (req, res) => {
    db.query(
        "INSERT INTO pages (title, url, content) VALUES (?, ?, ?)",
        [req.body.title, req.body.url, req.body.content],
        (err, result) => {
            if (err) {
                console.error("DATABASE ERROR:", err);
                return res.status(500).send("DATABASE ERROR " + err.message);
            }
            res.redirect('/admin/pagebuilder');
        }
    );
});


admin.get('/blogtools/', (req, res)=>{
        db.query("SELECT * FROM blog", (err, result) => {
            if (err) {
                console.error("DB error in middleware:", err);
                return res.status(500).send("Server error");
            }

        res.locals.blogPosts = result

            res.render('admin/blogtools')
    })


})

admin.get('/blogtools/edit/:id', (req, res)=>{
                db.query("SELECT * FROM blog WHERE ID=?", [req.params.id], (err, result) => {
        if (err) {
            console.error("DB error in middleware:", err);
            return res.status(500).send("Server error");
        }

        if(result.length === 0){
            res.render('error/404');
        }else{
        res.locals.post = result[0]

        res.render('admin/blogtoolsEditor');
        }
    })
})

admin.post('/blogtools/edit/:id', (req, res)=>{
                 db.query("UPDATE blog SET title=?, url=?, category=?, content=? WHERE ID = ?", [req.body.title, req.body.url, req.body.category, req.body.content, req.params.id], async(err2) =>{
                if (err2) {
                    return res.send("DATABASE ERROR " + err2);
                }

                            // Create the full URL
            const postUrl = req.body.url.startsWith("http")
                ? req.body.url
                : `https://cybrixnova.com/blog/post/${req.body.url}`;

            // ---------- DISCORD ROLE PING MESSAGE ----------
            const message = `hey <@&1442595995925090375>! ${res.locals.user.username} just updated blog post **${req.body.title}** with the category of: [${req.body.category}](https://cybrixnova.com/blog/category/${req.body.category}) — check it out:\n${postUrl}`;
            // ------------------------------------------------

            try {
                await axios.post(process.env.DISCORD_WEBHOOK_URL, {
                    content: message,    // role ping works only in "content"
                    allowed_mentions: {
                        parse: ["roles"] // REQUIRED so the ping actually works
                    }
                });

                //console.log("Webhook sent with role ping.");
            } catch (e) {
                console.error("Webhook error:", e);
            }


                res.redirect('/admin/blogtools'); // or wherever you want after login
            });
})


admin.get('/blogtools/new', (req, res)=>{
    res.render('admin/blogtoolsCreator')
})

admin.post('/blogtools/new', (req, res) => {

    db.query(
        "INSERT INTO blog (title, url, category, content) VALUES (?, ?, ?, ?)",
        [req.body.title, req.body.url, req.body.category, req.body.content],
        async (err, result) => {

            if (err) {
                console.error("DATABASE ERROR:", err);
                return res.status(500).send("DATABASE ERROR " + err.message);
            }

            console.log("Inserted ID:", result.insertId);

            // Create the full URL
            const postUrl = req.body.url.startsWith("http")
                ? req.body.url
                : `https://cybrixnova.com/blog/post/${req.body.url}`;

            // ---------- DISCORD ROLE PING MESSAGE ----------
            const message = `hey <@&1442595995925090375>! ${res.locals.user.username} just posted a new post on the blog called **${req.body.title}** with the category of: [${req.body.category}](https://cybrixnova.com/blog/category/${req.body.category}) — check it out:\n${postUrl}`;
            // ------------------------------------------------

            try {
                await axios.post(process.env.DISCORD_WEBHOOK_URL, {
                    content: message,    // role ping works only in "content"
                    allowed_mentions: {
                        parse: ["roles"] // REQUIRED so the ping actually works
                    }
                });

                //console.log("Webhook sent with role ping.");
            } catch (e) {
                console.error("Webhook error:", e);
            }

            res.redirect('/admin/blogtools');
        }
    );
});

admin.get('/blogtools/delete/:id', (req, res) => {
    const pageId = req.params.id;

    db.query(
        "DELETE FROM blog WHERE id = ?",
        [pageId],
        (err, result) => {
            if (err) {
                console.error("DATABASE ERROR:", err);
                return res.status(500).send("DATABASE ERROR " + err.message);
            }

            if (result.affectedRows === 0) {
                // Optional: handle missing record
                return res.status(404).send("Page not found");
            }

            // Redirect or respond with JSON, up to you
            res.redirect('/admin/blogtools');
        }
    );
});

admin.get('/upload', (req, res)=>{
    res.locals.uploadServer = process.env.UPLOADSERVER_URL
    res.render('admin/uploader')
})

admin.get('/files', (req, res)=>{
                    db.query("SELECT * FROM files", (err, result) => {
        if (err) {
            console.error("DB error in middleware:", err);
            return res.status(500).send("Server error");
        }

        res.locals.files = result

        if(process.env.UPLOADSERVER_URL == "http://127.0.0.1:5055/upload"){
            res.locals.uploadServer = "http://127.0.0.1:5055"
        }else{
            res.locals.uploadServer = "https://s.cybrixnova.com"
        }


        res.render('admin/files');
        




    })
})




module.exports = admin