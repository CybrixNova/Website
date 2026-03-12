const express = require('express');
const dotenv = require('dotenv').config()
const db = require('./custom_modules/sql/db_connector')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser');
const app = express();
app.set('view engine', 'ejs');
app.use(express.static('./public/assets'))
app.set('views', './public/views');
app.set('trust proxy', true);

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded())

// parse application/json
app.use(bodyParser.json())

app.use(cookieParser());

app.use(require('./custom_modules/security/userManager'))
app.use(require('./custom_modules/security/requestValidator'))
app.use(require('./custom_modules/globals'))




app.get('/', (req, res)=>{
    res.render('index')
})



app.use('/users', require('./routes/users'))
app.use('/sl', require('./routes/linkShortener'))
app.use('/blog', require('./routes/blog'))


app.use('/admin', require('./routes/admin'))


app.get('/erp-schedule', (req, res)=>{
        db.query("SELECT * FROM erp_schedule", (err, results) => {
        res.render("erp-schedule", { rows: results });
    });
})


app.get('/:page', (req, res)=>{
        db.query("SELECT * FROM pages WHERE url = ?", [req.params.page], (err, result) => {
        if (err) {
            console.error("DB error in middleware:", err);
            return res.status(500).send("Server error");
        }

        if (result.length === 0) {
            res.status(404)
            res.render('error/404')
        }else{
          res.locals.content = result[0].content  
          res.locals.title = result[0].title  


          res.render('template')
        }
    })
})

app.use('/',(req, res)=>{
    res.render('error/404');
})



app.listen(5050, ()=>{
    console.log("Cybrix.Dev web worker started")
})