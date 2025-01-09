require("dotenv").config();
const cookieParser = require("cookie-parser");
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const db = require("better-sqlite3")("InsideDEKA.db");
db.pragma("Journal_Mode = WAL");
const bodyParser = require("body-parser");

let sectionNum = 0;

const CreateTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL,
        admin INTEGER NOT NULL
    )`).run();
    db.prepare(`
        CREATE TABLE IF NOT EXISTS resources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        section INTEGER NOT NULL,
        title STRING NOT NULL,
        description STRING NOT NULL,
        link STRING NOT NULL
    )`).run();
})

CreateTables();

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static("public"));
app.use(cookieParser());

app.use(function (req, res, next) {
    res.locals.errors = [];
    
    try {
        const decoded = jwt.verify(req.cookies.InsideDEKA, process.env.JWTSECRET);
        req.user = decoded;
    } catch(err) {
        req.user=false;
    }

    res.locals.user = req.user;
    next();
});

app.get("/exams-sec1", (req, res) => {
    sectionNum = 1;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user });
});
app.get("/exams-sec2", (req, res) => {
    sectionNum = 2;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user });
});
app.get("/exams-sec3", (req, res) => {
    sectionNum = 3;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user });
});
app.get("/exams-sec4", (req, res) => {
    sectionNum = 4;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user });
});
app.get("/exams-sec5", (req, res) => {
    sectionNum = 5;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user });
});
app.get("/exams-sec6", (req, res) => {
    sectionNum = 6;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user });
});

app.get("/cases-sec1", (req, res) => {
    sectionNum = 1;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user });
});
app.get("/cases-sec2", (req, res) => {
    sectionNum = 2;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user });
});
app.get("/cases-sec3", (req, res) => {
    sectionNum = 3;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user });
});
app.get("/cases-sec4", (req, res) => {
    sectionNum = 4;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user });
});
app.get("/cases-sec5", (req, res) => {
    sectionNum = 5;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user });
});
app.get("/cases-sec6", (req, res) => {
    sectionNum = 6;
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user });
});


app.set("view engine", "ejs");

app.get("/", (req, res) => {
    res.render("homepage");
});

app.get("/fundementals", (req, res) => {
    res.render("fundementals");
});

app.get("/About-InsideDEKA", (req, res) => {
    res.render("AboutInsideDEKA");
})

app.get("/Our-Team", (req, res) => {
    res.render("OurTeam");
})

app.get("/sign-up", (req, res) => {
    res.render("SignUp");
})

app.get("/login", (req, res) => {
    res.render("Login");
})

app.post("/sign-up", (req, res) => {
    
    let admin = 0;
    const errors = [];

    console.log(req.body);
    
    if (typeof req.body.username !== "string" || typeof req.body.password !== "string") {
        req.body.username = "";
        req.body.password = "";
    }
    if (!req.body.username || !req.body.password) {
        errors.push("Please input a valid username and password");
    }

    const lookUp = db.prepare("SELECT * FROM users WHERE username = ?");
    const user = lookUp.get(req.body.username);
    if (user) {
        errors.push("Username already exists");
    }

    req.body.username = req.body.username.trim();
    if (req.body.username === "" || req.body.password === "") {
        errors.push("Please input a valid username and password");
    }
    if (req.body.password.length < 8) {
        errors.push("Password must be at least 8 characters long");
    }
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) {
        errors.push("Username must only contain letters and numbers");
    }
    if (req.body.adminPassword === process.env.adminCode) {
        admin = 1;
    }

    if (errors.length) {
        res.render("SignUp", { errors });
    } else {
        const salt = bcrypt.genSaltSync(10);
        req.body.password = bcrypt.hashSync(req.body.password, salt);
        const registerUser = db.prepare("INSERT INTO users (username, password, admin) VALUES (?, ?, ?)");
        const result = registerUser.run(req.body.username, req.body.password, admin);
        const lookUp = db.prepare("SELECT * FROM users WHERE ROWID = ?");

        const user = lookUp.get(result.lastInsertRowid);
        const tokVal = jwt.sign({exp: Math.floor(Date.now()/1000) + 60*60*24, userid: user.id, username: user.username, admin: user.admin}, process.env.JWTSECRET);
        res.cookie("InsideDEKA", tokVal, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000*60*60*24
        })
        res.render("homepage", { user });
    }
})

app.post("/login", (req, res) => {
    let errors = [];
    if (typeof req.body.username !== "string" || typeof req.body.password !== "string") {
        req.body.username = "";
        req.body.password = "";
    }
    if (req.body.username === "" || req.body.password === "") {
        errors = [("Incorrect username or password")];
    }

    const lookUp = db.prepare("SELECT * FROM users WHERE username = ?");
    const user = lookUp.get(req.body.username);

    if (!user) {
        errors = [("Incorrect username or password")];
    }

    if (errors.length) {
        res.render("Login", { errors });
    }

    const match = bcrypt.compareSync(req.body.password, user.password);
    if (!match) {
        errors = [("Incorrect username or password")];
    }

    const tokVal = jwt.sign({exp: Math.floor(Date.now()/1000) + 60*60*24, userid: user.id, username: user.username, admin: user.admin}, process.env.JWTSECRET);
    res.cookie("InsideDEKA", tokVal, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000*60*60*24
    })
    res.render("homepage", { user });

})

app.get("/logout", (req, res) => {
    res.clearCookie("InsideDEKA");
    res.redirect("/");
})

app.listen(3000)