require("dotenv").config();
const cookieParser = require("cookie-parser");
const express = require("express");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const db = require("better-sqlite3")("InsideDEKA.db");
db.pragma("Journal_Mode = WAL");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");


const CreateTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL,
        admin INTEGER NOT NULL
    )`).run();
    db.prepare(`
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sectionNum INTEGER,
            type INTEGER, -- 1 for exam, 2 for case
            name TEXT,
            description TEXT,
            filePath TEXT,
            uploadDate TEXT
        );
    `).run();
    db.prepare(`
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    `).run();
})

CreateTables();

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static("public"));
app.use(cookieParser());

app.use('/Exam Resources', express.static(path.join(__dirname, 'Exam Resources')));
app.use('/Case Resources', express.static(path.join(__dirname, 'Case Resources')));
app.use('/public', express.static(path.join(__dirname, 'public')));


let sectionNum = 0;

function initializeSectionNum() {
    const row = db.prepare("SELECT value FROM settings WHERE key = 'sectionNum'").get();
    if (row) {
        sectionNum = parseInt(row.value, 10);
    } else {
        db.prepare("INSERT INTO settings (key, value) VALUES ('sectionNum', ?)").run(sectionNum.toString());
    }
}

initializeSectionNum();

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'Exam Resources');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage: storage });

const CaseStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'Case Resources');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const store = multer({ storage: CaseStorage });

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

function updateSectionNum(newSectionNum) {
    sectionNum = newSectionNum;
    db.prepare("UPDATE settings SET value = ? WHERE key = 'sectionNum'").run(sectionNum.toString());
}



app.post("/create-exam", upload.single('file'), (req, res) => {
    const { name, description } = req.body;
    const file = req.file;

    if (!name || !description || !file) {
        return res.render("Create", { errors: ["All fields are required"] });
    }
    console.log(file.filename);
    console.log(file.id);

    const insertFile = db.prepare(`
        INSERT INTO files (sectionNum, type, name, description, filePath, uploadDate)
        VALUES (?, ?, ?, ?, ?, ?)
    `);
    const info = insertFile.run(sectionNum, 1, name, description, file.filename, new Date().toISOString());

    // Handle the file and form data as needed
    console.log("File uploaded:", file);

    // Redirect to the Exams or Cases page
    res.redirect(`/exams-sec${sectionNum}`); // Change to "/cases" if needed
});
app.get('/pdf/:file', (req, res) => {
    const filePath = path.join(__dirname, 'Exam Resources', req.params.file);
    console.log(filePath)
    res.sendFile(filePath);
});
app.post("/create-case", store.single('file'), (req, res) => {
    const { name, description } = req.body;
    const file = req.file;

    if (!name || !description || !file) {
        return res.render("Create", { errors: ["All fields are required"] });
    }
    console.log(file.filename);

    const insertFile = db.prepare(`
        INSERT INTO files (sectionNum, type, name, description, filePath, uploadDate)
        VALUES (?, ?, ?, ?, ?, ?)
    `);
    const info = insertFile.run(sectionNum, 0, name, description, file.filename, new Date().toISOString());

    // Retrieve the file ID

    // Redirect to the Exams or Cases page
    res.redirect(`/cases-sec${sectionNum}`); // Change to "/cases" if needed
});
app.get('/pdf/:file', (req, res) => {
    const filePath = path.join(__dirname, 'Case Resources', req.params.file);
    console.log(filePath)
    res.sendFile(filePath);
});

app.get("/exams/create", (req, res) => {
    res.render("Create", { sectionNum, user: req.user });
});
app.get("/cases/create", (req, res) => {
    res.render("CreateCase", { sectionNum, user: req.user });
});

app.get("/exams-sec1", (req, res) => {
    updateSectionNum(1);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 1").all(sectionNum);
    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user, resources });
});
app.get("/exams-sec2", (req, res) => {
    updateSectionNum(2);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 1").all(sectionNum);
    console.log(resources);
    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user, resources });
});
app.get("/exams-sec3", (req, res) => {
    updateSectionNum(3);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 1").all(sectionNum);

    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user, resources });
});
app.get("/exams-sec4", (req, res) => {
    updateSectionNum(4);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 1").all(sectionNum);

    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user, resources });
});
app.get("/exams-sec5", (req, res) => {
    updateSectionNum(5);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 1").all(sectionNum);

    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user, resources });
});
app.get("/exams-sec6", (req, res) => {
    updateSectionNum(6);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 1").all(sectionNum);

    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Exams", { sectionNum, admin, user: req.user, resources });
});

app.get("/cases-sec1", (req, res) => {
    updateSectionNum(1);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 0").all(sectionNum);
    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user, resources });
});
app.get("/cases-sec2", (req, res) => {
    updateSectionNum(2);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 0").all(sectionNum);
    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user, resources });
});
app.get("/cases-sec3", (req, res) => {
    updateSectionNum(3);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 0").all(sectionNum);
    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user, resources });
});
app.get("/cases-sec4", (req, res) => {
    updateSectionNum(4);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 0").all(sectionNum);
    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user, resources });
});
app.get("/cases-sec5", (req, res) => {
    updateSectionNum(5);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 0").all(sectionNum);
    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user, resources });
});
app.get("/cases-sec6", (req, res) => {
    updateSectionNum(6);
    const resources = db.prepare("SELECT * FROM files WHERE sectionNum = ? AND type = 0").all(sectionNum);
    if (!req.user) {
        res.render("Exams", { sectionNum, admin: 0, user: req.user, resources });
    }
    const adminOrNot = db.prepare("SELECT * FROM users WHERE id = ?");
    const curUser = adminOrNot.get(req.user.userid);
    const admin = curUser.admin;
    console.log(admin);
    res.render("Cases", { sectionNum, admin, user: req.user, resources });
});

app.get('/edit/:id', (req, res) => {
    const fileId = req.params.id;
    const file = db.prepare("SELECT * FROM files WHERE id = ?").get(fileId);
    if (file) {
        res.render("Edit", { file });
    } else {
        res.render("homepage");
    }
});

app.post('/update-exam/:id', upload.single('file'), (req, res) => {
    const { name, description, currentFilePath } = req.body;
    const file = req.file;
    const fileId = req.params.id;

    let filePath = currentFilePath;
    if (file) {
        filePath = `${file.filename}`;
    }

    const updateFile = db.prepare(`
        UPDATE files
        SET name = ?, description = ?, filePath = ?, uploadDate = ?
        WHERE id = ?
    `);
    updateFile.run(name, description, filePath, new Date().toISOString(), fileId);

    // Redirect to the Exams or Cases page
    res.redirect(`/exams-sec${sectionNum}`); // Change to "/cases" if needed
});

app.post('/delete-file/:id', (req, res) => {
    const fileId = req.params.id;
    // Retrieve the file information
    const file = db.prepare("SELECT * FROM files WHERE id = ?").get(fileId);
    const fileType = file.type;
    if (file) {
        let filePath = ""
        // Delete the file from the file system
        if (fileType == 1) {
            filePath = path.join(__dirname, 'Exam Resources', file.filePath);
        } else if (fileType == 2) {
            filePath = path.join(__dirname, 'Case Resources', file.filePath);
        }
        fs.unlink(filePath, (err) => {
            if (err) {
                console.error("Error deleting file:", err);
                return res.status(500).send("Error deleting file");
            }

            // Delete the file from the database
            db.prepare("DELETE FROM files WHERE id = ?").run(fileId);

            // Redirect to the appropriate page based on file type
            if (fileType == 1) {
                res.redirect(`/exams-sec${sectionNum}`);
            } else if (fileType == 2) {
                res.redirect(`/cases-sec${sectionNum}`);
            } else {
                res.redirect('/');
            }
        });
    } else {
        res.status(404).send('File not found');
    }
});

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