// Authentication | Creating an Environment Variable to Safeguard Password Encryption Secret.

// require("dotenv").config();
// console.log(process.env.SECRET);

const express = require("express");

const ejs = require("ejs");
const bodyParser = require("body-parser");

const mongoose = require("mongoose");

const encrypt = require("mongoose-encryption");
const md5 = require("md5");

const uri = "mongodb://0.0.0.0:27017/userDB";
mongoose.connect(uri);

const userSchema = new mongoose.Schema({ email: String, password: String });

// Level 2 - Authentication | Encrypting Password
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = mongoose.model("User", userSchema);

const app = express();

app.set("view engine", "ejs");

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.listen("3000", function(){

    console.log("\nServer Info:\n\nStatus: Active\nPort: 3000\n");
});

app.get("/", function(req, res){

    res.render("home");
});

app.get("/register", function(req, res){

    res.render("register");
});

app.post("/register", function(req, res){

    let username = req.body.username;
    // let password = req. body.password;
    
    // Level 3 - Authentication | Converting Password to an irreversible Hash.
    let password = md5(req. body.password);

    let newUser = new User({ email: username, password: password });
    
    newUser.save()
        .then(function(){ res.render("secrets"); })
        .catch(function(error){ console.log(); });
});

app.get("/login", function(req, res){

    res.render("login");
});

app.post("/login", function(req, res){

    let username = req.body.username;
    // let password = req.body.password;

    // Level 3 - Authentication | Converting the user-provided Password to the same irreversible Hash for Assertion.
    let password = md5(req. body.password);

    User.findOne({ email: username })
        .then(function(foundUser){

            if(foundUser.password === password){

                res.render("secrets");
            }

            else{

                console.log("Invalid Password!\n");
            }
        })
        .catch(function(error){ console.log(error); });
});