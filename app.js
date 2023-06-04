const express = require("express");

const ejs = require("ejs");
const bodyParser = require("body-parser");

const mongoose = require("mongoose");

const app = express();

app.set("view engine", "ejs");

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

// Level 5 - Authentication | Adding Cookies & Sessions.

const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const session = require("express-session");

// Starting Session.
app.use(session({

    secret: "This is my secret.",
    resave: false,

    saveUninitialized: true,
}));

app.use(passport.initialize());     // Initialising Passport Package.
app.use(passport.session());        // Using Passport to deal with the Session.

const uri = "mongodb://0.0.0.0:27017/userDB";
mongoose.connect(uri);

const userSchema = new mongoose.Schema({ email: String, password: String });

// Level 5 - Authentication | To Hash & Salt Password + Save Users in MongoDB Database
userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);

// Level 5 - Authentication | Setting up Passport Local Strategy + Serializing & Deserializing Users

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());       // Allows passport to create Cookie and stuffs user's identification.
passport.deserializeUser(User.deserializeUser());   // Allows passport to crumble Cookie and identify user. 

app.listen("3000", function(){

    console.log("\nServer Info:\n\nStatus: Active\nPort: 3000\n");
});

app.get("/", function(req, res){

    res.render("home");
});

app.get("/register", function(req, res){

    res.render("register");
});

// Creating a secrets route to ensure the user can directly connect if cookie is present in browser.
app.get("/secrets", function(req, res){

    if(req.isAuthenticated()){
      
        res.render("secrets");
    } else {

        res.redirect("/login");
    }
});

app.post("/register", function(req, res){

    // Using passport-local-mongoose to Register User.
    User.register({ username: req.body.username }, req.body.password, function(err, user) {
        
        if (err) { 
            
            console.log(err);
            res.redirect("/register");

         } else {

            // Using passport to Authenticate.
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");   // Works only if Authentication is Successful.
            });
        }
    });
});

app.get("/login", function(req, res){

    res.render("login");
});

app.post("/login", function(req, res){

    const user = new User({ username: req.body.username, password: req.body.password });

    // Using passport to Log In.
    req.login(user, function(err){

        if(err){ 

            console.log(err);
        } else {

            // Using passport to Authenticate.
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");   // Works only if Authentication is Successful.
            });
        }
    });
});