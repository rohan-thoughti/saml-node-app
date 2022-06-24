require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const passport = require("passport");
const SamlStrategy = require("passport-saml").Strategy;
const fs = require("fs");

const router = require("./routes");

const app = express();
const APP_PORT = process.env.APP_PORT || 9000;

app.use(
    express.urlencoded({
        extended: true,
    })
);
app.use(express.json({
    limit: "15mb"
}));
app.use(helmet());

// passport
const certificate = fs.readFileSync("cert/" + process.env.IDP_CERT_FILE, {
    encoding: process.env.IDP_CERT_FILE_ENCODING
});
passport.use(
    new SamlStrategy({
            callbackUrl: process.env.API_URL_BASE + "/login/sso/callback",
            entryPoint: process.env.IDP_ENTRY_POINT,
            issuer: process.env.IDP_ISSUER,
            signatureAlgorithm: process.env.IDP_CERT_ALGO,
            cert: certificate,
        },
        function (profile, done) {
            return done(null, profile);
        }
    )
);
passport.serializeUser(function (user, done) {
    done(null, user);
});
passport.deserializeUser(function (user, done) {
    done(null, user);
});
app.use(passport.initialize());
app.use(passport.session());

app.use(router);

app.listen(APP_PORT, function (err) {
    if (err) {
        console.log("Server creation error..");
    } else {
        console.log("Server is running on.." + APP_PORT);
    }
});

module.exports = app;