const cookieParser = require("cookie-parser");
const csrf = require("csurf");
const express = require("express");
const { registerPartials } = require("hbs");
const hbs = require("hbs");
const path = require("path");
const admin = require("firebase-admin");

const serviceAccount = require("../serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const csrfMiddleware = csrf({ cookie: true });
const port = process.env.PORT || 3000;
const app = express();

const static_path = path.join(__dirname, "../public");
const views_path = path.join(__dirname, "../templates/views");
const partials_path = path.join(__dirname, "../templates/partials");

app.set("view engine", "hbs"); // Set 'hbs' as template engine.
app.set("views", views_path);
hbs.registerPartials(partials_path);

app.use(express.static(static_path));

app.use(express.json());
app.use(cookieParser());
app.use(csrfMiddleware);


// TO PREVENTING CROSS SITE SCRIPTING ATTACKS.
app.all("*", (req, res, next) => {
  res.cookie("XSRF-TOKEN",req.csrfToken());
  next();
});

app.get("/", (req, res) => {
  res.render("index");
});
app.get("/signup", (req, res) => {
  res.render("signup");
});
app.get("/signin", (req, res) => {
  res.render("signin");
});
app.get("/profile", (req, res) => {
  const sessionCookie = req.cookies.session || "";

  admin
    .auth()
    .verifySessionCookie(sessionCookie, true /** checkRevoked */)
    .then(() => {
      res.render("profile");
    })
    .catch((error) => {
      res.redirect("/signin");
    });
});


app.post("/sessionLogin", (req, res) => {
  const idToken = req.body.idToken.toString();

  const expiresIn = 60 * 60 * 24 * 5 * 1000;

  admin
    .auth()
    .createSessionCookie(idToken, { expiresIn })
    .then(
      (sessionCookie) => {
        const options = { maxAge: expiresIn, httpOnly: true };
        res.cookie("session", sessionCookie, options);
        res.end(JSON.stringify({ status: "success" }));
      },
      (error) => {
        res.status(401).send("UNAUTHORIZED REQUEST!");
      }
    );
});

app.get("/sessionLogout", (req, res) => {
  res.clearCookie("session");
  res.redirect("/signin");
});


app.listen(port, () => {
  console.log(`The server is running on port ${port}`);
});
