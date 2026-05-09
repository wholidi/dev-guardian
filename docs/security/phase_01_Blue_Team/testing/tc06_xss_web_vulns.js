/**
 * TC-06: Cross-Site Scripting (XSS) — OWASP A03
 * Expected: CRITICAL — DOM-based, reflected, and stored XSS patterns
 * Purpose:  Validate Dev Guardian's JavaScript/web vulnerability detection
 * Language: JavaScript (Node.js + browser-side)
 */

// ── DOM-BASED XSS ─────────────────────────────────────────────────────────────

function renderUserProfile(userName) {
  // VULNERABLE: Directly injecting user input into innerHTML
  document.getElementById("profile").innerHTML = "<h2>Welcome, " + userName + "!</h2>";
  // Payload: <img src=x onerror=alert(document.cookie)>
}

function displaySearchResults(query) {
  // VULNERABLE: document.write with user-controlled input
  document.write("<p>Results for: " + query + "</p>");  // VULN
}

function updateGreeting() {
  const name = location.hash.substring(1);  // From URL fragment
  // VULNERABLE: Reading from location.hash without sanitisation
  document.getElementById("greeting").innerHTML = "Hello " + name;  // VULN
}


// ── REFLECTED XSS (Server-Side Template — Express.js) ────────────────────────

const express = require("express");
const app = express();

app.get("/search", (req, res) => {
  const query = req.query.q;
  // VULNERABLE: Reflecting query param directly into HTML response
  res.send(`<html><body><p>You searched for: ${query}</p></body></html>`);  // VULN
});

app.get("/user/:name", (req, res) => {
  const name = req.params.name;
  // VULNERABLE: No output encoding
  res.send(`<h1>Profile: ${name}</h1>`);  // VULN
});


// ── STORED XSS ────────────────────────────────────────────────────────────────

function saveAndDisplayComment(comment) {
  // VULNERABLE: Storing raw input and rendering without sanitisation
  localStorage.setItem("lastComment", comment);
  const stored = localStorage.getItem("lastComment");
  document.getElementById("comments").innerHTML += stored;  // VULN
}


// ── INSECURE eval() USAGE ─────────────────────────────────────────────────────

function processUserFormula(input) {
  // VULNERABLE: eval() on user input enables code execution
  const result = eval(input);  // VULN — OWASP A03
  return result;
}

function loadConfig(configString) {
  // VULNERABLE: Function constructor is equivalent to eval
  const fn = new Function("return " + configString);  // VULN
  return fn();
}


// ── OPEN REDIRECT ─────────────────────────────────────────────────────────────

app.get("/redirect", (req, res) => {
  const target = req.query.url;
  // VULNERABLE: No validation of redirect target — phishing vector
  res.redirect(target);  // VULN
});


// ── CSRF — NO TOKEN VALIDATION ────────────────────────────────────────────────

app.post("/transfer", (req, res) => {
  const { to, amount } = req.body;
  // VULNERABLE: No CSRF token check — any site can trigger this
  processTransfer(to, amount);  // VULN
  res.json({ status: "transferred" });
});
