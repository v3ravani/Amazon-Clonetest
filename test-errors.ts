// ================================
// 1. HARD‑CODED API KEY (SECURITY)
// ================================
const STRIPE_API_KEY = "sk_live_1234567890abcdef123456"; // ❌ hard‑coded secret

// ================================
// 2. UNENCRYPTED PASSWORD
// ================================
const password = "admin123"; // ❌ plaintext password

// ================================
// 3. DANGEROUS CODE
// ================================
const cmd = "rm -rf /";
require("child_process").exec(cmd); // ❌ dangerous OS command

// ================================
// 4. BACKDOOR‑LIKE CODE
// ================================
const payload = "console.log('backdoor')";
eval(payload); // ❌ eval detected

// ================================
// 5. BROKEN / INFINITE LOOP
// ================================
while (true) {
  console.log("infinite loop"); // ❌ no break condition
}

// ================================
// 6. OPEN ENDPOINT
// ================================
import express from "express";
const app = express();

app.get("/open", (req, res) => {
  res.send("Anyone can access this"); // ❌ open endpoint
});

app.listen(3000, "0.0.0.0"); // ❌ open to public network

// ================================
// 7. CODE DUPLICATION (BLOCK COPY)
// ================================
function duplicateLogic1() {
  const a = 10;
  const b = 20;
  return a + b;
}

function duplicateLogic2() {
  const a = 10;
  const b = 20;
  return a + b;
}

// ================================
// 8. TODO / DEAD CODE STYLE
// ================================
function unusedFunction(): void {
  // TODO: remove this later
  console.log("I am never used");
}

// ================================
// 9. SYNTAX ERROR
// ================================
function brokenFunction( {
  console.log("missing parenthesis"); // ❌ syntax error
