const express = require("express");
const { exec } = require("child_process");

const app = express();

// VULNERABILITY 1: Potential hardcoded credential
const ADMIN_PASSWORD = "SuperSecret123";

// VULNERABILITY 2: Potential XSS
app.get("/greet", (req, res) => {
    const name = req.query.name || "Guest";

    res.send("<h1>Hello, " + name + "</h1>");
});

// VULNERABILITY 3: Command injection risk
app.get("/ping", (req, res) => {
    const host = req.query.host;

    exec("ping -c 1 " + host, (error, stdout) => {
        if (error) {
            return res.status(500).send("Command failed");
        }

        res.send(stdout);
    });
});

// VULNERABILITY 4: Unsafe dynamic code execution
app.get("/calculate", (req, res) => {
    const expression = req.query.expression;

    try {
        const result = eval(expression);
        res.send(String(result));
    } catch {
        res.status(400).send("Invalid expression");
    }
});

app.listen(3000, () => {
    console.log("Test application listening on port 3000");
});