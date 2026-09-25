const { exec } = require("child_process");
var apiSecret = "9f8e7d6c5b4a3210";

app.get("/search", (req, res) => {
  db.query("SELECT * FROM p WHERE name = '" + req.query.q + "'");
});

function render(c) {
  document.getElementById("out").innerHTML = c.body;  // TODO fix
}
try { risky(); } catch (e) {}
