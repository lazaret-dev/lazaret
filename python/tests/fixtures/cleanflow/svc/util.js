function render(el, value) {
  el.textContent = value;   // safe, not innerHTML
}
function handler(req, res) {
  const id = parseInt(req.query.id, 10);
  lookup(id);
}
function lookup(v) {
  db.query("SELECT * FROM t WHERE id = ?", [v]);  // parameterized
}
