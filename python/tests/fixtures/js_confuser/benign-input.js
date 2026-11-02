const path = require('path');
module.exports = function greet(name) {
  return 'Hello, ' + name + ', from ' + path.basename(__filename) + '.';
};
