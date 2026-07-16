const { exec } = require("node:child_process");
const [input, output] = process.argv.slice(2);
exec(`convert ${input} ${output}`);
