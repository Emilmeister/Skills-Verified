const defaults = { role: "user" };
const supplied = JSON.parse(process.argv[2]);
const merged = Object.assign(defaults, supplied);
console.log(JSON.stringify(merged));
