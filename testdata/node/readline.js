// readline on a terminal (windows/m8/ptyrun drives it).
const readline = require("readline");
console.log("tty", process.stdin.isTTY === true, process.stdout.isTTY === true);
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
rl.question("name? ", a => {
  console.log(`hello ${a}`);
  rl.close();
});
