const board = document.getElementById("game-board");

for (let i = 0; i < 9; i++) {
  const cell = document.createElement("div");
  cell.className = "cell";
  board.appendChild(cell);
}