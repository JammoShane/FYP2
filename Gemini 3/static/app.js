async function sendMessage() {
  const msg = document.getElementById("message").value;
  if (!msg) return;

  const chatBox = document.getElementById("chatBox");
  chatBox.innerHTML += `<p><strong>You:</strong> ${msg}</p>`;

  const res = await fetch("/chat", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ message: msg })
  });

  const data = await res.json();
  chatBox.innerHTML += `<p><strong>Bot:</strong> ${data.reply}</p>`;

  if (data.classification) {
    chatBox.innerHTML += `<pre>${JSON.stringify(data.classification, null, 2)}</pre>`;
  }

  document.getElementById("message").value = "";
}