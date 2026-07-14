let authToken = "";

const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const authStatus = document.getElementById("authStatus");
const noteContentInput = document.getElementById("noteContent");
const notesList = document.getElementById("notesList");

function setStatus(message, isError = false) {
  authStatus.textContent = message;
  authStatus.style.color = isError ? "#b91c1c" : "#0f766e";
}

async function requestJson(url, method, payload, token = "") {
  const headers = {
    "Content-Type": "application/json",
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    method,
    headers,
    body: payload ? JSON.stringify(payload) : undefined,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Request failed with status ${response.status}`);
  }

  return data;
}

async function registerUser() {
  try {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    await requestJson("/api/register", "POST", { username, password });
    setStatus("User registered. You can now log in.");
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function loginUser() {
  try {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    const data = await requestJson("/api/login", "POST", { username, password });
    authToken = data.token;
    setStatus("Login successful. Token stored in memory.");
    await loadNotes();
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function logoutUser() {
  try {
    if (!authToken) {
      setStatus("You are already logged out.");
      return;
    }

    await requestJson("/api/logout", "POST", null, authToken);
    authToken = "";
    notesList.innerHTML = "";
    setStatus("Logged out.");
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function saveNote() {
  try {
    if (!authToken) {
      setStatus("Please log in first.", true);
      return;
    }

    const content = noteContentInput.value.trim();
    await requestJson("/api/me/notes", "POST", { content }, authToken);
    noteContentInput.value = "";
    setStatus("Note saved.");
    await loadNotes();
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function loadNotes() {
  try {
    if (!authToken) {
      notesList.innerHTML = "";
      return;
    }

    const data = await requestJson("/api/me/notes", "GET", null, authToken);
    notesList.innerHTML = "";

    if (!Array.isArray(data.notes) || data.notes.length === 0) {
      notesList.innerHTML = "<li>No notes yet.</li>";
      return;
    }

    for (const note of data.notes) {
      const item = document.createElement("li");
      item.textContent = `${note.created_at}: ${note.content}`;
      notesList.appendChild(item);
    }
  } catch (error) {
    setStatus(error.message, true);
  }
}

document.getElementById("registerBtn").addEventListener("click", registerUser);
document.getElementById("loginBtn").addEventListener("click", loginUser);
document.getElementById("logoutBtn").addEventListener("click", logoutUser);
document.getElementById("saveNoteBtn").addEventListener("click", saveNote);
document.getElementById("refreshBtn").addEventListener("click", loadNotes);
