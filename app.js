const messagesEl = document.querySelector('#messages');
const composerEl = document.querySelector('#composer');
const promptEl = document.querySelector('#prompt');
const clearButtonEl = document.querySelector('#clear-chat');
const exportMarkdownEl = document.querySelector('#export-md');
const exportJsonEl = document.querySelector('#export-json');
const refreshStateEl = document.querySelector('#refresh-state');
const statusEl = document.querySelector('#chat-status');
const noteFormEl = document.querySelector('#note-form');
const noteInputEl = document.querySelector('#note-input');
const noteStatusEl = document.querySelector('#note-status');
const recentNotesEl = document.querySelector('#recent-notes');
const toolLogEl = document.querySelector('#tool-log');
const classifierLogEl = document.querySelector('#classifier-log');
const templateEl = document.querySelector('#message-template');
const feedTemplateEl = document.querySelector('#feed-item-template');

const storageKey = 'darktracex-session-v2';
const starterMessages = [
  {
    role: 'assistant',
    text: 'DarkTraceX online. How can I help you secure or analyze something today?',
  },
];

let conversationId = null;
let messages = loadSession();
let pending = false;

function loadSession() {
  const stored = localStorage.getItem(storageKey);
  if (!stored) {
    return [...starterMessages];
  }

  try {
    const parsed = JSON.parse(stored);
    conversationId = parsed.conversationId || null;
    if (Array.isArray(parsed.messages) && parsed.messages.length > 0) {
      return parsed.messages;
    }
  } catch {}

  return [...starterMessages];
}

function saveSession() {
  localStorage.setItem(
    storageKey,
    JSON.stringify({
      conversationId,
      messages,
    }),
  );
}

function setStatus(text) {
  statusEl.textContent = text;
}

function renderMessage(message) {
  const fragment = templateEl.content.cloneNode(true);
  const article = fragment.querySelector('.message');
  const role = fragment.querySelector('.message-role');
  const text = fragment.querySelector('.message-text');

  article.classList.add(message.role);
  role.textContent = message.role;
  text.textContent = message.text;

  messagesEl.appendChild(fragment);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function renderMessages(items) {
  messagesEl.innerHTML = '';
  items.forEach(renderMessage);
}

function autoResize(textarea) {
  textarea.style.height = 'auto';
  textarea.style.height = `${Math.min(textarea.scrollHeight, 220)}px`;
}

function resetFeed(el, emptyText) {
  el.innerHTML = '';
  el.classList.add('empty-state');
  el.textContent = emptyText;
}

function addFeedItem(container, title, body) {
  if (container.classList.contains('empty-state')) {
    container.classList.remove('empty-state');
    container.innerHTML = '';
  }

  const fragment = feedTemplateEl.content.cloneNode(true);
  fragment.querySelector('.feed-item-title').textContent = title;
  fragment.querySelector('.feed-item-body').textContent = body;
  container.appendChild(fragment);
}

function updateStats(stats) {
  document.querySelector('#stat-conversations').textContent = stats?.conversations ?? '0';
  document.querySelector('#stat-messages').textContent = stats?.messages ?? '0';
  document.querySelector('#stat-notes').textContent = stats?.notes ?? '0';
  document.querySelector('#stat-knowledge').textContent = stats?.knowledge_docs ?? '0';

  resetFeed(recentNotesEl, 'No notes yet.');
  (stats?.recent_notes || []).forEach((note) => {
    addFeedItem(recentNotesEl, `Note #${note.id}`, note.content);
  });
}

function updateToolLog(toolEvents) {
  resetFeed(toolLogEl, 'No tools used in this session.');
  resetFeed(classifierLogEl, 'No classifier output yet.');
  (toolEvents || []).forEach((event) => {
    const body = JSON.stringify(event.result, null, 2);
    addFeedItem(toolLogEl, event.tool_name, body);
    if (event.tool_name === 'classify_defense_text') {
      addFeedItem(
        classifierLogEl,
        event.result.model,
        `label=${event.result.label} confidence=${event.result.confidence}`,
      );
    }
  });
}

async function fetchState() {
  const response = await fetch('/api/state');
  if (!response.ok) {
    return;
  }
  const data = await response.json();
  updateStats(data);
}

async function sendChat(payload) {
  const response = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data.error || 'The server could not complete the request.';

    if (response.status === 401) {
      throw new Error('The configured model provider rejected the request.');
    }

    if (response.status === 429) {
      throw new Error('The configured local provider is rate-limited or unavailable.');
    }

    throw new Error(message);
  }

  return data;
}

async function createNote(content) {
  const response = await fetch('/api/notes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || 'Could not save note.');
  }
  return data;
}

function downloadConversation(format) {
  if (!conversationId) {
    setStatus('Nothing to export yet');
    return;
  }

  const url = `/api/export?conversation_id=${encodeURIComponent(conversationId)}&format=${encodeURIComponent(
    format,
  )}`;
  window.open(url, '_blank', 'noopener');
}

composerEl.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (pending) {
    return;
  }

  const prompt = promptEl.value.trim();
  if (!prompt) {
    return;
  }

  const userMessage = { role: 'user', text: prompt };
  messages.push(userMessage);
  renderMessage(userMessage);
  saveSession();

  promptEl.value = '';
  autoResize(promptEl);
  pending = true;
  setStatus('Thinking');

  try {
    const data = await sendChat({
      conversation_id: conversationId,
      messages,
    });

    conversationId = data.conversation_id || conversationId;
    const assistantMessage = { role: 'assistant', text: data.reply };
    messages.push(assistantMessage);
    renderMessage(assistantMessage);
    saveSession();
    updateToolLog(data.tool_events);
    updateStats(data.stats);
    setStatus(`Ready · ${data.model}`);
  } catch (error) {
    const assistantMessage = {
      role: 'system',
      text: `Request failed: ${error.message}`,
    };
    messages.push(assistantMessage);
    renderMessage(assistantMessage);
    saveSession();
    setStatus('Error');
  } finally {
    pending = false;
  }
});

noteFormEl.addEventListener('submit', async (event) => {
  event.preventDefault();
  const content = noteInputEl.value.trim();
  if (!content) {
    return;
  }

  noteStatusEl.textContent = 'Saving';

  try {
    const data = await createNote(content);
    noteInputEl.value = '';
    autoResize(noteInputEl);
    updateStats(data.stats);
    noteStatusEl.textContent = `Saved note #${data.note.id}`;
  } catch (error) {
    noteStatusEl.textContent = error.message;
  }
});

clearButtonEl.addEventListener('click', () => {
  if (pending) {
    return;
  }
  conversationId = null;
  messages = [...starterMessages];
  saveSession();
  renderMessages(messages);
  updateToolLog([]);
  setStatus('Ready');
});

refreshStateEl.addEventListener('click', () => {
  fetchState().catch(() => {});
});

exportMarkdownEl.addEventListener('click', () => {
  downloadConversation('markdown');
});

exportJsonEl.addEventListener('click', () => {
  downloadConversation('json');
});

renderMessages(messages);
updateToolLog([]);
fetchState().catch(() => {});
autoResize(promptEl);
autoResize(noteInputEl);

promptEl.addEventListener('input', () => autoResize(promptEl));
noteInputEl.addEventListener('input', () => autoResize(noteInputEl));

renderMessages(messages);
updateToolLog([]);
fetchState().catch(() => {});
autoResize(promptEl);
autoResize(noteInputEl);
setStatus('Ready');
