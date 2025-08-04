document.addEventListener('DOMContentLoaded', () => {
  const API_URL = 'http://localhost:3000';
  let conversationHistory = [];
  let authToken = localStorage.getItem('authToken'); // pega o token salvo

  const chatContainer = document.getElementById('chat-container');
  const userInput = document.getElementById('user-input');
  const sendBtn = document.getElementById('send-btn');
  const typingIndicator = document.getElementById('typing-indicator');

  function loadConversation() {
    const savedHistory = localStorage.getItem('chatHistory');
    if (savedHistory) {
      conversationHistory = JSON.parse(savedHistory);
      conversationHistory.forEach(msg => {
        addMessage(msg.content, msg.role === 'user' ? 'user' : 'bot');
      });
    }
  }

  function addMessage(text, sender) {
    const msgDiv = document.createElement('div');
    msgDiv.classList.add('message', sender);
    msgDiv.textContent = text;
    chatContainer.appendChild(msgDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;
  }

  async function sendMessageToServer(userText) {
    if (!authToken) {
      throw new Error('Usuário não autenticado');
    }

    const response = await fetch(`${API_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
      },
      body: JSON.stringify({
        message: userText,
        history: conversationHistory // enviar histórico para contexto
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Erro ao enviar mensagem');
    }

    const data = await response.json();
    return data; // { reply: "...texto do bot..." }
  }

  async function sendMessage() {
    const userText = userInput.value.trim();
    if (!userText) return;

    userInput.disabled = true;
    sendBtn.disabled = true;

    addMessage(userText, 'user');
    userInput.value = '';

    typingIndicator.style.display = 'block';
    chatContainer.scrollTop = chatContainer.scrollHeight;

    try {
      const { reply } = await sendMessageToServer(userText);

      conversationHistory.push(
        { role: "user", content: userText },
        { role: "assistant", content: reply }
      );
      localStorage.setItem('chatHistory', JSON.stringify(conversationHistory));

      typingIndicator.style.display = 'none';
      addMessage(reply, 'bot');

    } catch (error) {
      typingIndicator.style.display = 'none';
      addMessage(`Erro: ${error.message}`, 'bot');
    }

    userInput.disabled = false;
    sendBtn.disabled = false;
    userInput.focus();
  }

  document.getElementById('input-area').addEventListener('submit', e => {
    e.preventDefault();
    sendMessage();
  });

  userInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  loadConversation();
});
