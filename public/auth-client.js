document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('.auth-form');
  if (!form) return;

  const isRegister = Boolean(document.getElementById('fullName'));
  const message = document.createElement('p');
  message.className = 'auth-message';
  message.setAttribute('role', 'alert');
  form.prepend(message);

  const setMessage = (text, error = true) => {
    message.textContent = text;
    message.hidden = !text;
    message.dataset.state = error ? 'error' : 'success';
  };

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setMessage('');
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    submit.textContent = isRegister ? 'Création en cours…' : 'Connexion en cours…';

    try {
      const data = Object.fromEntries(new FormData(form).entries());
      let payload;
      let endpoint;

      if (isRegister) {
        const names = String(data.fullName || '').trim().split(/\s+/);
        const firstName = names.shift() || '';
        payload = {
          firstName,
          lastName: names.join(' '),
          email: data.email,
          password: data.password,
          level: data.studentLevel,
          objective: 'Améliorer mon français'
        };
        if (data.password !== data.passwordConfirm) {
          throw new Error('Les mots de passe ne correspondent pas.');
        }
        endpoint = '/api/auth/register';
      } else {
        payload = { email: data.email, password: data.password };
        endpoint = '/api/auth/login';
      }

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok || !result.token) {
        throw new Error(result.message || 'Une erreur est survenue.');
      }

      localStorage.setItem('elprof_token', result.token);
      window.location.href = '/dashboard.html';
    } catch (error) {
      setMessage(error.message || 'Impossible de contacter le serveur.');
      submit.disabled = false;
      submit.textContent = isRegister ? 'Créer mon compte' : 'Se connecter';
    }
  });

  document.querySelectorAll('[data-provider]').forEach((button) => {
    button.addEventListener('click', () => {
      setMessage(`L'inscription avec ${button.dataset.provider} nécessite encore la configuration OAuth côté serveur.`);
    });
  });
});
