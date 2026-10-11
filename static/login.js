document.getElementById('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  const error = document.getElementById('login-error');
  error.hidden = true;
  const form = event.target;
  const response = await fetch('/api/v1/auth/login', {method: 'POST', headers: {'Content-Type': 'application/json',
    'X-Aegis-CSRF': document.querySelector('meta[name="csrf-token"]').content},
    body: JSON.stringify({username: form.username.value, password: form.password.value})});
  if (response.ok) { window.location.assign('/'); return; }
  const data = await response.json().catch(() => ({}));
  error.textContent = data.error || 'Sign-in failed.';
  error.hidden = false;
  form.password.value = '';
});
