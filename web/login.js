document.getElementById('loginTheme').onclick = () => {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('agentflow.theme.v3', next);
};

const $ = id => document.getElementById(id);
const t = window.lfT || ((zh) => zh);
let mode = 'login', iamProvider = '', iamEnabled = false, otherLoginOpen = false;
let iamError = new URLSearchParams(location.search).get('iam_error') || '';

if (iamError) {
  const params = new URLSearchParams(location.search);
  params.delete('iam_error');
  const query = params.toString();
  try { history.replaceState({}, document.title, location.pathname + (query ? '?' + query : '') + location.hash); } catch {}
}

function iamErrorMessage(code) {
  switch (code) {
    case 'config': return t('IAM 登录尚未配置，请联系管理员', 'IAM sign-in is not configured. Contact an administrator.');
    case 'access_denied': return t('已取消 IAM 登录', 'IAM sign-in was cancelled.');
    case 'state': return t('登录请求已过期，请重试', 'The sign-in request expired. Try again.');
    case 'provider': return t('IAM 服务暂时不可用，请稍后重试', 'IAM is unavailable. Try again later.');
    case 'profile': return t('无法读取 IAM 账号信息，请联系管理员', 'Could not read your IAM profile. Contact an administrator.');
    case 'signup_disabled': return t('账号尚未开通，请联系管理员', 'Your account is not provisioned. Contact an administrator.');
    case 'login_conflict': return t('登录名刚被其他请求占用，请重试', 'The login name was just taken by another request. Try again.');
    case 'account_linked': return t('该账号已绑定其他 IAM 身份，请联系管理员', 'This account is already linked to a different IAM identity. Contact an administrator.');
    case 'link_disabled': return t('该账号尚未开通 IAM 登录，请联系管理员', 'IAM sign-in is not enabled for this account. Contact an administrator.');
    case 'account_missing': return t('账号状态异常，请联系管理员', 'Your account is unavailable. Contact an administrator.');
    case 'provision_failed': return t('创建平台账号失败，请联系管理员', 'Could not create your platform account. Contact an administrator.');
    default: return t('IAM 登录失败，请重试', 'IAM sign-in failed. Try again.');
  }
}

function renderIAM() {
  if (!iamProvider) return;
  $('iamLogin').textContent = t(`使用 ${iamProvider} 登录`, `Continue with ${iamProvider}`);
}

function render() {
  const setup = mode === 'setup';
  const showPassword = setup || !iamEnabled || otherLoginOpen;
  $('loginSubtitle').textContent = setup ? t('创建管理员账号', 'Create the administrator account') : t('登录你的交付工作台', 'Sign in to your delivery workspace');
  $('setupNotice').hidden = !setup;
  $('confirmField').hidden = !setup;
  $('passwordRule').hidden = !setup;
  $('loginForm').elements.confirm.required = setup;
  $('loginForm').elements.password.autocomplete = setup ? 'new-password' : 'current-password';
  $('loginSubmit').textContent = setup ? t('创建并进入', 'Create and continue') : t('登录', 'Sign in');
  $('loginForm').hidden = !showPassword;
  $('iamLogin').hidden = !iamEnabled;
  $('otherLoginToggle').hidden = setup || !iamEnabled;
  $('otherLoginToggle').setAttribute('aria-expanded', String(otherLoginOpen));
  $('otherLoginToggle').textContent = otherLoginOpen
    ? t('收起其他登录方式', 'Hide other sign-in options')
    : t('其他登录方式', 'Other sign-in options');
  $('loginContact').hidden = setup;
  $('loginError').textContent = iamError ? iamErrorMessage(iamError) : '';
  renderIAM();
}

$('iamLogin').onclick = () => {
  const target = new URLSearchParams(location.search).get('return_url');
  location.href = '/api/auth/iam/start' + (target ? '?return_url=' + encodeURIComponent(target) : '');
};

$('otherLoginToggle').onclick = () => {
  otherLoginOpen = !otherLoginOpen;
  render();
};

Promise.all([
  fetch('/api/auth/setup')
    .then(response => response.ok ? response.json() : null)
    .catch(() => null),
  fetch('/api/auth/iam')
    .then(response => response.ok ? response.json() : null)
    .catch(() => null),
]).then(([setupState, iamState]) => {
  if (iamState && iamState.enabled) {
    iamEnabled = true;
    iamProvider = iamState.displayName || 'IAM';
  }
  if (setupState && setupState.needsSetup) mode = 'setup';
  render();
});

$('loginForm').onsubmit = async event => {
  event.preventDefault();
  const form = event.currentTarget, button = $('loginSubmit'), error = $('loginError');
  const setup = mode === 'setup';
  if (setup && form.elements.password.value !== form.elements.confirm.value) {
    error.textContent = t('两次输入的密码不一致', 'Passwords do not match');
    return;
  }
  button.disabled = true;
  error.textContent = '';
  try {
    const response = await fetch(setup ? '/api/auth/register' : '/api/auth/password', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({login: form.elements.login.value.trim(), password: form.elements.password.value}),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || t('操作失败', 'Request failed'));
    location.replace('/');
  } catch (err) { error.textContent = err.message; button.disabled = false; }
};
