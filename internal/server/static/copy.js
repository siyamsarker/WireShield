document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-copy-target]');
  if (!btn) return;
  const sel = btn.getAttribute('data-copy-target');
  const node = document.querySelector(sel);
  if (!node) return;
  let text = '';
  if (node.tagName === 'PRE' || node.tagName === 'CODE') {
    text = node.innerText;
  } else if ('value' in node) {
    text = node.value;
  } else {
    text = node.textContent || '';
  }
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'Copied!';
    setTimeout(() => (btn.textContent = 'Copy to clipboard'), 1500);
  } catch (err) {
    console.error('Copy failed', err);
  }
});
