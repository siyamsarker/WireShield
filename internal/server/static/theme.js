(function(){
  const key = 'ws-theme';
  function apply(theme){
    if(theme){ document.documentElement.setAttribute('data-theme', theme); }
    else { document.documentElement.removeAttribute('data-theme'); }
  }
  function load(){ return localStorage.getItem(key); }
  function save(t){ localStorage.setItem(key, t); }
  const btn = document.getElementById('themeToggle');
  const current = load();
  if(current){ apply(current); }
  if(btn){
    btn.addEventListener('click', function(){
      const now = document.documentElement.getAttribute('data-theme');
      const next = now === 'dark' ? 'light' : 'dark';
      apply(next);
      save(next);
    });
  }
})();