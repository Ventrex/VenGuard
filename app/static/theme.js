// Runs before CSS: the default is dark, without a bright first-frame flash.
(function(){
 let theme='dark';try{theme=localStorage.getItem('venguard-theme')==='light'?'light':'dark';}catch{}
 function apply(next){theme=next;document.documentElement.dataset.theme=theme;document.querySelectorAll('[data-theme-toggle]').forEach(b=>{b.textContent=theme==='dark'?'☀ Light mode':'☾ Dark mode';b.setAttribute('aria-label',theme==='dark'?'Light mode inschakelen':'Dark mode inschakelen');});}
 apply(theme);
 document.addEventListener('DOMContentLoaded',()=>apply(theme));
 document.addEventListener('click',e=>{if(!e.target.closest('[data-theme-toggle]'))return;apply(theme==='dark'?'light':'dark');try{localStorage.setItem('venguard-theme',theme);}catch{}});
})();
