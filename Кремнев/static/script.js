document.querySelectorAll('form.js-confirm').forEach(function (form) {
  form.addEventListener('submit', function (e) {
    if (!confirm('Удалить эту запись?')) {
      e.preventDefault();
    }
  });
});

setTimeout(function () {
  document.querySelectorAll('.flash').forEach(function (el) {
    el.style.transition = 'opacity .4s, transform .4s';
    el.style.opacity = '0';
    el.style.transform = 'translateY(-6px)';
    setTimeout(function () { el.remove(); }, 400);
  });
}, 4000);