// Runs before the first paint (loaded synchronously from <head>; CSP allows
// only same-origin scripts). Dark is the default even when the system is
// light; light applies only when the analyst chose it with the theme button.
(function () {
  var light = false
  try {
    light = window.localStorage.getItem('tf-theme') === 'light'
  } catch (error) {
    // Storage blocked: keep the dark default.
  }
  document.documentElement.classList.toggle('dark', !light)
})()
