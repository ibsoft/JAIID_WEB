/*!
* Start Bootstrap - Simple Sidebar v6.0.6 (https://startbootstrap.com/template/simple-sidebar)
* Copyright 2013-2023 Start Bootstrap
* Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-simple-sidebar/blob/master/LICENSE)
*/
// 
// Scripts
// 

window.addEventListener('DOMContentLoaded', event => {
    // Toggle the side navigation
    const sidebarToggle = document.body.querySelector('#sidebarToggle');
    if (sidebarToggle) {
        // Uncomment Below to persist sidebar toggle between refreshes
         if (localStorage.getItem('sb|sidebar-toggle') === 'true') {
             document.body.classList.toggle('sb-sidenav-toggled');
         }
        sidebarToggle.addEventListener('click', event => {
            event.preventDefault();
            document.body.classList.toggle('sb-sidenav-toggled');
            localStorage.setItem('sb|sidebar-toggle', document.body.classList.contains('sb-sidenav-toggled'));
        });
    }
});

$(document).ready(function() {
               
    // Initialize Bootstrap Switch
    $('#theme-toggle').bootstrapSwitch();

    // Get the theme toggle switch element
    var themeToggle = document.getElementById('theme-toggle');

    // Function to apply the dark theme
    function applyDarkTheme() {
        $('body').removeClass('light-theme').addClass('dark-theme');
        $('.modal-content').removeClass('light-theme').addClass('dark-theme');
        $('#theme-style').attr('href', '/static/css/dark.css'); // Replace with the path to your dark theme CSS file
    }

    // Function to apply the light theme
    function applyLightTheme() {
        $('body').removeClass('dark-theme').addClass('light-theme');
        $('.modal-content').removeClass('dark-theme').addClass('light-theme');
        $('#theme-style').attr('href', 'http://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css');
    }

    // Function to save the theme preference in localStorage
    function saveThemePreference(isDarkTheme) {
        localStorage.setItem('darkThemePreferred', isDarkTheme);
    }

    // Event listener for theme toggle switch change
    $('#theme-toggle').on('switchChange.bootstrapSwitch', function(event, state) {
        if (state) {
            applyDarkTheme();
            saveThemePreference(true);
        } else {
            applyLightTheme();
            saveThemePreference(false);
        }
    });

    // Apply the saved theme preference if available
    var savedThemePreference = localStorage.getItem('darkThemePreferred');
    if (savedThemePreference === 'true') {
        $('#theme-toggle').bootstrapSwitch('state', true);
        applyDarkTheme();
    } else {
        $('#theme-toggle').bootstrapSwitch('state', false);
        applyLightTheme();
    }
});

 // Show/hide the "Go to Top" button based on the scroll position
 $(window).scroll(function () {
    if ($(this).scrollTop() > 100) {
      $('#goToTopBtn').fadeIn();
    } else {
      $('#goToTopBtn').fadeOut();
    }
  });

  // Scroll to the top of the page when the button is clicked
  function goToTop() {
    $('html, body').animate({ scrollTop: 0 }, 'slow');
  }