// ============================================================================
// DARK MODE - Script externe pour toutes les pages
// Fichier : static/dark-mode.js
// ============================================================================

(function() {
    'use strict';
    
    // Créer le bouton Dark Mode au chargement
    function createDarkModeButton() {
        // Vérifier si le bouton n'existe pas déjà
        if (document.getElementById('darkModeToggle')) {
            return;
        }
        
        // Créer le bouton
        const button = document.createElement('button');
        button.className = 'dark-mode-toggle';
        button.id = 'darkModeToggle';
        button.title = 'Basculer mode jour/nuit';
        
        // Créer les icônes
        const sunIcon = document.createElement('i');
        sunIcon.className = 'fas fa-sun';
        
        const moonIcon = document.createElement('i');
        moonIcon.className = 'fas fa-moon';
        
        // Ajouter les icônes au bouton
        button.appendChild(sunIcon);
        button.appendChild(moonIcon);
        
        // Ajouter le bouton au body
        document.body.insertBefore(button, document.body.firstChild);
        
        return button;
    }
    
    // Initialiser le dark mode
    function initDarkMode() {
        const body = document.body;
        const toggleButton = createDarkModeButton();
        
        // Charger la préférence sauvegardée
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            body.classList.add('dark-mode');
        }
        
        // Gérer le clic sur le bouton
        if (toggleButton) {
            toggleButton.addEventListener('click', function() {
                body.classList.toggle('dark-mode');
                
                // Sauvegarder la préférence
                if (body.classList.contains('dark-mode')) {
                    localStorage.setItem('theme', 'dark');
                } else {
                    localStorage.setItem('theme', 'light');
                }
            });
        }
        
        // Raccourci clavier : Ctrl + D
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'd') {
                e.preventDefault();
                if (toggleButton) {
                    toggleButton.click();
                }
            }
        });
    }
    
    // Attendre que le DOM soit chargé
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initDarkMode);
    } else {
        initDarkMode();
    }
})();
