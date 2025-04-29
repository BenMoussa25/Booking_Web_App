// Add any interactive functionality here
document.addEventListener('DOMContentLoaded', function() {
    // Add any JavaScript functionality you need
    console.log('CyberSphere Congress app loaded');
    
    // Example: Add active class to current nav link
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
    
    // Add animations or other interactive elements
    const eventCards = document.querySelectorAll('.event-card, .event-item');
    
    eventCards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-5px)';
            card.style.boxShadow = '0 10px 25px rgba(0, 255, 157, 0.1)';
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = '';
            card.style.boxShadow = '';
        });
    });
});