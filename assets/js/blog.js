// Blog search and filter functionality
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchInput');
    const filterTags = document.querySelectorAll('.filter-tag');
    const postCards = document.querySelectorAll('.post-card');
    const noResults = document.getElementById('noResults');
    const postsGrid = document.getElementById('postsGrid');
    
    let currentFilter = 'all';
    
    // Search functionality
    if (searchInput) {
        searchInput.addEventListener('input', filterPosts);
    }
    
    // Filter tag functionality
    filterTags.forEach(tag => {
        tag.addEventListener('click', () => {
            // Remove active class from all tags
            filterTags.forEach(t => t.classList.remove('active'));
            // Add active class to clicked tag
            tag.classList.add('active');
            // Update current filter
            currentFilter = tag.dataset.filter;
            // Filter posts
            filterPosts();
        });
    });
    
    function filterPosts() {
        const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
        let visibleCount = 0;
        
        postCards.forEach(card => {
            const title = card.querySelector('.post-title a').textContent.toLowerCase();
            const excerpt = card.querySelector('.post-excerpt').textContent.toLowerCase();
            const tags = card.dataset.tags.toLowerCase();
            
            // Check search match
            const matchesSearch = title.includes(searchTerm) || 
                                excerpt.includes(searchTerm) || 
                                tags.includes(searchTerm);
            
            // Check filter match
            const matchesFilter = currentFilter === 'all' || 
                                tags.includes(currentFilter.toLowerCase());
            
            // Show/hide card
            if (matchesSearch && matchesFilter) {
                card.style.display = 'flex';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });
        
        // Show/hide no results message
        if (noResults) {
            if (visibleCount === 0) {
                postsGrid.style.display = 'none';
                noResults.style.display = 'block';
            } else {
                postsGrid.style.display = 'grid';
                noResults.style.display = 'none';
            }
        }
    }
});