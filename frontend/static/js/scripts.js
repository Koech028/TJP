// Example: Save trade
document.getElementById('trade-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    
    const response = await fetch('/save-trade', {
        method: 'POST',
        body: formData
    });
    
    if(response.ok) {
        alert('Trade saved successfully!');
        e.target.reset();
    }
});
// Initialize performance chart
const ctx = document.getElementById('performanceChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        datasets: [{
            label: 'Portfolio Value',
            data: [12000, 12500, 13200, 12800, 14000, 14200],
            backgroundColor: 'rgba(37, 99, 235, 0.1)',
            borderColor: '#2563eb',
            borderWidth: 2
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: false
            }
        }
    }
});
// Load portfolio data
async function loadPortfolio() {
    const response = await fetch('/portfolio-data');
    const data = await response.json();
    
    document.getElementById('total-value').textContent = `$${data.total_value.toLocaleString()}`;
    document.getElementById('win-rate').textContent = `${data.win_rate}%`;
    // ... update other elements
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
    if(document.getElementById('performanceChart')) {
        initCharts();
    }
    if(document.getElementById('portfolio-section')) {
        loadPortfolio();
    }
});