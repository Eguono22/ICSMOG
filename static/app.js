/**
 * ICSMOG Web Application
 * Client-side logic for the cybersecurity dashboard
 */

// API base URL (automatically set based on current host)
const API_BASE = window.location.origin;

/**
 * Fetch and display dashboard data
 */
async function loadDashboard() {
  try {
    const response = await fetch(`${API_BASE}/cybersecurity/dashboard`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const data = await response.json();
    displayDashboard(data);
  } catch (error) {
    console.error('Failed to load dashboard:', error);
    showError('Failed to load dashboard data');
  }
}

/**
 * Display dashboard data on the page
 */
function displayDashboard(data) {
  const container = document.getElementById('dashboard-content');
  
  let html = `
    <div class="grid">
      <div class="card">
        <h3>Active Alerts</h3>
        <div class="card-value">${data.alert_count || 0}</div>
        <div class="card-meta">Total active alerts</div>
      </div>
      <div class="card">
        <h3>Critical Issues</h3>
        <div class="card-value">${data.critical_count || 0}</div>
        <div class="card-meta">Require immediate attention</div>
      </div>
      <div class="card">
        <h3>Network Events</h3>
        <div class="card-value">${data.network_event_count || 0}</div>
        <div class="card-meta">Recent 24 hours</div>
      </div>
    </div>
  `;
  
  // Display recent alerts if available
  if (data.recent_alerts && data.recent_alerts.length > 0) {
    html += `
      <h2 style="margin-top: 32px; margin-bottom: 16px;">Recent Alerts</h2>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Threat Level</th>
            <th>Source</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          ${data.recent_alerts.map(alert => `
            <tr>
              <td>${new Date(alert.timestamp).toLocaleString()}</td>
              <td><span class="status-badge ${alert.threat_level.toLowerCase()}">${alert.threat_level}</span></td>
              <td>${alert.source_ip || 'N/A'}</td>
              <td>${alert.description || 'No description'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }
  
  container.innerHTML = html;
}

/**
 * Show error message
 */
function showError(message) {
  const container = document.getElementById('dashboard-content');
  container.innerHTML = `<div class="error">${message}</div>`;
}

/**
 * Show success message
 */
function showSuccess(message) {
  const container = document.getElementById('dashboard-content');
  container.innerHTML = `<div class="success">${message}</div>`;
}

/**
 * Initialize the application
 */
document.addEventListener('DOMContentLoaded', () => {
  loadDashboard();
  // Refresh every 30 seconds
  setInterval(loadDashboard, 30000);
});
