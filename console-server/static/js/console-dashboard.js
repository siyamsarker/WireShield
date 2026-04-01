// console-dashboard.js — Overview/Dashboard functions

async function loadDashboardData() {
    try {
        // Show loading shimmer
        const statsGrid = document.getElementById('stats-grid');
        statsGrid.innerHTML = `
            <div class="stat-card loading" style="height: 140px;"></div>
            <div class="stat-card loading" style="height: 140px;"></div>
            <div class="stat-card loading" style="height: 140px;"></div>
            <div class="stat-card loading" style="height: 140px;"></div>
        `;

        // Load stats
        const statsResponse = await fetch('/api/console/dashboard-stats', { cache: 'no-store' });
        const stats = await statsResponse.json();
        statsGrid.innerHTML = `
            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-title">Total Users</span>
                    <div class="stat-icon" style="background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);">
                        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                            <circle cx="12" cy="7" r="4"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-value">${stats.total_users || 0}</div>
                <div class="stat-change positive">+${stats.new_users_24h || 0} last 24h</div>
            </div>
            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-title">Active Sessions</span>
                    <div class="stat-icon" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%);">
                        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <circle cx="12" cy="12" r="10"/>
                            <polyline points="12,6 12,12 16,14"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-value">${stats.active_sessions || 0}</div>
                <div class="stat-change positive">Real-time</div>
            </div>
            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-title">Failed Attempts</span>
                    <div class="stat-icon" style="background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);">
                        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="15" y1="9" x2="9" y2="15"/>
                            <line x1="9" y1="9" x2="15" y2="15"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-value">${stats.failed_attempts_24h || 0}</div>
                <div class="stat-change negative">Last 24h</div>
            </div>
            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-title">Bandwidth</span>
                    <div class="stat-icon" style="background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);">
                        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <line x1="18" y1="20" x2="18" y2="10"/>
                            <line x1="12" y1="20" x2="12" y2="4"/>
                            <line x1="6" y1="20" x2="6" y2="14"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-value">${formatBytes(stats.bandwidth_24h || 0)}</div>
                <div class="stat-change positive">Last 24h</div>
            </div>
        `;

        // Load charts
        const chartsResponse = await fetch('/api/console/dashboard-charts', { cache: 'no-store' });
        const charts = await chartsResponse.json();

        loadActivityChart(charts.activity_trend);
        loadActionsChart(charts.action_distribution);
        loadRecentEvents(charts.recent_events);

    } catch (error) {
        console.error('Error loading dashboard data:', error);
    }
}

function loadActivityChart(data) {
    if (activityChart) {
        activityChart.destroy();
    }

    const ctx = document.getElementById('activityChart').getContext('2d');
    activityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(d => d.hour),
            datasets: [
                {
                    label: 'Connections',
                    data: data.map(d => d.connections),
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    tension: 0.4,
                    fill: true,
                    yAxisID: 'y'
                },
                {
                    label: 'Active Users',
                    data: data.map(d => d.active_users),
                    borderColor: '#16a34a',
                    backgroundColor: 'rgba(22, 163, 74, 0.1)',
                    tension: 0.4,
                    fill: true,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            scales: {
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Connections'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    beginAtZero: true,
                    grid: {
                        drawOnChartArea: false
                    },
                    title: {
                        display: true,
                        text: 'Users'
                    }
                },
                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45,
                        autoSkip: true,
                        maxTicksLimit: 12
                    }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return context.dataset.label + ': ' + context.parsed.y;
                        }
                    }
                }
            }
        }
    });
}

function loadActionsChart(data) {
    if (actionsChart) {
        actionsChart.destroy();
    }

    const ctx = document.getElementById('actionsChart').getContext('2d');
    actionsChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(d => d.action),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: [
                    '#2563eb',
                    '#16a34a',
                    '#ca8a04',
                    '#dc2626',
                    '#7c3aed'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

function loadRecentEvents(events) {
    const tbody = document.getElementById('recent-events');
    if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:40px;">No recent events found</td></tr>';
        return;
    }
    tbody.innerHTML = events.map(event => `
        <tr>
            <td>${new Date(event.timestamp).toLocaleString()}</td>
            <td>${event.client_id || 'System'}</td>
            <td>${event.action}</td>
            <td>
                <span style="color: ${getStatusColor(event.outcome || event.status)}">
                    ${event.outcome || event.status}
                </span>
            </td>
            <td>${event.ip_address}</td>
        </tr>
    `).join('');
}
