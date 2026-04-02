// console-dashboard.js — Overview/Dashboard functions

async function loadDashboardData() {
    try {
        const statsGrid = document.getElementById('stats-grid');
        // Loading skeleton
        statsGrid.innerHTML = `
            <div class="stat-card loading" style="height:104px;border-radius:12px;"></div>
            <div class="stat-card loading" style="height:104px;border-radius:12px;"></div>
            <div class="stat-card loading" style="height:104px;border-radius:12px;"></div>
            <div class="stat-card loading" style="height:104px;border-radius:12px;"></div>
        `;

        const statsResponse = await fetch('/api/console/dashboard-stats', { cache: 'no-store' });
        const stats = await statsResponse.json();

        statsGrid.innerHTML = `
            <div class="stat-card sc-users">
                <div class="stat-header">
                    <div>
                        <div class="stat-title">Total Users</div>
                        <div class="stat-value">${stats.total_users || 0}</div>
                    </div>
                    <div class="stat-icon si-users">
                        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                            <circle cx="9" cy="7" r="4"/>
                            <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-change ${(stats.new_users_24h || 0) > 0 ? 'positive' : 'neutral'}">
                    +${stats.new_users_24h || 0} last 24h
                </div>
            </div>

            <div class="stat-card sc-sessions">
                <div class="stat-header">
                    <div>
                        <div class="stat-title">Active Sessions</div>
                        <div class="stat-value">${stats.active_sessions || 0}</div>
                    </div>
                    <div class="stat-icon si-sessions">
                        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-change positive">Real-time</div>
            </div>

            <div class="stat-card sc-failed">
                <div class="stat-header">
                    <div>
                        <div class="stat-title">Failed Attempts</div>
                        <div class="stat-value">${stats.failed_attempts_24h || 0}</div>
                    </div>
                    <div class="stat-icon si-failed">
                        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-change ${(stats.failed_attempts_24h || 0) > 0 ? 'negative' : 'neutral'}">Last 24h</div>
            </div>

            <div class="stat-card sc-bandwidth">
                <div class="stat-header">
                    <div>
                        <div class="stat-title">Bandwidth</div>
                        <div class="stat-value">${formatBytes(stats.bandwidth_24h || 0)}</div>
                    </div>
                    <div class="stat-icon si-bandwidth">
                        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-change neutral">Last 24h</div>
            </div>
        `;

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
    if (activityChart) { activityChart.destroy(); }

    const ctx = document.getElementById('activityChart').getContext('2d');

    const gradBlue = ctx.createLinearGradient(0, 0, 0, 240);
    gradBlue.addColorStop(0, 'rgba(59,130,246,0.18)');
    gradBlue.addColorStop(1, 'rgba(59,130,246,0.01)');

    const gradGreen = ctx.createLinearGradient(0, 0, 0, 240);
    gradGreen.addColorStop(0, 'rgba(16,185,129,0.18)');
    gradGreen.addColorStop(1, 'rgba(16,185,129,0.01)');

    activityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(d => d.hour),
            datasets: [
                {
                    label: 'Connections',
                    data: data.map(d => d.connections),
                    borderColor: '#3b82f6',
                    backgroundColor: gradBlue,
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    yAxisID: 'y'
                },
                {
                    label: 'Active Users',
                    data: data.map(d => d.active_users),
                    borderColor: '#10b981',
                    backgroundColor: gradGreen,
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            animation: { duration: 600, easing: 'easeOutQuart' },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    align: 'end',
                    labels: {
                        boxWidth: 10,
                        boxHeight: 10,
                        padding: 16,
                        font: { size: 11, weight: 600 },
                        color: '#64748b',
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15,23,42,0.92)',
                    titleColor: '#fff',
                    bodyColor: '#cbd5e1',
                    borderColor: 'rgba(255,255,255,0.08)',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                    callbacks: {
                        label: ctx => `  ${ctx.dataset.label}: ${ctx.parsed.y}`
                    }
                }
            },
            scales: {
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    beginAtZero: true,
                    grid: { color: 'rgba(148,163,184,0.08)', drawBorder: false },
                    ticks: { color: '#94a3b8', font: { size: 10 }, maxTicksLimit: 5, padding: 6 }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    beginAtZero: true,
                    grid: { drawOnChartArea: false, drawBorder: false },
                    ticks: { color: '#94a3b8', font: { size: 10 }, maxTicksLimit: 5, padding: 6 }
                },
                x: {
                    grid: { color: 'rgba(148,163,184,0.06)', drawBorder: false },
                    ticks: {
                        color: '#94a3b8',
                        font: { size: 10 },
                        maxRotation: 0,
                        autoSkip: true,
                        maxTicksLimit: 10
                    }
                }
            }
        }
    });
}

function loadActionsChart(data) {
    if (actionsChart) { actionsChart.destroy(); }

    const ctx = document.getElementById('actionsChart').getContext('2d');
    const colors = ['#3b82f6','#10b981','#f59e0b','#f43f5e','#8b5cf6','#06b6d4','#84cc16'];
    const total  = data.reduce((s, d) => s + d.count, 0);

    actionsChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(d => d.action),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: colors.slice(0, data.length),
                borderWidth: 0,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '68%',
            animation: { duration: 600, easing: 'easeOutQuart' },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        boxWidth: 8,
                        boxHeight: 8,
                        padding: 10,
                        font: { size: 10.5, weight: 600 },
                        color: '#64748b',
                        usePointStyle: true,
                        pointStyle: 'rectRounded'
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15,23,42,0.92)',
                    titleColor: '#fff',
                    bodyColor: '#cbd5e1',
                    borderColor: 'rgba(255,255,255,0.08)',
                    borderWidth: 1,
                    padding: 10,
                    cornerRadius: 8,
                    callbacks: {
                        label: ctx => {
                            const pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
                            return `  ${ctx.label}: ${ctx.parsed} (${pct}%)`;
                        }
                    }
                }
            }
        },
        plugins: [{
            // Center text: total events
            id: 'centerText',
            afterDraw(chart) {
                const { ctx: c, chartArea: { top, bottom, left, right } } = chart;
                const cx = (left + right) / 2;
                const cy = (top + bottom) / 2;
                c.save();
                c.textAlign = 'center';
                c.textBaseline = 'middle';
                c.fillStyle = '#0f172a';
                c.font = 'bold 20px Inter, system-ui, sans-serif';
                c.fillText(total, cx, cy - 7);
                c.fillStyle = '#94a3b8';
                c.font = '10px Inter, system-ui, sans-serif';
                c.fillText('EVENTS', cx, cy + 9);
                c.restore();
            }
        }]
    });
}

function loadRecentEvents(events) {
    const tbody = document.getElementById('recent-events');
    if (!events || events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px 0;">No recent events</td></tr>`;
        return;
    }

    function statusPill(s) {
        const cls = getStatusClass(s);
        return `<span class="status-pill ${cls}">${s}</span>`;
    }

    function fmtTime(ts) {
        const d = new Date(ts);
        return d.toLocaleString(undefined, {
            month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    }

    tbody.innerHTML = events.map(ev => `
        <tr>
            <td style="color:var(--text-muted);font-size:12px;">${fmtTime(ev.timestamp)}</td>
            <td style="font-weight:600;">${ev.client_id || 'System'}</td>
            <td><span class="action-chip">${ev.action}</span></td>
            <td>${statusPill(ev.outcome || ev.status)}</td>
            <td><span class="ip-text">${ev.ip_address}</span></td>
        </tr>
    `).join('');
}
