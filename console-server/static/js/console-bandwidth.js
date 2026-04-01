// console-bandwidth.js — Bandwidth Insights functions

// Bandwidth Insights State
let bandwidthState = {
    currentDays: 7,
    rangeMode: 'preset',
    customDateFrom: '',
    customDateTo: '',
    chartType: 'line',
    previousData: null,
    autoRefreshInterval: null,
    selectedUser: 'all',
    eventsInitialized: false
};

// Initialize Bandwidth Event Listeners
function initBandwidthEvents() {
    if (bandwidthState.eventsInitialized) {
        return;
    }

    // Time range selector
    document.querySelectorAll('.time-range-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.time-range-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');

            if (this.dataset.days === 'custom') {
                bandwidthState.rangeMode = 'custom';
                const customRange = document.getElementById('bandwidth-custom-range');
                if (customRange) {
                    customRange.style.display = 'flex';
                }
                return;
            }

            bandwidthState.rangeMode = 'preset';
            bandwidthState.currentDays = parseInt(this.dataset.days, 10);
            bandwidthState.previousData = null;

            const customRange = document.getElementById('bandwidth-custom-range');
            if (customRange) {
                customRange.style.display = 'none';
            }

            loadBandwidthData();
        });
    });

    // Chart type toggle
    document.querySelectorAll('.chart-type-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.chart-type-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            bandwidthState.chartType = this.dataset.type;
            loadBandwidthData();
        });
    });

    bandwidthState.eventsInitialized = true;
}

function applyBandwidthCustomDate() {
    const fromInput = document.getElementById('bandwidth-date-from');
    const toInput = document.getElementById('bandwidth-date-to');
    const fromDate = fromInput ? fromInput.value : '';
    const toDate = toInput ? toInput.value : '';

    if (!fromDate || !toDate) {
        alert('Please select both start and end dates.');
        return;
    }

    if (new Date(fromDate) > new Date(toDate)) {
        alert('Start date must be before or equal to end date.');
        return;
    }

    bandwidthState.rangeMode = 'custom';
    bandwidthState.customDateFrom = fromDate;
    bandwidthState.customDateTo = toDate;
    bandwidthState.previousData = null;
    loadBandwidthData();
}

// Animated number counter
function animateNumber(element, target, duration = 1000) {
    const start = 0;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = start + (target - start) * easeOut;

        element.textContent = formatBytes(current);

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

// Update stat card with animation
function updateStatCard(id, bytes, comparison = null, badgeChange = null) {
    const element = document.getElementById(id);
    if (!element) return;

    const formatted = formatBytesAnimated(bytes);

    element.innerHTML = `
        <span class="stat-number">${formatted.value}</span>
        <span class="stat-unit">${formatted.unit}</span>
    `;

    // Update comparison if provided
    if (comparison && element.parentElement) {
        const comparisonEl = element.parentElement.querySelector('.stat-comparison .comparison-value');
        if (comparisonEl) {
            comparisonEl.textContent = comparison.text;
            comparisonEl.className = 'comparison-value ' + comparison.class;
        }
    }
}

// Load Bandwidth Data
async function loadBandwidthData(days = null) {
    const targetDays = days || bandwidthState.currentDays;

    try {
        // Show loading state
        const chartLoading = document.getElementById('bandwidth-chart-loading');
        const chartEmpty = document.getElementById('bandwidth-chart-empty');
        const chartCanvas = document.getElementById('bandwidthChart');

        if (chartLoading) chartLoading.style.display = 'flex';
        if (chartEmpty) chartEmpty.style.display = 'none';
        if (chartCanvas) chartCanvas.style.opacity = '0';

        const params = new URLSearchParams();
        const useCustomRange = bandwidthState.rangeMode === 'custom' && bandwidthState.customDateFrom && bandwidthState.customDateTo;

        if (useCustomRange) {
            params.append('start_date', bandwidthState.customDateFrom);
            params.append('end_date', bandwidthState.customDateTo);
        } else {
            params.append('days', String(targetDays));
        }

        if (bandwidthState.selectedUser !== 'all') {
            params.append('user', bandwidthState.selectedUser);
        }

        const response = await fetch(`/api/console/bandwidth-usage?${params.toString()}`, { cache: 'no-store' });
        const data = await response.json();

        // Hide loading
        if (chartLoading) chartLoading.style.display = 'none';

        // Check for empty data
        const hasTrafficData = (data.upload || []).some(v => Number(v) > 0) || (data.download || []).some(v => Number(v) > 0);
        if (!data.labels || data.labels.length === 0 || !hasTrafficData) {
            if (chartEmpty) chartEmpty.style.display = 'flex';
            if (chartCanvas) chartCanvas.style.opacity = '0';
            updateEmptyStats();
            return;
        }

        if (chartCanvas) chartCanvas.style.opacity = '1';

        // Calculate statistics
        const totalUpload = data.upload.reduce((a, b) => a + b, 0);
        const totalDownload = data.download.reduce((a, b) => a + b, 0);
        const maxUpload = Math.max(...data.upload);
        const maxDownload = Math.max(...data.download);
        const peakUsage = Math.max(maxUpload, maxDownload);
        const peakIndex = maxUpload >= maxDownload ? data.upload.indexOf(maxUpload) : data.download.indexOf(maxDownload);
        const avgSpeed = (totalUpload + totalDownload) / Math.max(data.labels.length, 1);
        const totalTraffic = totalUpload + totalDownload;

        // Calculate progress percentages
        const maxTotal = Math.max(totalUpload, totalDownload);
        const uploadProgress = maxTotal > 0 ? (totalUpload / maxTotal) * 100 : 0;
        const downloadProgress = maxTotal > 0 ? (totalDownload / maxTotal) * 100 : 0;

        // Update stats cards with animation (values are already bytes)
        updateStatCard('total-upload', totalUpload);
        updateStatCard('total-download', totalDownload);
        updateStatCard('peak-usage', peakUsage);
        updateStatCard('avg-speed', avgSpeed);

        // Update progress bars
        const uploadProgressBar = document.getElementById('upload-progress');
        const downloadProgressBar = document.getElementById('download-progress');
        if (uploadProgressBar) uploadProgressBar.style.width = uploadProgress + '%';
        if (downloadProgressBar) downloadProgressBar.style.width = downloadProgress + '%';

        // Update peak time badge
        const peakTimeBadge = document.getElementById('peak-time-badge');
        if (peakTimeBadge && peakTimeBadge.querySelector('span')) {
            peakTimeBadge.querySelector('span').textContent = data.labels[peakIndex] || '--';
        }

        // Update peak comparison
        const peakComparison = document.getElementById('peak-comparison');
        if (peakComparison) {
            const peakValue = peakComparison.querySelector('.comparison-value');
            if (peakValue) {
                peakValue.textContent = formatBytes(peakUsage);
            }
        }

        // Update chart footer summary
        const totalTrafficEl = document.getElementById('total-traffic');
        const dataPointsEl = document.getElementById('data-points');
        const avgDailyEl = document.getElementById('avg-daily');
        const lastUpdatedEl = document.getElementById('bandwidth-last-updated');

        if (totalTrafficEl) totalTrafficEl.textContent = formatBytes(totalTraffic);
        if (dataPointsEl) {
            dataPointsEl.textContent = useCustomRange
                ? `${data.labels.length} points`
                : (targetDays === 1 ? '24h' : `${data.labels.length} days`);
        }
        if (avgDailyEl) avgDailyEl.textContent = formatBytes(avgSpeed);
        if (lastUpdatedEl) lastUpdatedEl.textContent = new Date().toLocaleTimeString();

        // Calculate comparison with previous period (if available)
        if (bandwidthState.previousData) {
            updateComparison(bandwidthState.previousData, { totalUpload, totalDownload });
        }

        // Store current data for future comparison
        bandwidthState.previousData = { totalUpload, totalDownload };

        // Destroy existing chart
        if (bandwidthChart) {
            bandwidthChart.destroy();
            bandwidthChart = null;
        }

        // Create chart
        const ctx = document.getElementById('bandwidthChart').getContext('2d');
        const chartType = bandwidthState.chartType;

        // Create gradient for upload
        const uploadGradient = ctx.createLinearGradient(0, 0, 0, 300);
        uploadGradient.addColorStop(0, 'rgba(59, 130, 246, 0.3)');
        uploadGradient.addColorStop(1, 'rgba(59, 130, 246, 0.01)');

        // Create gradient for download
        const downloadGradient = ctx.createLinearGradient(0, 0, 0, 300);
        downloadGradient.addColorStop(0, 'rgba(16, 185, 129, 0.3)');
        downloadGradient.addColorStop(1, 'rgba(16, 185, 129, 0.01)');

        const chartConfig = {
            type: chartType,
            data: {
                labels: data.labels.map(label => {
                    // Format date labels
                    const date = new Date(label);
                    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                }),
                datasets: [{
                    label: 'Upload',
                    data: data.upload,
                    borderColor: '#3b82f6',
                    backgroundColor: chartType === 'line' ? uploadGradient : 'rgba(59, 130, 246, 0.8)',
                    borderWidth: chartType === 'line' ? 3 : 0,
                    fill: chartType === 'line',
                    tension: 0.4,
                    pointRadius: chartType === 'line' ? (data.labels.length > 14 ? 0 : 4) : 0,
                    pointHoverRadius: chartType === 'line' ? 6 : 0,
                    pointBackgroundColor: '#3b82f6',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: '#3b82f6',
                    pointHoverBorderWidth: 3,
                    borderRadius: chartType === 'bar' ? 6 : 0
                }, {
                    label: 'Download',
                    data: data.download,
                    borderColor: '#10b981',
                    backgroundColor: chartType === 'line' ? downloadGradient : 'rgba(16, 185, 129, 0.8)',
                    borderWidth: chartType === 'line' ? 3 : 0,
                    fill: chartType === 'line',
                    tension: 0.4,
                    pointRadius: chartType === 'line' ? (data.labels.length > 14 ? 0 : 4) : 0,
                    pointHoverRadius: chartType === 'line' ? 6 : 0,
                    pointBackgroundColor: '#10b981',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: '#10b981',
                    pointHoverBorderWidth: 3,
                    borderRadius: chartType === 'bar' ? 6 : 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                animation: {
                    duration: 750,
                    easing: 'easeOutQuart'
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        titleFont: { size: 13, weight: 600 },
                        bodyFont: { size: 12 },
                        padding: 16,
                        borderColor: 'rgba(148, 163, 184, 0.2)',
                        borderWidth: 1,
                        displayColors: true,
                        boxWidth: 12,
                        boxHeight: 12,
                        boxPadding: 4,
                        usePointStyle: true,
                        cornerRadius: 8,
                        callbacks: {
                            title: function(context) {
                                return context[0].label;
                            },
                            label: function(context) {
                                const value = context.parsed.y;
                                return ' ' + context.dataset.label + ': ' + formatBytes(value);
                            },
                            afterBody: function(context) {
                                const uploadVal = context[0].chart.data.datasets[0].data[context[0].dataIndex];
                                const downloadVal = context[0].chart.data.datasets[1].data[context[0].dataIndex];
                                const total = uploadVal + downloadVal;
                                return '\nTotal: ' + formatBytes(total);
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: true,
                            color: 'rgba(148, 163, 184, 0.08)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#64748b',
                            font: {
                                size: 11,
                                weight: 500
                            },
                            maxRotation: 45,
                            minRotation: 0
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            display: true,
                            color: 'rgba(148, 163, 184, 0.08)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#64748b',
                            font: {
                                size: 11,
                                weight: 500
                            },
                            padding: 8,
                            callback: function(value) {
                                return formatBytes(value);
                            }
                        }
                    }
                }
            }
        };

        bandwidthChart = new Chart(ctx, chartConfig);

    } catch (error) {
        console.error('Error loading bandwidth data:', error);
        const chartLoading = document.getElementById('bandwidth-chart-loading');
        const chartEmpty = document.getElementById('bandwidth-chart-empty');
        if (chartLoading) chartLoading.style.display = 'none';
        if (chartEmpty) {
            chartEmpty.style.display = 'flex';
            chartEmpty.querySelector('p').textContent = 'Error loading data. Please try again.';
        }
    }
}

// Update comparison with previous period
function updateComparison(previous, current) {
    const uploadChange = previous.totalUpload > 0
        ? ((current.totalUpload - previous.totalUpload) / previous.totalUpload * 100).toFixed(1)
        : 0;
    const downloadChange = previous.totalDownload > 0
        ? ((current.totalDownload - previous.totalDownload) / previous.totalDownload * 100).toFixed(1)
        : 0;

    // Update upload badge
    const uploadBadge = document.getElementById('upload-badge');
    if (uploadBadge) {
        const changeSpan = uploadBadge.querySelector('span');
        const arrow = uploadChange >= 0
            ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="18,15 12,9 6,15"></polyline></svg>'
            : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="6,9 12,15 18,9"></polyline></svg>';
        uploadBadge.innerHTML = arrow + '<span>' + Math.abs(uploadChange) + '%</span>';
        uploadBadge.className = 'stat-badge ' + (uploadChange >= 0 ? 'positive' : 'negative');
    }

    // Update download badge
    const downloadBadge = document.getElementById('download-badge');
    if (downloadBadge) {
        const arrow = downloadChange >= 0
            ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="18,15 12,9 6,15"></polyline></svg>'
            : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="6,9 12,15 18,9"></polyline></svg>';
        downloadBadge.innerHTML = arrow + '<span>' + Math.abs(downloadChange) + '%</span>';
        downloadBadge.className = 'stat-badge ' + (downloadChange >= 0 ? 'positive' : 'negative');
    }
}

// Update empty stats
function updateEmptyStats() {
    ['total-upload', 'total-download', 'peak-usage', 'avg-speed'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.innerHTML = '<span class="stat-number">0</span><span class="stat-unit">B</span>';
        }
    });
}

// Wrapper that maintains the onchange handler reference in the HTML template.
// The bandwidth user filter <select> uses onchange="loadBandwidthUserFilter()"
// so we keep this name as a thin wrapper around the deduplicated loadUserFilter().
function loadBandwidthUserFilter() {
    loadUserFilter('bandwidth-user-filter');
}

// Filter bandwidth data by user
function filterBandwidthByUser() {
    const select = document.getElementById('bandwidth-user-filter');
    bandwidthState.selectedUser = select.value;
    bandwidthState.previousData = null;
    loadBandwidthData();
}
