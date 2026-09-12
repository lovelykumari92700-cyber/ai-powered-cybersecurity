// AEGIS Cybersecurity SaaS Dashboard Logic

document.addEventListener('DOMContentLoaded', function () {
    // Current Active Tab Panel State
    let activePanel = 'dashboard';
    
    // Chart References
    let scamDistributionChart = null;
    let threatTrendsChart = null;
    let monthlyLogsChart = null;
    let adminWorkloadChart = null;
    
    // Cache Elements
    const sidebarItems = document.querySelectorAll('.sidebar-menu li');
    const panels = document.querySelectorAll('.panel');
    const topbarTitle = document.getElementById('topbar-title-text');
    
    // Mobile Sidebar Toggle
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.querySelector('.sidebar');
    
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('sidebar-open');
        });
        
        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', function(event) {
            const isClickInside = sidebar.contains(event.target) || sidebarToggle.contains(event.target);
            if (!isClickInside && window.innerWidth < 992) {
                sidebar.classList.remove('sidebar-open');
            }
        });
    }
    
    // Initialize tooltips
    let tooltipList = [];
    function refreshTooltips() {
        // Dispose old tooltips
        tooltipList.forEach(t => t.dispose());
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltipList = [...tooltipTriggerList].map(el => new bootstrap.Tooltip(el));
    }

    // Tab Navigation Switcher
    sidebarItems.forEach(item => {
        item.addEventListener('click', function (e) {
            // Allow default behavior for logout
            if (this.classList.contains('mt-auto')) return;
            
            e.preventDefault();
            const targetPanel = this.getAttribute('data-panel');
            switchTab(targetPanel);
            
            // Auto close on mobile
            if (window.innerWidth < 992 && sidebar) {
                sidebar.classList.remove('sidebar-open');
            }
        });
    });

    // Landing Page CTAs
    document.querySelectorAll('.btn-trigger-scan').forEach(btn => {
        btn.addEventListener('click', function () {
            const target = this.getAttribute('data-target');
            switchTab(target);
        });
    });

    function switchTab(panelId) {
        if (!panelId) return;
        
        // Update sidebar active classes
        sidebarItems.forEach(item => {
            if (item.getAttribute('data-panel') === panelId) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });

        // Toggle visibility of panels
        panels.forEach(p => {
            if (p.id === `panel-${panelId}`) {
                p.classList.add('active');
            } else {
                p.classList.remove('active');
            }
        });

        // Set Topbar Title
        let titleText = 'Dashboard Overview';
        let titleIcon = 'fa-chart-line';
        
        if (panelId === 'text-scam') {
            titleText = 'Scam & Fraud Text Analyzer';
            titleIcon = 'fa-envelope-open-text';
        } else if (panelId === 'url-phishing') {
            titleText = 'URL Phishing Detection';
            titleIcon = 'fa-link';
        } else if (panelId === 'ml-intelligence') {
            titleText = 'Threat Intelligence Core';
            titleIcon = 'fa-brain';
            loadMLMetrics();
        } else if (panelId === 'history') {
            titleText = 'Scans History Log';
            titleIcon = 'fa-clock-rotate-left';
            loadHistory();
        } else if (panelId === 'admin-console') {
            titleText = 'Administration Console';
            titleIcon = 'fa-user-shield';
            loadAdminPanel();
        }

        topbarTitle.innerHTML = `<i class="fa-solid ${titleIcon}"></i> ${titleText}`;
        activePanel = panelId;

        // Force chart resize/renders if switching to dashboard
        if (panelId === 'dashboard') {
            loadDashboardStats();
        }
    }

    // --- Circular Gauge Animation Helper ---
    function updateGauge(fillId, textId, score, colorClass) {
        const fillElement = document.getElementById(fillId);
        const textElement = document.getElementById(textId);
        if (!fillElement || !textElement) return;
        
        // Gauge Radius is 70, Circumference is 2 * PI * 70 = ~439.8 (we use 440)
        const circumference = 440;
        const offset = circumference - (score / 100) * circumference;
        
        fillElement.style.strokeDashoffset = offset;
        textElement.innerText = `${score}%`;

        // Update colors based on threat colors
        let colorHex = 'var(--color-emerald)';
        if (colorClass === 'safe') colorHex = 'var(--color-emerald)';
        else if (colorClass === 'low') colorHex = 'var(--color-cyan)';
        else if (colorClass === 'medium') colorHex = 'var(--color-amber)';
        else if (colorClass === 'high') colorHex = 'var(--color-crimson)';
        else if (colorClass === 'critical') colorHex = 'var(--color-crimson)';
        
        fillElement.style.stroke = colorHex;
    }

    // Map Threat Level to Class style
    function getThreatClass(threatLevel) {
        switch (threatLevel) {
            case 'Safe': return 'safe';
            case 'Low Risk': return 'low';
            case 'Medium Risk': return 'medium';
            case 'High Risk': return 'high';
            case 'Critical Risk': return 'critical';
            default: return 'low';
        }
    }

    // --- SCAM TEXT ANALYZER MODULE ---
    const btnAnalyzeText = document.getElementById('btn-analyze-text');
    const textInput = document.getElementById('text-scam-input');
    const mlModelSelect = document.getElementById('select-ml-model');
    
    if (btnAnalyzeText) {
        btnAnalyzeText.addEventListener('click', function () {
            const text = textInput.value;
            if (!text.trim()) {
                alert('Please input a suspicious message before running details.');
                return;
            }
            
            // Show loading state
            document.getElementById('text-scam-initial-state').classList.add('d-none');
            document.getElementById('text-scam-results').classList.add('d-none');
            document.getElementById('text-scam-loading').classList.remove('d-none');
            
            fetch('/api/analyze/text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    text: text,
                    model: mlModelSelect.value
                })
            })
            .then(res => { if(res.status === 401) { window.location.href = '/login'; throw new Error('Unauthorized'); } return res.json(); })
            .then(data => {
                document.getElementById('text-scam-loading').classList.add('d-none');
                document.getElementById('text-scam-results').classList.remove('d-none');
                
                // Set text outputs
                document.getElementById('text-predicted-category').innerText = data.category;
                document.getElementById('text-confidence-score').innerText = `${data.confidence}%`;
                document.getElementById('text-model-selected').innerText = mlModelSelect.value;
                document.getElementById('text-highlighted-output').innerHTML = data.highlighted_text;
                
                // Threat badges
                const badge = document.getElementById('text-threat-badge');
                badge.innerText = data.threat_level;
                badge.className = `threat-level-badge ${getThreatClass(data.threat_level)}`;
                
                // Circular Gauge
                updateGauge('text-gauge-fill', 'text-risk-score', data.risk_score, getThreatClass(data.threat_level));
                
                // Red flags breakdown
                const flagsList = document.getElementById('text-flags-list');
                const noFlagsMsg = document.getElementById('text-no-flags');
                flagsList.innerHTML = '';
                
                if (data.red_flags && data.red_flags.length > 0) {
                    noFlagsMsg.classList.add('d-none');
                    data.red_flags.forEach(flag => {
                        const item = document.createElement('div');
                        item.className = 'flag-tag-item';
                        item.innerHTML = `
                            <div class="flag-tag-title">${flag.name}</div>
                            <div class="flag-tag-desc">${flag.description}</div>
                        `;
                        flagsList.appendChild(item);
                    });
                } else {
                    noFlagsMsg.classList.remove('d-none');
                }
                
                // Recommendations
                const recsList = document.getElementById('text-recommendations');
                recsList.innerHTML = '';
                data.recommendations.forEach(rec => {
                    const li = document.createElement('li');
                    li.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> <span>${rec}</span>`;
                    recsList.appendChild(li);
                });
                
                refreshTooltips();
            })
            .catch(err => {
                console.error("Text analysis failed:", err);
                document.getElementById('text-scam-loading').classList.add('d-none');
                document.getElementById('text-scam-initial-state').classList.remove('d-none');
                alert('Analysis failed. Check backend console details.');
            });
        });
    }

    // Templates loader helper
    window.loadPreset = function (type) {
        const presets = {
            'otp': "Your OTP code for verification is 982173. Never share this code with anyone claiming to call from bank security.",
            'bank': "BANK SUSPENSION WARNING: Your debit card has been temporarily blocked due to suspect activity. Please log in at http://chase-security-verify.com to confirm identity.",
            'job': "Immediate opening! Work part-time from home evaluating apps and earn $300 to $1000 daily! No experience required. Text recruiter on WhatsApp: http://easy-whatsapp-apply.net",
            'investment': "Guarantee profits! Invest $100 in our new automatic Bitcoin mining bot and get $5000 payouts weekly. Risk free. Sign up http://double-bitcoin-fast.com",
            'lottery': "Congratulations! Your mobile number won the second prize in the annual mega draw of £500,000! Contact prize-claim@mega-raffle.co.uk to register details.",
            'safe': "Hey John, are we still meeting tomorrow morning at 10 AM for the project design review? I will send over the Zoom coordinates shortly. Best, Sarah."
        };
        if (textInput && presets[type]) {
            textInput.value = presets[type];
        }
    };

    // --- URL PHISHING SCANNER MODULE ---
    const btnAnalyzeUrl = document.getElementById('btn-analyze-url');
    const urlInput = document.getElementById('url-phishing-input');
    
    if (btnAnalyzeUrl) {
        btnAnalyzeUrl.addEventListener('click', function () {
            const url = urlInput.value;
            if (!url.trim()) {
                alert('Please input a target website URL coordinate.');
                return;
            }
            
            // Show loading state
            document.getElementById('url-initial-state').classList.add('d-none');
            document.getElementById('url-results').classList.add('d-none');
            document.getElementById('url-loading').classList.remove('d-none');
            
            fetch('/api/analyze/url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            })
            .then(res => { if(res.status === 401) { window.location.href = '/login'; throw new Error('Unauthorized'); } return res.json(); })
            .then(data => {
                document.getElementById('url-loading').classList.add('d-none');
                document.getElementById('url-results').classList.remove('d-none');
                
                // Set text outputs
                document.getElementById('url-verdict').innerText = data.verdict;
                document.getElementById('url-safety-score').innerText = `${100 - data.risk_score}%`;
                document.getElementById('url-confidence').innerText = `${data.confidence}%`;
                document.getElementById('url-explanation').innerText = data.explanation;
                
                // Threat badges
                const badge = document.getElementById('url-threat-badge');
                badge.innerText = data.threat_level;
                badge.className = `threat-level-badge ${getThreatClass(data.threat_level)}`;
                
                // Circular Gauge
                updateGauge('url-gauge-fill', 'url-risk-score', data.risk_score, getThreatClass(data.threat_level));
                
                // Indicators breakdown
                const indicatorsList = document.getElementById('url-indicators-list');
                const noIndicatorsMsg = document.getElementById('url-no-indicators');
                indicatorsList.innerHTML = '';
                
                if (data.indicators && data.indicators.length > 0) {
                    noIndicatorsMsg.classList.add('d-none');
                    data.indicators.forEach(ind => {
                        const item = document.createElement('div');
                        item.className = 'url-indicator-card';
                        
                        let severityClass = 'low';
                        if (ind.severity.toLowerCase() === 'high') severityClass = 'high';
                        else if (ind.severity.toLowerCase() === 'medium') severityClass = 'medium';
                        
                        item.innerHTML = `
                            <span class="url-indicator-badge ${severityClass}">${ind.severity}</span>
                            <div class="url-indicator-content">
                                <h5>${ind.name}</h5>
                                <p>${ind.desc}</p>
                            </div>
                        `;
                        indicatorsList.appendChild(item);
                    });
                } else {
                    noIndicatorsMsg.classList.remove('d-none');
                }
                
                // Recommendations for URLs
                const recsList = document.getElementById('url-recommendations');
                recsList.innerHTML = '';
                
                let urlRecs = [];
                if (data.verdict === 'Phishing' || data.verdict === 'Suspicious') {
                    urlRecs = [
                        "Do not input usernames, passwords, card numbers or OTP pins on this domain.",
                        "Check domain registrar credentials. Safe banking domains are registered for several years, while phishing sites are hours old.",
                        "Inspect for unicode homoglyph lookalikes (e.g. paying attention to special letters like 'ȧ' instead of 'a').",
                        "Avoid following redirection strings from shortening links."
                    ];
                } else {
                    urlRecs = [
                        "This URL structure displays standard security behaviors.",
                        "Always verify that web elements have legitimate locks in the browser address bar.",
                        "Double check the domain address if accessed through links from untrusted sender emails."
                    ];
                }
                
                urlRecs.forEach(rec => {
                    const li = document.createElement('li');
                    li.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> <span>${rec}</span>`;
                    recsList.appendChild(li);
                });
            })
            .catch(err => {
                console.error("URL analysis failed:", err);
                document.getElementById('url-loading').classList.add('d-none');
                document.getElementById('url-initial-state').classList.remove('d-none');
                alert('Analysis failed. Check connection.');
            });
        });
    }

    // URL presets loader
    window.loadUrlPreset = function (url) {
        if (urlInput) {
            urlInput.value = url;
        }
    };

    // --- DASHBOARD CHARTS & DATA LOAD ---
    function loadDashboardStats() {
        fetch('/api/dashboard/stats')
        .then(res => { if(res.status === 401) { window.location.href = '/login'; throw new Error('Unauthorized'); } return res.json(); })
        .then(data => {
            // Update Dashboard cards
            document.getElementById('dash-total-scans').innerText = data.total_scans;
            document.getElementById('dash-total-threats').innerText = data.high_threats_count;
            document.getElementById('dash-avg-risk').innerText = `${data.avg_risk_score}%`;
            
            // Build Charts
            renderScamCategoryChart(data.scans_by_category);
            renderThreatTrendsChart(data.scans_by_threat);
            renderMonthlyLogsChart();
        })
        .catch(err => console.error("Error loading dashboard stats:", err));
    }

    // 1. Scam Category Distribution Chart (Pie/Doughnut)
    function renderScamCategoryChart(categoryData) {
        const ctx = document.getElementById('chart-scam-distribution');
        if (!ctx) return;

        const labels = Object.keys(categoryData);
        const values = Object.values(categoryData);
        
        // Colors mapping
        const backgroundColors = [
            'rgba(6, 182, 212, 0.65)',  // Cyan
            'rgba(245, 158, 11, 0.65)',  // Amber
            'rgba(239, 68, 68, 0.65)',   // Crimson
            'rgba(139, 92, 246, 0.65)',  // Purple
            'rgba(16, 185, 129, 0.65)',  // Emerald
            'rgba(14, 165, 233, 0.65)',  // Light Blue
            'rgba(236, 72, 153, 0.65)',  // Pink
            'rgba(107, 114, 128, 0.65)'  // Gray
        ];
        
        const borderColors = [
            '#06b6d4', '#f59e0b', '#ef4444', '#8b5cf6', '#10b981', '#0ea5e9', '#ec4899', '#6b7280'
        ];

        if (scamDistributionChart) {
            scamDistributionChart.destroy();
        }

        scamDistributionChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: backgroundColors.slice(0, labels.length),
                    borderColor: borderColors.slice(0, labels.length),
                    borderWidth: 1.5,
                    hoverOffset: 12
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#9ca3af',
                            font: { family: 'Inter', size: 10 }
                        }
                    }
                },
                cutout: '70%'
            }
        });
    }

    // 2. Threat Trends Chart (Bar)
    function renderThreatTrendsChart(threatData) {
        const ctx = document.getElementById('chart-threat-trends');
        if (!ctx) return;

        const allLevels = ['Safe', 'Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'];
        const values = allLevels.map(lvl => threatData[lvl] || 0);

        if (threatTrendsChart) {
            threatTrendsChart.destroy();
        }

        threatTrendsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: allLevels,
                datasets: [{
                    label: 'Threat Count',
                    data: values,
                    backgroundColor: [
                        'rgba(16, 185, 129, 0.3)', // Safe
                        'rgba(6, 182, 212, 0.3)',  // Low
                        'rgba(245, 158, 11, 0.3)',  // Medium
                        'rgba(239, 68, 68, 0.3)',   // High
                        'rgba(239, 68, 68, 0.6)'    // Critical
                    ],
                    borderColor: [
                        '#10b981', '#06b6d4', '#f59e0b', '#ef4444', '#ef4444'
                    ],
                    borderWidth: 1.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        ticks: { color: '#9ca3af', font: { family: 'Inter', size: 10 } },
                        grid: { color: 'rgba(255, 255, 255, 0.03)' }
                    },
                    y: {
                        ticks: { color: '#9ca3af', stepSize: 1 },
                        grid: { color: 'rgba(255, 255, 255, 0.03)' }
                    }
                }
            }
        });
    }

    // 3. Monthly Logs Timeline Chart (Line)
    function renderMonthlyLogsChart() {
        const ctx = document.getElementById('chart-monthly-logs');
        if (!ctx) return;

        if (monthlyLogsChart) {
            monthlyLogsChart.destroy();
        }

        // Mock a timeline of last 12 days scan count
        const labels = ['Jul 7', 'Jul 8', 'Jul 9', 'Jul 10', 'Jul 11', 'Jul 12', 'Jul 13', 'Jul 14', 'Jul 15', 'Jul 16', 'Jul 17', 'Jul 18'];
        const scamLogs = [5, 8, 12, 6, 9, 14, 15, 18, 11, 19, 24, 32];
        const threatLogs = [2, 3, 5, 2, 4, 8, 9, 11, 6, 12, 15, 22];

        monthlyLogsChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Total Scans Logged',
                        data: scamLogs,
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.05)',
                        borderWidth: 2,
                        tension: 0.35,
                        fill: true
                    },
                    {
                        label: 'Threats Isolated',
                        data: threatLogs,
                        borderColor: '#ef4444',
                        backgroundColor: 'transparent',
                        borderWidth: 2,
                        tension: 0.35,
                        borderDash: [5, 5]
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#9ca3af', font: { family: 'Inter', size: 10 } }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#9ca3af', font: { family: 'Inter', size: 9 } },
                        grid: { color: 'rgba(255, 255, 255, 0.02)' }
                    },
                    y: {
                        ticks: { color: '#9ca3af' },
                        grid: { color: 'rgba(255, 255, 255, 0.02)' }
                    }
                }
            }
        });
    }

    // --- HISTORY TABLE LOADER ---
    const historySearch = document.getElementById('history-search-input');
    const historyCatFilter = document.getElementById('history-filter-category');
    const historyRiskFilter = document.getElementById('history-filter-risk');
    const btnResetFilters = document.getElementById('btn-reset-filters');
    const historyTableBody = document.getElementById('history-table-body');

    function loadHistory() {
        if (!historyTableBody) return;
        
        const q = historySearch.value;
        const cat = historyCatFilter.value;
        const risk = historyRiskFilter.value;
        
        let url = `/api/history?limit=50`;
        if (q) url += `&query=${encodeURIComponent(q)}`;
        if (cat) url += `&category=${encodeURIComponent(cat)}`;
        if (risk) url += `&risk_level=${encodeURIComponent(risk)}`;
        
        fetch(url)
        .then(res => { if(res.status === 401) { window.location.href = '/login'; throw new Error('Unauthorized'); } return res.json(); })
        .then(data => {
            historyTableBody.innerHTML = '';
            
            if (data.length === 0) {
                historyTableBody.innerHTML = `
                    <tr>
                        <td colspan="8" class="text-center text-secondary py-4">
                            <i class="fa-solid fa-circle-exclamation mb-2"></i> No records match filters.
                        </td>
                    </tr>
                `;
                return;
            }
            
            data.forEach(item => {
                const tr = document.createElement('tr');
                const riskClass = getThreatClass(item.threat_level);
                
                // Format type badge
                const typeIcon = item.scan_type === 'text' ? '<i class="fa-solid fa-envelope-open-text text-cyan"></i> Text' : '<i class="fa-solid fa-link text-purple"></i> URL';
                
                // Truncate content
                let contentText = item.input_content;
                if (contentText.length > 50) {
                    contentText = contentText.substring(0, 47) + '...';
                }
                
                // Format timestamp (remove seconds and MS if needed)
                const formattedTime = item.timestamp.replace('T', ' ').substring(0, 19);

                tr.innerHTML = `
                    <td class="font-orbitron font-weight-bold" style="color: var(--text-muted);">#${item.id}</td>
                    <td style="font-size: 0.78rem; white-space: nowrap;">${formattedTime}</td>
                    <td style="white-space: nowrap;">${typeIcon}</td>
                    <td class="truncate-text" title="${item.input_content.replace(/"/g, '&quot;')}">${contentText}</td>
                    <td class="font-orbitron" style="font-size: 0.78rem;">${item.category}</td>
                    <td class="font-orbitron font-weight-bold" style="color: ${riskClass === 'safe' ? 'var(--color-emerald)' : riskClass === 'low' ? 'var(--color-cyan)' : riskClass === 'medium' ? 'var(--color-amber)' : 'var(--color-crimson)'}">${item.risk_score}%</td>
                    <td><span class="threat-level-badge ${riskClass}" style="padding: 2px 8px; font-size: 0.62rem;">${item.threat_level}</span></td>
                    <td class="text-center">
                        <button class="btn-cyber-outline btn-sm font-orbitron" style="padding: 2px 8px; font-size: 0.65rem;" onclick="viewScanRecord(${item.id})">
                            Audit
                        </button>
                    </td>
                `;
                historyTableBody.appendChild(tr);
            });
        })
        .catch(err => console.error("History fetch error:", err));
    }

    if (historySearch) {
        historySearch.addEventListener('input', loadHistory);
        historyCatFilter.addEventListener('change', loadHistory);
        historyRiskFilter.addEventListener('change', loadHistory);
    }
    
    if (btnResetFilters) {
        btnResetFilters.addEventListener('click', function () {
            historySearch.value = '';
            historyCatFilter.value = '';
            historyRiskFilter.value = '';
            loadHistory();
        });
    }

    // View specific scan record callback in modal
    window.viewScanRecord = function (id) {
        fetch(`/api/history`)
        .then(res => { if(res.status === 401) { window.location.href = '/login'; throw new Error('Unauthorized'); } return res.json(); })
        .then(scans => {
            const scan = scans.find(s => s.id === id);
            if (!scan) return;
            
            document.getElementById('detail-timestamp').innerText = scan.timestamp.replace('T', ' ').substring(0, 19);
            document.getElementById('detail-type').innerText = scan.scan_type.toUpperCase();
            document.getElementById('detail-category').innerText = scan.category;
            document.getElementById('detail-content').innerText = scan.input_content;
            document.getElementById('detail-risk-score').innerText = `${scan.risk_score}%`;
            
            const badge = document.getElementById('detail-threat-badge');
            badge.innerText = scan.threat_level;
            badge.className = `threat-level-badge ${getThreatClass(scan.threat_level)}`;
            
            // Flags
            const flagsList = document.getElementById('detail-flags-list');
            const noFlags = document.getElementById('detail-no-flags');
            flagsList.innerHTML = '';
            
            if (scan.flags && scan.flags.length > 0) {
                noFlags.classList.add('d-none');
                scan.flags.forEach(f => {
                    const span = document.createElement('span');
                    span.className = 'badge bg-dark border border-warning text-warning font-orbitron px-3 py-2';
                    span.style.fontSize = '0.7rem';
                    span.innerText = f;
                    flagsList.appendChild(span);
                });
            } else {
                noFlags.classList.remove('d-none');
            }
            
            const detailModal = new bootstrap.Modal(document.getElementById('modal-scan-details'));
            detailModal.show();
        })
        .catch(err => console.error("Error fetching record detail:", err));
    };

    // --- MACHINE LEARNING PANEL LOADER ---
    let modelMetricsData = null;
    
    function loadMLMetrics() {
        fetch('/api/ml/metrics')
        .then(res => { if(res.status === 401) { window.location.href = '/login'; throw new Error('Unauthorized'); } return res.json(); })
        .then(data => {
            modelMetricsData = data;
            
            // Populate metrics labels in HTML
            const modelNames = ['Logistic Regression', 'Naive Bayes', 'Random Forest'];
            const containers = document.querySelectorAll('#ml-models-container .col-lg-4');
            
            modelNames.forEach((name, idx) => {
                const metrics = data[name];
                if (!metrics) return;
                
                const card = containers[idx];
                card.querySelector('.ml-accuracy').innerText = `${metrics.accuracy}%`;
                card.querySelector('.ml-precision').innerText = `${metrics.precision}%`;
                card.querySelector('.ml-recall').innerText = `${metrics.recall}%`;
                card.querySelector('.ml-f1').innerText = `${metrics.f1_score}%`;
            });
        })
        .catch(err => console.error("Error loading model metrics:", err));
    }

    // Modal Confusion Matrix trigger
    window.viewConfusionMatrix = function (modelName) {
        if (!modelMetricsData || !modelMetricsData[modelName]) {
            alert('Model metrics loading. Please wait.');
            return;
        }

        const metrics = modelMetricsData[modelName];
        const grid = document.getElementById('confusion-matrix-grid');
        const labelsList = document.getElementById('matrix-labels-list');
        
        document.getElementById('matrix-modal-title').innerText = `${modelName} Confusion Matrix`;
        
        // Clear old content
        grid.innerHTML = '';
        labelsList.innerHTML = '';
        
        const labels = metrics.labels;
        const cm = metrics.confusion_matrix;
        const size = labels.length;
        
        // Populate indices list
        labels.forEach((lbl, idx) => {
            const li = document.createElement('li');
            li.innerHTML = `<strong>Index ${idx}</strong>: ${lbl}`;
            labelsList.appendChild(li);
        });

        // Set CSS Grid parameters dynamic size + borders
        grid.style.gridTemplateColumns = `repeat(${size}, 50px)`;
        
        // Calculate max value in CM to scale opacity
        let maxVal = 1;
        for (let r = 0; r < size; r++) {
            for (let c = 0; c < size; c++) {
                if (cm[r][c] > maxVal) maxVal = cm[r][c];
            }
        }

        // Draw cells row by row
        for (let r = 0; r < size; r++) {
            for (let c = 0; c < size; c++) {
                const cell = document.createElement('div');
                cell.className = 'matrix-cell';
                const count = cm[r][c];
                cell.innerText = count;
                
                // Color scaling: Highlight diagonals (true positives) vs errors
                const isDiagonal = r === c;
                let bgOpacity = count / maxVal;
                // Clamp minimum transparency so values are readable
                bgOpacity = Math.max(0.08, bgOpacity);
                
                if (isDiagonal) {
                    // Green gradient for correct predicts
                    cell.style.backgroundColor = `rgba(16, 185, 129, ${bgOpacity * 0.8})`;
                    cell.style.border = '1px solid rgba(16, 185, 129, 0.4)';
                    cell.style.boxShadow = isDiagonal && count > 0 ? 'inset 0 0 10px rgba(16, 185, 129, 0.2)' : '';
                } else {
                    // Crimson red gradient for classification errors
                    cell.style.backgroundColor = count > 0 ? `rgba(239, 68, 68, ${bgOpacity * 0.65})` : 'rgba(255,255,255,0.01)';
                    cell.style.border = count > 0 ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(255,255,255,0.03)';
                }
                
                cell.setAttribute('title', `Actual: ${labels[r]} | Predicted: ${labels[c]}`);
                grid.appendChild(cell);
            }
        }

        const matrixModal = new bootstrap.Modal(document.getElementById('modal-confusion-matrix'));
        matrixModal.show();
    };

    // --- ADMIN PANEL CONSOLE LOADER ---
    let adminWorkloadTimer = null;
    
    function loadAdminPanel() {
        // Count Critical Audits
        fetch('/api/history')
        .then(res => { if(res.status === 401) { window.location.href = '/login'; throw new Error('Unauthorized'); } return res.json(); })
        .then(data => {
            const criticals = data.filter(s => s.threat_level === 'High Risk' || s.threat_level === 'Critical Risk');
            document.getElementById('admin-critical-count').innerText = criticals.length;
            
            // Populate administrative audit table logs
            const auditTableBody = document.getElementById('admin-audit-table-body');
            auditTableBody.innerHTML = '';
            
            // Slice last 10 audits
            const lastTen = data.slice(0, 10);
            
            if (lastTen.length === 0) {
                auditTableBody.innerHTML = `
                    <tr><td colspan="6" class="text-center text-secondary py-3">No audit activity logged.</td></tr>
                `;
                return;
            }
            
            lastTen.forEach(item => {
                const tr = document.createElement('tr');
                const isScam = item.threat_level !== 'Safe';
                const operatorStatus = isScam ? '<span class="text-danger"><i class="fa-solid fa-ban"></i> BLOCKED</span>' : '<span class="text-success"><i class="fa-solid fa-check"></i> PASSED</span>';
                
                let message = `Payload evaluation for input type: '${item.scan_type}'`;
                if (item.threat_level === 'Critical Risk' || item.threat_level === 'High Risk') {
                    message = `Critical alert triggers: Classified scam category '${item.category}' isolated.`;
                } else if (item.threat_level === 'Safe') {
                    message = `Safe audit passed: Resource query matched verification standards.`;
                }
                
                const timeOnly = item.timestamp.replace('T', ' ').substring(11, 19);

                tr.innerHTML = `
                    <td class="font-monospace text-secondary" style="font-size: 0.78rem;">${timeOnly}</td>
                    <td class="font-orbitron" style="font-size: 0.78rem;">${item.scan_type === 'text' ? 'TEXT_ENGINE' : 'URL_SCAN_DAEMON'}</td>
                    <td style="font-size: 0.78rem;">${item.category}</td>
                    <td class="text-secondary truncate-text" style="max-width: 320px;" title="${message}">${message}</td>
                    <td class="font-monospace text-warning" style="font-size: 0.78rem;">SEC_ERR_R${item.risk_score}</td>
                    <td class="font-orbitron" style="font-size: 0.75rem;">${operatorStatus}</td>
                `;
                auditTableBody.appendChild(tr);
            });
            
            renderAdminWorkloadChart();
        })
        .catch(err => console.error("Admin stats failed:", err));
    }

    // Server workload chart (Real time simulation)
    function renderAdminWorkloadChart() {
        const ctx = document.getElementById('chart-admin-workload');
        if (!ctx) return;

        if (adminWorkloadChart) {
            adminWorkloadChart.destroy();
        }

        const labels = Array.from({length: 15}, (_, i) => `${i*2}s ago`).reverse();
        const dataValues = Array.from({length: 15}, () => Math.floor(Math.random() * 30) + 10); // Start 10-40%

        adminWorkloadChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Server CPU utilization %',
                    data: dataValues,
                    borderColor: '#a855f7',
                    backgroundColor: 'rgba(168, 85, 247, 0.05)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#6b7280' }, grid: { display: false } },
                    y: { min: 0, max: 100, ticks: { color: '#6b7280' }, grid: { color: 'rgba(255,255,255,0.01)' } }
                }
            }
        });

        // Simulation update polling interval
        if (adminWorkloadTimer) {
            clearInterval(adminWorkloadTimer);
        }
        
        adminWorkloadTimer = setInterval(() => {
            if (activePanel !== 'admin-console') {
                clearInterval(adminWorkloadTimer);
                return;
            }
            
            const nextVal = Math.floor(Math.random() * 25) + 12; // Next simulated data point
            adminWorkloadChart.data.datasets[0].data.shift();
            adminWorkloadChart.data.datasets[0].data.push(nextVal);
            adminWorkloadChart.update('quiet');
        }, 2000);
    }

    // --- FIRST APP RUN LOAD ---
    loadDashboardStats();
});
