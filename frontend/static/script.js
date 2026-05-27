// ── State ──────────────────────────────────────────────
let components = [];

// ── Navigation ─────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    showSection('home');
});

function showSection(sectionId) {
    document.querySelectorAll("section").forEach(s => s.classList.remove("active"));
    document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));

    const section = document.getElementById(sectionId);
    if (section) section.classList.add("active");

    const navLinks = document.querySelectorAll(".nav-link");
    navLinks.forEach(link => {
        if (link.getAttribute('onclick') &&
            link.getAttribute('onclick').includes(sectionId)) {
            link.classList.add('active');
        }
    });
}

// ── DFD Builder ────────────────────────────────────────
function addComponent() {
    const name = document.getElementById('comp-name').value.trim();
    const type = document.getElementById('comp-type').value;
    const sensitivity = document.getElementById('comp-sensitivity').value;

    if (!name) {
        alert('Please enter a component name.');
        return;
    }

    components.push({ name, type, sensitivity });
    renderComponentList();
    document.getElementById('comp-name').value = '';
}

function renderComponentList() {
    const list = document.getElementById('components-list');
    list.innerHTML = '';

    components.forEach((comp, index) => {
        const li = document.createElement('li');
        li.innerHTML = `
            <span>
                ${getTypeIcon(comp.type)} <strong>${comp.name}</strong>
                <small style="color:#8b949e"> — ${comp.type} (${comp.sensitivity})</small>
            </span>
            <button onclick="removeComponent(${index})"
                style="background:transparent;border:none;color:#f85149;
                cursor:pointer;font-size:16px;">✕</button>
        `;
        list.appendChild(li);
    });
}

function removeComponent(index) {
    components.splice(index, 1);
    renderComponentList();
}

function clearComponents() {
    components = [];
    renderComponentList();
}

function getTypeIcon(type) {
    const icons = {
        'process': '⚙️',
        'data_store': '🗄️',
        'external_entity': '👤',
        'data_flow': '→'
    };
    return icons[type] || '📦';
}

// ── Load Default DFD ───────────────────────────────────
async function loadDefaultDFD() {
    try {
        const response = await fetch('/api/dfd/default');
        const data = await response.json();

        if (data.status === 'success') {
            components = data.components;
            showSection('create-dfd');
            renderComponentList();
        }
    } catch (error) {
        console.error('Error loading default DFD:', error);
    }
}

// ── Analyze Threats ────────────────────────────────────
async function analyzeDFD() {
    if (components.length === 0) {
        alert('Please add at least one component before analyzing.');
        return;
    }

    showSection('analyze-threats');
    document.getElementById('analysis-loading').style.display = 'block';
    document.getElementById('summary-cards').innerHTML = '';
    document.getElementById('threats-container').innerHTML = '';

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ components })
        });

        const data = await response.json();

        document.getElementById('analysis-loading').style.display = 'none';

        if (data.status === 'success') {
            renderSummary(data.summary);
            renderThreats(data.threats);
        }
    } catch (error) {
        document.getElementById('analysis-loading').style.display = 'none';
        document.getElementById('threats-container').innerHTML =
            '<p style="color:#f85149">Error running analysis. Make sure the server is running.</p>';
    }
}

// ── Render Summary ─────────────────────────────────────
function renderSummary(summary) {
    const container = document.getElementById('summary-cards');
    const bySeverity = summary.by_severity || {};

    container.innerHTML = `
        <div class="summary-card">
            <div class="count total-count">${summary.total || 0}</div>
            <div class="label">Total Threats</div>
        </div>
        <div class="summary-card">
            <div class="count critical-count">${bySeverity.Critical || 0}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card">
            <div class="count high-count">${bySeverity.High || 0}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card">
            <div class="count medium-count">${bySeverity.Medium || 0}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card">
            <div class="count low-count">${bySeverity.Low || 0}</div>
            <div class="label">Low</div>
        </div>
    `;
}

// ── Render Threats ─────────────────────────────────────
function renderThreats(threats) {
    const container = document.getElementById('threats-container');
    container.innerHTML = '';

    threats.forEach(threat => {
        const severity = (threat.severity || 'low').toLowerCase();
        const dread = threat.dread_breakdown || {};
        const mitigations = threat.mitigations || [];

        const card = document.createElement('div');
        card.className = `threat-card ${severity}`;
        card.innerHTML = `
            <div class="threat-header">
                <div class="threat-title">
                    ${getCategoryIcon(threat.category)}
                    ${threat.category} — <em>${threat.component}</em>
                </div>
                <span class="severity-badge badge-${severity}">
                    ${threat.severity} | DREAD: ${threat.dread_score}
                </span>
            </div>
            <div class="threat-body">
                <p>${threat.description}</p>

                <div class="dread-scores">
                    <div class="dread-item">Damage <span>${dread.damage || 'N/A'}</span></div>
                    <div class="dread-item">Reproducibility <span>${dread.reproducibility || 'N/A'}</span></div>
                    <div class="dread-item">Exploitability <span>${dread.exploitability || 'N/A'}</span></div>
                    <div class="dread-item">Affected Users <span>${dread.affected_users || 'N/A'}</span></div>
                    <div class="dread-item">Discoverability <span>${dread.discoverability || 'N/A'}</span></div>
                </div>

                <br><strong>Mitigations:</strong>
                <ul class="mitigations-list">
                    ${mitigations.map(m => `<li>${m}</li>`).join('')}
                </ul>
            </div>
        `;
        container.appendChild(card);
    });
}

function getCategoryIcon(category) {
    const icons = {
        'Spoofing': '🎭',
        'Tampering': '✏️',
        'Repudiation': '🚫',
        'Information Disclosure': '🔓',
        'Denial of Service': '💥',
        'Elevation of Privilege': '⬆️'
    };
    return icons[category] || '⚠️';
}

// ── Reports ────────────────────────────────────────────
async function loadReports() {
    try {
        const response = await fetch('/api/reports');
        const data = await response.json();
        const container = document.getElementById('reports-container');

        if (!data.reports || data.reports.length === 0) {
            container.innerHTML = '<p style="color:#8b949e">No reports saved yet. Run an analysis first.</p>';
            return;
        }

        container.innerHTML = data.reports.map(report => `
            <div class="report-card">
                <h3>📋 ${report.title}</h3>
                <p>${report.summary || 'No summary available.'}</p>
                <p style="font-size:12px;color:#8b949e;margin-top:8px;">
                    Created: ${report.created_at}
                </p>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading reports:', error);
    }
}
