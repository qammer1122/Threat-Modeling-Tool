from flask import Blueprint, render_template, request, jsonify
from backend.stride import stride_analysis, get_threat_summary
from backend.dfd import create_dfd, get_dfd_components, get_dfd_flows
from backend.database import (save_threat, get_all_threats,
                               save_component, get_all_components,
                               save_report, get_all_reports)
from utils.threat_utils import generate_mitigation_report

frontend = Blueprint('frontend', __name__)

# ─── Pages ───────────────────────────────────────────────

@frontend.route('/')
def index():
    return render_template('index.html')

# ─── DFD API ─────────────────────────────────────────────

@frontend.route('/api/dfd/create', methods=['POST'])
def create_dfd_route():
    """Create a new DFD from provided components and flows."""
    data = request.get_json()
    components = data.get('components', [])
    flows = data.get('flows', [])

    G = create_dfd(components, [(f['source'], f['target'],
                                  f.get('label', ''))
                                 for f in flows])

    # Save components to database
    for comp in components:
        save_component(comp['name'], comp['type'],
                       comp.get('description', ''))

    return jsonify({
        'status': 'success',
        'components': get_dfd_components(G),
        'flows': get_dfd_flows(G),
        'message': f'DFD created with {len(components)} components'
    })

@frontend.route('/api/dfd/default', methods=['GET'])
def get_default_dfd():
    """Return the default sample DFD."""
    G = create_dfd()
    return jsonify({
        'status': 'success',
        'components': get_dfd_components(G),
        'flows': get_dfd_flows(G)
    })

# ─── Analysis API ─────────────────────────────────────────

@frontend.route('/api/analyze', methods=['POST'])
def analyze_threats():
    """Run STRIDE analysis on provided components."""
    data = request.get_json()
    components = data.get('components', [])

    if not components:
        G = create_dfd()
        components = get_dfd_components(G)

    threats = stride_analysis(components)
    summary = get_threat_summary(threats)
    mitigation_report = generate_mitigation_report(threats)

    # Save threats to database
    for threat in threats:
        save_threat(
            component_id=None,
            category=threat['category'],
            name=f"{threat['category']} on {threat['component']}",
            description=threat['description'],
            severity=threat['severity'],
            dread_score=threat['dread_score'],
            mitigation=threat['mitigation']
        )

    return jsonify({
        'status': 'success',
        'threats': threats,
        'summary': summary,
        'mitigation_report': mitigation_report,
        'total_threats': len(threats)
    })

# ─── Reports API ─────────────────────────────────────────

@frontend.route('/api/reports', methods=['GET'])
def get_reports():
    """Get all saved reports."""
    reports = get_all_reports()
    return jsonify({'status': 'success', 'reports': reports})

@frontend.route('/api/reports/save', methods=['POST'])
def save_report_route():
    """Save a new threat modeling report."""
    data = request.get_json()
    title = data.get('title', 'Untitled Report')
    summary = data.get('summary', '')
    threats = data.get('threats', [])

    report_id = save_report(title, summary, threats)
    return jsonify({
        'status': 'success',
        'report_id': report_id,
        'message': 'Report saved successfully'
    })

# ─── Threats API ─────────────────────────────────────────

@frontend.route('/api/threats', methods=['GET'])
def get_threats():
    """Get all saved threats from database."""
    threats = get_all_threats()
    return jsonify({'status': 'success', 'threats': threats})
