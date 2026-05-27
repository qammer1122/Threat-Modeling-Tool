from backend.stride import STRIDE_THREATS, get_severity

def identify_threats(components):
    """
    Identify potential threats for each DFD component
    based on its type and sensitivity.
    Returns a structured list of threats.
    """
    threats = []

    component_threat_map = {
        'process': ['Spoofing', 'Tampering', 'Repudiation',
                    'Information Disclosure', 'Denial of Service',
                    'Elevation of Privilege'],
        'data_store': ['Tampering', 'Information Disclosure',
                       'Denial of Service'],
        'external_entity': ['Spoofing', 'Repudiation',
                            'Information Disclosure'],
        'data_flow': ['Tampering', 'Information Disclosure',
                      'Denial of Service']
    }

    for component in components:
        name = component.get('name', 'Unknown')
        comp_type = component.get('type', 'process')
        sensitivity = component.get('sensitivity', 'medium')

        applicable = component_threat_map.get(comp_type, list(STRIDE_THREATS.keys()))

        for category in applicable:
            threat_info = STRIDE_THREATS.get(category, {})
            threats.append({
                'component': name,
                'type': comp_type,
                'sensitivity': sensitivity,
                'category': category,
                'description': threat_info.get('description', ''),
                'mitigations': threat_info.get('mitigations', [])
            })

    return threats

def prioritize_threats(threats):
    """Sort threats by severity (DREAD score) descending."""
    return sorted(threats, key=lambda x: x.get('dread_score', 0), reverse=True)

def filter_threats_by_severity(threats, severity):
    """Filter threats by severity level."""
    return [t for t in threats if t.get('severity', '').lower() == severity.lower()]

def generate_mitigation_report(threats):
    """
    Generate a structured mitigation report from a list of threats.
    Groups mitigations by STRIDE category.
    """
    report = {}
    for threat in threats:
        category = threat.get('category', 'Unknown')
        if category not in report:
            report[category] = {
                'threats': [],
                'mitigations': set()
            }
        report[category]['threats'].append(threat.get('component', ''))
        for m in threat.get('mitigations', []):
            report[category]['mitigations'].add(m)

    # Convert sets to lists for JSON serialization
    for cat in report:
        report[cat]['mitigations'] = list(report[cat]['mitigations'])

    return report
