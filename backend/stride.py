from .cve import get_cve_data
from .dread import dread_analysis

# STRIDE threat categories with descriptions and mitigations
STRIDE_THREATS = {
    "Spoofing": {
        "description": "Attacker impersonates a legitimate user or system component.",
        "examples": [
            "Session hijacking via stolen authentication tokens",
            "IP spoofing to impersonate trusted hosts",
            "Man-in-the-middle attack to intercept credentials"
        ],
        "mitigations": [
            "Implement strong multi-factor authentication (MFA)",
            "Use digital signatures and certificates",
            "Enforce strict session management policies",
            "Use secure communication protocols (TLS/SSL)"
        ],
        "cve_examples": ["CVE-2022-21907", "CVE-2021-44228"]
    },
    "Tampering": {
        "description": "Unauthorized modification of data in transit or at rest.",
        "examples": [
            "SQL injection to modify database records",
            "Parameter tampering in HTTP requests",
            "File integrity violations through unauthorized access"
        ],
        "mitigations": [
            "Implement input validation and parameterized queries",
            "Use data integrity checks (checksums, HMAC)",
            "Apply least privilege access controls",
            "Enable audit logging for data modifications"
        ],
        "cve_examples": ["CVE-2021-34527", "CVE-2022-30190"]
    },
    "Repudiation": {
        "description": "User denies performing an action without ability to prove otherwise.",
        "examples": [
            "User denies making unauthorized transactions",
            "Attacker deletes audit logs after intrusion",
            "Missing timestamps on critical operations"
        ],
        "mitigations": [
            "Implement comprehensive audit logging",
            "Use digital signatures for critical transactions",
            "Ensure logs are tamper-proof and stored securely",
            "Implement non-repudiation mechanisms"
        ],
        "cve_examples": ["CVE-2021-26855"]
    },
    "Information Disclosure": {
        "description": "Sensitive information exposed to unauthorized parties.",
        "examples": [
            "Unencrypted sensitive data in transit",
            "Verbose error messages revealing system details",
            "Misconfigured cloud storage exposing private data"
        ],
        "mitigations": [
            "Encrypt sensitive data at rest and in transit",
            "Implement proper error handling (no verbose errors)",
            "Apply need-to-know access controls",
            "Regular security audits and penetration testing"
        ],
        "cve_examples": ["CVE-2021-44228", "CVE-2022-22965"]
    },
    "Denial of Service": {
        "description": "Attacker disrupts service availability for legitimate users.",
        "examples": [
            "DDoS attack overwhelming server resources",
            "Resource exhaustion through malformed requests",
            "Application-layer attacks targeting specific endpoints"
        ],
        "mitigations": [
            "Implement rate limiting and throttling",
            "Use DDoS protection services (CDN, WAF)",
            "Design for horizontal scalability",
            "Implement graceful degradation mechanisms"
        ],
        "cve_examples": ["CVE-2022-3602", "CVE-2021-45046"]
    },
    "Elevation of Privilege": {
        "description": "Attacker gains unauthorized elevated access or permissions.",
        "examples": [
            "Exploiting unpatched vulnerabilities for privilege escalation",
            "Bypassing authorization checks",
            "Abusing misconfigured sudo permissions"
        ],
        "mitigations": [
            "Apply principle of least privilege",
            "Regularly patch and update systems",
            "Implement proper authorization checks at every layer",
            "Use role-based access control (RBAC)"
        ],
        "cve_examples": ["CVE-2021-34527", "CVE-2022-37969"]
    }
}

def stride_analysis(components):
    """
    Perform STRIDE threat analysis on DFD components.
    Returns a list of identified threats with DREAD scores and mitigations.
    """
    all_threats = []

    for component in components:
        component_name = component.get('name', 'Unknown Component')
        component_type = component.get('type', 'process')

        # Determine applicable STRIDE categories based on component type
        applicable_threats = get_applicable_threats(component_type)

        for category in applicable_threats:
            threat_info = STRIDE_THREATS[category]

            threat = {
                'component': component_name,
                'component_type': component_type,
                'category': category,
                'description': threat_info['description'],
                'examples': threat_info['examples'],
                'mitigation': '\n'.join(threat_info['mitigations']),
                'mitigations': threat_info['mitigations'],
                'cve_examples': threat_info['cve_examples']
            }

            # Calculate DREAD score
            dread_scores = dread_analysis(component, category)
            threat['dread_score'] = dread_scores['total']
            threat['dread_breakdown'] = dread_scores
            threat['severity'] = get_severity(dread_scores['total'])

            # Fetch CVE data for first example CVE
            if threat_info['cve_examples']:
                cve_id = threat_info['cve_examples'][0]
                cve_data = get_cve_data(cve_id)
                if cve_data:
                    threat['cve_details'] = cve_data

            all_threats.append(threat)

    # Sort by DREAD score (highest risk first)
    all_threats.sort(key=lambda x: x['dread_score'], reverse=True)
    return all_threats

def get_applicable_threats(component_type):
    """Return applicable STRIDE threats based on component type."""
    threat_map = {
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
    return threat_map.get(component_type, list(STRIDE_THREATS.keys()))

def get_severity(dread_score):
    """Convert DREAD score to severity label."""
    if dread_score >= 8:
        return 'Critical'
    elif dread_score >= 6:
        return 'High'
    elif dread_score >= 4:
        return 'Medium'
    else:
        return 'Low'

def get_threat_summary(threats):
    """Generate a summary of threats by category and severity."""
    summary = {
        'total': len(threats),
        'by_category': {},
        'by_severity': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    }

    for threat in threats:
        category = threat['category']
        severity = threat['severity']

        if category not in summary['by_category']:
            summary['by_category'][category] = 0
        summary['by_category'][category] += 1
        summary['by_severity'][severity] += 1

    return summary
