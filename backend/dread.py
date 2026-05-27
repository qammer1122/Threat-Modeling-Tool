def dread_analysis(component, threat_category):
    """
    Perform DREAD risk scoring for a given component and threat category.

    DREAD Scoring (1-10 scale):
    - Damage:          How bad would an attack be?
    - Reproducibility: How easy is it to reproduce the attack?
    - Exploitability:  How much work is it to launch the attack?
    - Affected Users:  How many people will be impacted?
    - Discoverability: How easy is it to discover the threat?

    Total score = Average of all five dimensions (1-10)
    """
    component_type = component.get('type', 'process')
    sensitivity = component.get('sensitivity', 'medium')

    # Base scores per threat category
    base_scores = {
        'Spoofing': {
            'damage': 8,
            'reproducibility': 7,
            'exploitability': 6,
            'affected_users': 7,
            'discoverability': 6
        },
        'Tampering': {
            'damage': 9,
            'reproducibility': 6,
            'exploitability': 7,
            'affected_users': 8,
            'discoverability': 5
        },
        'Repudiation': {
            'damage': 6,
            'reproducibility': 8,
            'exploitability': 5,
            'affected_users': 5,
            'discoverability': 7
        },
        'Information Disclosure': {
            'damage': 8,
            'reproducibility': 7,
            'exploitability': 6,
            'affected_users': 9,
            'discoverability': 8
        },
        'Denial of Service': {
            'damage': 7,
            'reproducibility': 9,
            'exploitability': 8,
            'affected_users': 9,
            'discoverability': 7
        },
        'Elevation of Privilege': {
            'damage': 10,
            'reproducibility': 5,
            'exploitability': 6,
            'affected_users': 8,
            'discoverability': 4
        }
    }

    # Sensitivity multiplier
    sensitivity_multiplier = {
        'low': 0.7,
        'medium': 1.0,
        'high': 1.3,
        'critical': 1.5
    }.get(sensitivity, 1.0)

    scores = base_scores.get(threat_category, {
        'damage': 5,
        'reproducibility': 5,
        'exploitability': 5,
        'affected_users': 5,
        'discoverability': 5
    })

    # Apply sensitivity modifier and cap at 10
    adjusted = {
        key: min(10, round(val * sensitivity_multiplier, 1))
        for key, val in scores.items()
    }

    # Calculate total DREAD score (average)
    total = round(sum(adjusted.values()) / len(adjusted), 2)

    return {
        'damage': adjusted['damage'],
        'reproducibility': adjusted['reproducibility'],
        'exploitability': adjusted['exploitability'],
        'affected_users': adjusted['affected_users'],
        'discoverability': adjusted['discoverability'],
        'total': total
    }

def calculate_damage(component):
    """Assess potential damage from a threat."""
    sensitivity = component.get('sensitivity', 'medium')
    return {'low': 3, 'medium': 5, 'high': 8, 'critical': 10}.get(sensitivity, 5)

def calculate_reproducibility(component):
    """Assess how easily the attack can be reproduced."""
    component_type = component.get('type', 'process')
    return {'external_entity': 8, 'data_flow': 7,
            'process': 6, 'data_store': 5}.get(component_type, 6)

def calculate_exploitability(component):
    """Assess level of skill/effort required to exploit."""
    component_type = component.get('type', 'process')
    return {'external_entity': 7, 'data_flow': 8,
            'process': 6, 'data_store': 4}.get(component_type, 5)

def calculate_affected_users(component):
    """Assess how many users would be impacted."""
    scale = component.get('scale', 'medium')
    return {'small': 3, 'medium': 6, 'large': 9, 'global': 10}.get(scale, 6)

def calculate_discoverability(component):
    """Assess how easily the vulnerability can be discovered."""
    visibility = component.get('visibility', 'internal')
    return {'public': 9, 'external': 7,
            'internal': 5, 'private': 3}.get(visibility, 5)
