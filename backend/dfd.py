import networkx as nx
import json

def create_dfd(components=None, data_flows=None):
    """
    Create a Data Flow Diagram (DFD) as a directed graph.

    Components should be a list of dicts with:
    - name: str
    - type: 'process' | 'data_store' | 'external_entity' | 'data_flow'
    - sensitivity: 'low' | 'medium' | 'high' | 'critical'

    Data flows should be a list of tuples: (source, target, label)
    """
    G = nx.DiGraph()

    # Add default sample components if none provided
    if components is None:
        components = [
            {'name': 'Web Browser',    'type': 'external_entity', 'sensitivity': 'low'},
            {'name': 'Web Server',     'type': 'process',         'sensitivity': 'high'},
            {'name': 'Auth Service',   'type': 'process',         'sensitivity': 'critical'},
            {'name': 'Database',       'type': 'data_store',      'sensitivity': 'critical'},
            {'name': 'Admin Panel',    'type': 'process',         'sensitivity': 'high'},
            {'name': 'External API',   'type': 'external_entity', 'sensitivity': 'medium'},
        ]

    if data_flows is None:
        data_flows = [
            ('Web Browser',  'Web Server',   'HTTPS Request'),
            ('Web Server',   'Auth Service', 'Auth Token'),
            ('Web Server',   'Database',     'SQL Query'),
            ('Auth Service', 'Database',     'User Lookup'),
            ('Admin Panel',  'Database',     'Admin Query'),
            ('Web Server',   'External API', 'API Call'),
        ]

    # Add nodes with attributes
    for component in components:
        G.add_node(
            component['name'],
            type=component.get('type', 'process'),
            sensitivity=component.get('sensitivity', 'medium'),
            description=component.get('description', '')
        )

    # Add edges (data flows)
    for flow in data_flows:
        if len(flow) == 3:
            source, target, label = flow
            G.add_edge(source, target, label=label)
        else:
            G.add_edge(flow[0], flow[1])

    return G

def get_dfd_components(G):
    """Extract components from DFD graph as list of dicts."""
    components = []
    for node, attrs in G.nodes(data=True):
        components.append({
            'name': node,
            'type': attrs.get('type', 'process'),
            'sensitivity': attrs.get('sensitivity', 'medium'),
            'description': attrs.get('description', '')
        })
    return components

def get_dfd_flows(G):
    """Extract data flows from DFD graph."""
    flows = []
    for source, target, attrs in G.edges(data=True):
        flows.append({
            'source': source,
            'target': target,
            'label': attrs.get('label', '')
        })
    return flows

def dfd_to_json(G):
    """Convert DFD graph to JSON format."""
    return json.dumps({
        'components': get_dfd_components(G),
        'flows': get_dfd_flows(G)
    }, indent=2)

def get_trust_boundaries(G):
    """Identify trust boundaries in the DFD."""
    boundaries = []
    for source, target in G.edges():
        source_type = G.nodes[source].get('type')
        target_type = G.nodes[target].get('type')
        # External entity crossing into process = trust boundary
        if source_type == 'external_entity' or target_type == 'external_entity':
            boundaries.append({
                'from': source,
                'to': target,
                'boundary': 'External Trust Boundary'
            })
    return boundaries
