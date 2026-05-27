import networkx as nx

def generate_graph(components=None, flows=None):
    """
    Generate a NetworkX directed graph from components and flows.
    """
    G = nx.DiGraph()

    if components:
        for comp in components:
            G.add_node(comp['name'], **comp)

    if flows:
        for flow in flows:
            G.add_edge(flow['source'], flow['target'],
                       label=flow.get('label', ''))

    return G

def get_node_color(node_type):
    """Return color code for each node type."""
    colors = {
        'process': '#4A90D9',
        'data_store': '#27AE60',
        'external_entity': '#E74C3C',
        'data_flow': '#F39C12'
    }
    return colors.get(node_type, '#95A5A6')

def get_graph_stats(G):
    """Return basic statistics about the DFD graph."""
    return {
        'total_nodes': G.number_of_nodes(),
        'total_edges': G.number_of_edges(),
        'node_types': count_node_types(G),
        'trust_boundaries': count_trust_boundaries(G)
    }

def count_node_types(G):
    """Count nodes by type."""
    counts = {}
    for _, attrs in G.nodes(data=True):
        node_type = attrs.get('type', 'unknown')
        counts[node_type] = counts.get(node_type, 0) + 1
    return counts

def count_trust_boundaries(G):
    """Count trust boundary crossings in the graph."""
    boundaries = 0
    for source, target in G.edges():
        s_type = G.nodes[source].get('type', '')
        t_type = G.nodes[target].get('type', '')
        if s_type == 'external_entity' or t_type == 'external_entity':
            boundaries += 1
    return boundaries

def find_critical_paths(G):
    """Find paths involving critical or high sensitivity nodes."""
    critical_nodes = [
        n for n, d in G.nodes(data=True)
        if d.get('sensitivity') in ['critical', 'high']
    ]
    return critical_nodes

def graph_to_dict(G):
    """Convert graph to dictionary format for JSON serialization."""
    return {
        'nodes': [
            {'id': n, **data}
            for n, data in G.nodes(data=True)
        ],
        'edges': [
            {'source': u, 'target': v, **data}
            for u, v, data in G.edges(data=True)
        ]
    }
