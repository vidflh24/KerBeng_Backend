import graphviz

# Buat grafik terarah kembali setelah reset
dot = graphviz.Digraph(format='png')
dot.attr(rankdir='LR')  # Buat grafik searah horizontal

# Struktur direktori dan file
structure = {
    'Pentest': {
        'AutoPentest': ['APentest.py'],
        'CVE': {
            'CVE12_2122': [
                'CVE12_2122.py',
                'CVE12_Banner.py',
                'CVE12_Scanner.py',
                'CVE12_Enum.py',
                'CVE12_VulnAnals.py',
                'CVE12_Exploit.py',
                'CVE12_Report.py',
            ],
            'CVE22_46169': []
        },
        'Metode': [
            'Banner.py', 'Scanner.py', 'Enumerator.py', 'VulnerAnalist.py', 'Exploit.py', 'Report.py'
        ],
        'Utils': ['PentestUtils.py']
    }
}

# Fungsi rekursif untuk menambahkan node dan edge
def add_nodes_edges(parent, children):
    if isinstance(children, dict):
        for k, v in children.items():
            dot.node(k)
            dot.edge(parent, k)
            add_nodes_edges(k, v)
    elif isinstance(children, list):
        for item in children:
            dot.node(item, shape='note')
            dot.edge(parent, item)

# Bangun grafik
dot.node('Pentest')
add_nodes_edges('Pentest', structure['Pentest'])

# Simpan file
output_path = "/mnt/data/pentest_structure_graph"
dot.render(output_path, cleanup=True)
output_path + ".png"
