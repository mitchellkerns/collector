import pandas as pd

def parse_nessus_csv(filepath):
    try:
        df = pd.read_csv(filepath)
        results = []

        for _, row in df.iterrows():
            cve = row.get("CVE", "")
            ip = row.get("Host")
            protocol = row.get("Protocol")
            port = row.get("Port")
            name = row.get("Name")
            synopsis = row.get("Synopsis", "")
            plugin_output = row.get("Plugin Output", "")

            if not ip or not protocol or not port or not name:
                continue

            results.append((cve, ip, protocol, int(port), name, synopsis, plugin_output))
        
        return results
    except Exception as e:
        print(f"Error parsing Nessus CSV: {e}")
        return []
