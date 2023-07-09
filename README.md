# Cyber

Miscellaneous notebooks for *.pcap parsing and analysis

1. Download smallFlows.pcap and bigFlows.pcap files from https://tcpreplay.appneta.com/wiki/captures.html into your data directory
2. SandBox.ipynb is the notebook containing some classifiers running on flows generated by Suricata
3. Traitement_dataframes.ipynb is the notebook for unsupervised learning on raw packets. It is required to run toy_pyshark.ipynb first to create a specific dataframe out of the *.pcap file

NB : a running Suricata installation is required : https://suricata.io/
