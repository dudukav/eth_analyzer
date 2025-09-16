import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import networkx as nx
import sys

anomalies_path = sys.argv[1]
patterns_path = sys.argv[2]

anomalies = pd.read_csv(anomalies_path, parse_dates=["timestamp"])
patterns = pd.read_csv(patterns_path)
anomalies['severity'] = anomalies['severity'].fillna('Unknown')
anomalies['count'] = anomalies['count'].fillna(0)
anomalies['fee_eth'] = anomalies['fee_eth'].fillna(0)
# anomalies['receivers'] = anomalies['receivers_json'].apply(lambda x: json.loads(x) if pd.notna(x) else [])
patterns['count'] = patterns['count'].fillna(0)
patterns['type_name'] = patterns['type_name'].fillna('Unknown')

# График аномалий по типу и силе
plt.figure(figsize=(12,6))
sns.countplot(data=anomalies, x='type_name', hue='severity', palette='Set2')
plt.xticks(rotation=45, ha='right')
plt.title("Количество аномалий по типу и severity")
plt.xlabel("Тип аномалии")
plt.ylabel("Количество")
sns.despine()
plt.tight_layout()
plt.show()

#  график закономерностей
patterns_df = pd.read_csv(patterns_path)
pattern_counts = patterns_df['type_name'].value_counts().reset_index()
pattern_counts.columns = ['type_name', 'count']

plt.figure(figsize=(12,6))
sns.barplot(data=pattern_counts, x='type_name', y='count', palette='Set2')
plt.xticks(rotation=45, ha='right')
plt.title("Количество бизнес-паттернов по типу")
plt.xlabel("Тип бизнес-паттерна")
plt.ylabel("Количество")
sns.despine()
plt.tight_layout()
plt.show()

# График всплесков аномалий по типу
anomalies['timestamp'] = pd.to_datetime(anomalies['timestamp'], utc=True, errors='coerce')
anomalies_clean = anomalies.dropna(subset=['timestamp'])

end_time = anomalies_clean['timestamp'].max()
start_time = end_time - pd.Timedelta(hours=1)
last_hour = anomalies_clean[(anomalies_clean['timestamp'] >= start_time) &
                            (anomalies_clean['timestamp'] <= end_time)]

last_hour['time_sec'] = last_hour['timestamp'].dt.floor('S')
time_series = last_hour.groupby(['time_sec', 'type_name']).size().reset_index(name='count')
fig2 = px.line(
    time_series,
    x='time_sec',
    y='count',
    color='type_name',
    markers=True,
    title='Аномалии за последний час по типам',
    labels={'time_sec': 'Время', 'count': 'Количество аномалий', 'type_name': 'Тип аномалии'}
)

fig2.update_traces(mode='lines+markers')
fig2.show()


# Граф подозрительных сязей
# exploded = anomalies.explode('receivers')

# edges_df = exploded.dropna(subset=['sender', 'receivers'])
# filtered_edges = edges_df[['sender', 'receivers']].rename(columns={'receivers': 'addres'})

# G = nx.from_pandas_edgelist(filtered_edges, 'sender', 'addres', create_using=nx.DiGraph())
# node_sizes = [300 + 50 * G.degree(n) for n in G.nodes]
# pos = nx.kamada_kawai_layout(G)

# plt.figure(figsize=(14, 14))
# nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color='orange', alpha=0.8)
# nx.draw_networkx_edges(G, pos, alpha=0.3, arrows=True, arrowstyle='-|>', arrowsize=10)
# nx.draw_networkx_labels(G, pos, font_size=6, font_color='black')

# plt.title("Граф связей подозрительных адресов (фильтрованные)")
# plt.axis("off")
# plt.tight_layout()
# plt.show()