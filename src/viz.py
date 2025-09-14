# import pandas as pd
# import matplotlib.pyplot as plt
# import sys

# anomalies_path = sys.argv[1]
# patterns_path = sys.argv[2]

# anomalies = pd.read_csv(anomalies_path, parse_dates=["timestamp"])
# patterns = pd.read_csv(patterns_path)


# # График количества аномалий по типу
# anomalies['type_name'].value_counts().plot(kind='bar', title='Аномалии по типу')
# plt.savefig("anomalies_types.png")
# plt.clf()

# # График аномалий по времени
# anomalies.groupby(anomalies['timestamp'].dt.hour).size().plot(kind='line', title='Аномалии по времени')
# plt.savefig("anomalies_time.png")