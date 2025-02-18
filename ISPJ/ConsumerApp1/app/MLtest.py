import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from kaggle.api.kaggle_api_extended import KaggleApi


# api = KaggleApi()
# api.authenticate()
# api.dataset_download_files('dasgroup/rba-dataset', path='./data', unzip=True)


df = pd.read_csv('data/Training.csv')


print(df.head(100))

corr = df.corr(numeric_only=True)


numeric_columns = df.select_dtypes(include=['number']).columns 
if len(numeric_columns) > 0:
    model = IsolationForest(n_estimators=50, max_samples='auto', contamination=0.1, max_features=1.0)
    model.fit(df[[numeric_columns[0]]])  


sns.heatmap(corr, annot=True, cmap="coolwarm", linewidths=0.5)
plt.show()
