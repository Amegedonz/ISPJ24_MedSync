import kaggle

data = kaggle.api.dataset_download_files('dasgroup/rba-dataset', path='./data', unzip=True)

print(data)
