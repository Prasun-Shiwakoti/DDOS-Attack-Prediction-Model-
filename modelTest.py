
import pandas as pd
import matplotlib.pyplot as plt
import pickle

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix

with open("MODEL/LargeModelPickleFile", "rb") as f:
    rf_model = pickle.load(f)

def nullValuesChecker(df):
    plt.figure(1,figsize=( 10,4))
    plt.hist(df.isna().sum())
    # Set the title and axis labels
    plt.xticks([0, 1], labels=['Not Null=0', 'Null=1'])
    plt.title('Columns with Null Values')
    plt.xlabel('Feature')
    plt.ylabel('The number of features')
    plt.show()  


def plotMissingValues(dataframe):
    missing_values = dataframe.isnull().sum()  # This counts null values for all columns
    plt.figure(figsize=(16, 5))
    missing_values.plot(kind='bar')
    plt.xlabel("Features")
    plt.ylabel("Missing values")
    plt.title("Total number of Missing values in each feature")
    plt.show()


df_train = pd.read_csv("DDoS-Large.csv")
label_encoder = LabelEncoder()


columns = (['duration'
,'protocol_type'
,'service'
,'flag'
,'src_bytes'
,'dst_bytes'
,'land'
,'wrong_fragment'
,'urgent'
,'hot'
,'num_failed_logins'
,'logged_in'
,'num_compromised'
,'root_shell'
,'su_attempted'
,'num_root'
,'num_file_creations'
,'num_shells'
,'num_access_files'
,'num_outbound_cmds'
,'is_host_login'
,'is_guest_login'
,'count'
,'srv_count'
,'serror_rate'
,'srv_serror_rate'
,'rerror_rate'
,'srv_rerror_rate'
,'same_srv_rate'
,'diff_srv_rate'
,'srv_diff_host_rate'
,'dst_host_count'
,'dst_host_srv_count'
,'dst_host_same_srv_rate'
,'dst_host_diff_srv_rate'
,'dst_host_same_src_port_rate'
,'dst_host_srv_diff_host_rate'
,'dst_host_serror_rate'
,'dst_host_srv_serror_rate'
,'dst_host_rerror_rate'
,'dst_host_srv_rerror_rate'
,'attack'
,'level'])

df_train.columns = columns

# nullValuesChecker(df)
# plotMissingValues(df)

df_train["attack"] = df_train.attack.map(lambda x: 0 if x == "normal" else 1)
df_train['protocol_type'] = label_encoder.fit_transform(df_train['protocol_type'])
df_train['service'] = label_encoder.fit_transform(df_train['service'])
df_train['flag'] = label_encoder.fit_transform(df_train['flag'])


df_train_X = df_train.drop("attack", axis=1)
df_train_Y = df_train["attack"]


x_train, x_test, y_train, y_test = train_test_split(df_train_X, df_train_Y, test_size=0.4, random_state=42)


# Test Model
rf_pred = rf_model.predict(x_test)

def showFeaturesImportance():
    # Getting feature importances from the trained model
    importances = rf_model.feature_importances_

    # Getting the indices of features sorted by importance
    indices = sorted(range(len(importances)), key=lambda i: importances[i], reverse=False)
    feature_names = [df_train.columns[i] for i in indices]

    # Plotting feature importances horizontally
    plt.figure(figsize=(8, 14))
    plt.barh(range(x_train.shape[1]), importances[indices], align="center")
    plt.yticks(range(x_train.shape[1]), feature_names)
    plt.xlabel("Importance")
    plt.title("Feature Importances")
    plt.show()

showFeaturesImportance()

def evaluateModel():
    # Evaluate the Model
    conf_matrix = confusion_matrix(y_test, rf_pred)
    rf_accuracy = accuracy_score(y_test, rf_pred)
    rf_f1 = f1_score(y_test, rf_pred)
    rf_precision = precision_score(y_test, rf_pred)
    rf_recall = recall_score(y_test, rf_pred)

    print('Model Accuracies:')
    print(f'Accuracy:', round(rf_accuracy, 4))
    print(f'F1 Score:', round(rf_f1, 4))
    print(f'Precision:', round(rf_precision,4))
    print(f'Recall:', round(rf_recall, 4))
    print("\nConfusion Matrix:")
    print(conf_matrix)

evaluateModel()

input()

