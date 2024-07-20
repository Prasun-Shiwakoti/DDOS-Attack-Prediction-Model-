import pandas as pd
import matplotlib.pyplot as plt
import pickle
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix   


# Dataset: https://www.kaggle.com/code/maryamanwer/ddos-attack-detection-using-ml/input
df_train = pd.read_csv("Dataset/DDoS-Large.csv")
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


df_train["attack"] = df_train.attack.map(lambda x: 0 if x == "normal" else 1)
df_train['protocol_type'] = label_encoder.fit_transform(df_train['protocol_type'])
df_train['service'] = label_encoder.fit_transform(df_train['service'])
df_train['flag'] = label_encoder.fit_transform(df_train['flag'])


df_train_X = df_train.drop("attack", axis=1)
df_train_Y = df_train["attack"]


x_train, x_test, y_train, y_test = train_test_split(df_train_X, df_train_Y, test_size=0.4, random_state=42)

rf_model = RandomForestClassifier(n_estimators=160, random_state=90)
rf_model.fit(x_train, y_train)

rf_pred = rf_model.predict(x_test)


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
    print(f'Precision:', round(rf_precision, 4))
    print(f'Recall:', round(rf_recall, 4))
    print("\nConfusion Matrix:")
    print(conf_matrix)

evaluateModel()


with open("LargeModelPickleFile", 'wb') as f:
    pickle.dump(rf_model, f)

