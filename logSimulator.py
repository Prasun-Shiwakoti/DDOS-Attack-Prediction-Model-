import pandas as pd
import random
import requests
import time
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from datetime import datetime

# url of api endpoint
URL = 'http://127.0.0.1:5000/predict'

# number of request to send to server
turns = 10000

# to check for accuracy
y_true =  y_predict = []

# load dataset
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

# log printing function
def print_log(log_id, prediction, actualValue):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"{current_time} - Log number: {log_id} : {actualValue}"
    if prediction == 1:
        log_message += "\n\t\t\t\t [ALERT: Potential Attack Detected]"
    print("-" * 120)
    print("\t"*4,log_message)
    print("-" * 120)


df_train["attack"] = df_train.attack.map(lambda x: 0 if x == "normal" else 1)
df_train['protocol_type'] = label_encoder.fit_transform(df_train['protocol_type'])
df_train['service'] = label_encoder.fit_transform(df_train['service'])
df_train['flag'] = label_encoder.fit_transform(df_train['flag'])


df_train_X = df_train.drop("attack", axis=1)
df_train_Y = df_train["attack"]


x_train, x_test, y_train, y_test = train_test_split(df_train_X, df_train_Y, test_size=0.4, random_state=42)


for i in range(turns):
    # randomly chooses which index to send to server
    ind = random.randrange(0, len(x_test))    

    data = x_test.iloc[ind].to_dict()

    # make the request
    response = requests.post(URL, json=data)

    modelPrediction = response.json().get("prediction")
    actualValue = y_test.iloc[ind]

    # add actual and predicted values to respective arrays
    y_true.append(actualValue)
    y_predict.append(modelPrediction)

    # print the log
    print_log(ind, modelPrediction, actualValue)
    time.sleep(1)

def calculateAccuracy(y_true, y_predict):
    # generates true negative, false positive, false negative and true positive data in matrix form
    conf_matrix = confusion_matrix(y_true, y_predict)

    accuracy = accuracy_score(y_true, y_predict)
    precision = precision_score(y_true, y_predict, average='binary', pos_label=1)
    recall = recall_score(y_true, y_predict, average='binary', pos_label=1)
    f1 = f1_score(y_true, y_predict, average='binary', pos_label=1)

    # Display the output
    print("\nAccuracy Metrics:")
    print(f"Accuracy: {accuracy}")
    print(f"Precision: {precision}")
    print(f"Recall: {recall}")
    print(f"F1 Score: {f1}")
    print("\nConfusion Matrix:")
    print(conf_matrix)


calculateAccuracy(y_true, y_predict)
input()