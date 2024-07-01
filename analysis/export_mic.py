import json
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from enum import Enum

class ValueType(Enum):
    MIC = "MIC"
    DEVNONCE = "DevNonce"
    FRMPayload = "FRMPayload"

def extract_n_sort(input_file, valueType):
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    values = []
    if isinstance(data, list):
        for item in data:
            if 'content' in item and valueType.value in item['content']:
                values.append(item['content'][valueType.value])
    else:
        if 'content' in data and valueType.value in data['content']:
            values.append(data['content'][valueType.value])
    
    """     values.sort()"""    

    return values

def save_to_json(values, output_file, label='values'):
    output_data = {label: values}
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=4)

def plot_distribution(values, valueType):

    bins = 50

    plt.figure(figsize=(10, 6))
    sns.histplot(values, kde=True, bins=bins)
    plt.title(f'Distribution of {valueType.value} values')
    plt.suptitle(f'Set size: {len(values)}\n Bins size {bins}')
    plt.xlabel(valueType.value)
    plt.ylabel('Frequency')
    plt.grid(True)
    plt.show()



input_file = 'wss_messages.json'
output_file = 'output.json'
t = ValueType.MIC
values = extract_n_sort(input_file,t)
""" save_to_json(values, output_file)
 """
plot_distribution(values, t)