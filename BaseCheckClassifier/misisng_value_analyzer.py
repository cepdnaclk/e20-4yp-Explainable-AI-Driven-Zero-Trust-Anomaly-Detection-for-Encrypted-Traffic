import pandas as pd
import os

# Define the directory containing CSV files
csv_directory = '/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/Generated-Labelled-Flow/TrafficLabelling'

# Loop through each file in the directory
for filename in os.listdir(csv_directory):
    # Check if the file is a CSV
    if filename.endswith('.csv'):
        # Construct the full file path
        csv_file_path = os.path.join(csv_directory, filename)
        
        # Check if the file exists
        if os.path.exists(csv_file_path):
            print(f"\nAnalyzing file: {filename}")
            
            # Load the dataset
            dataset = pd.read_csv(csv_file_path, encoding='utf-8')
            
            # Check for missing values in the entire dataset
            missing_values = dataset.isnull().sum()
            
            # Display columns with missing values and the number of missing values in each column
            print("Missing values per column:")
            print(missing_values[missing_values > 0])
            
            # To get the rows with missing values
            rows_with_missing_values = dataset[dataset.isnull().any(axis=1)]
            
            # Display the number of missing values per row
            rows_with_missing_count = rows_with_missing_values.isnull().sum(axis=1)
            
            # Print the rows with missing values and how many missing in each row
            print("\nRows with missing values and count of missing values:")
            print(rows_with_missing_count)
            
            # Optionally, display rows with missing values for further inspection
            print("\nRows with missing values:")
            print(rows_with_missing_values)
        else:
            print(f"File not found: {csv_file_path}")
