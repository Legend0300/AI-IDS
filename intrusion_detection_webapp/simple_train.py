#!/usr/bin/env python3
"""
Simple script to train and save the intrusion detection model
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from train_model import IntrusionDetectionTrainer
    
    print("Starting model training...")
    trainer = IntrusionDetectionTrainer()
    trainer.run_training_pipeline()
    print("Model training completed successfully!")
    
except ImportError as e:
    print(f"Import error: {e}")
    print("Training model manually...")
    
    import numpy as np
    import pandas as pd
    import pickle
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score
    from datetime import datetime
    
    print("Loading data...")
    
    # Column names for NSL-KDD dataset
    columns = [
        'Duration', 'Protocol Type', 'Service', 'Flag', 'Src Bytes', 'Dst Bytes', 
        'Land', 'Wrong Fragment', 'Urgent', 'Hot', 'Num Failed Logins', 'Logged In', 
        'Num Compromised', 'Root Shell', 'Su Attempted', 'Num Root', 'Num File Creations', 
        'Num Shells', 'Num Access Files', 'Num Outbound Cmds', 'Is Hot Logins', 
        'Is Guest Login', 'Count', 'Srv Count', 'Serror Rate', 'Srv Serror Rate', 
        'Rerror Rate', 'Srv Rerror Rate', 'Same Srv Rate', 'Diff Srv Rate', 
        'Srv Diff Host Rate', 'Dst Host Count', 'Dst Host Srv Count', 
        'Dst Host Same Srv Rate', 'Dst Host Diff Srv Rate', 'Dst Host Same Src Port Rate', 
        'Dst Host Srv Diff Host Rate', 'Dst Host Serror Rate', 'Dst Host Srv Serror Rate', 
        'Dst Host Rerror Rate', 'Dst Host Srv Rerror Rate', 'Class', 'Difficulty Level'
    ]
    
    selected_features = [
        'Duration', 'Protocol Type', 'Service', 'Flag', 
        'Src Bytes', 'Dst Bytes', 'Urgent'
    ]
    
    # Load training and test data
    df_train = pd.read_csv("../data/KDDTrain+.txt", names=columns)
    df_test = pd.read_csv("../data/KDDTest+.txt", names=columns)
    
    # Keep only selected features and target
    df_train = df_train[selected_features + ['Class']]
    df_test = df_test[selected_features + ['Class']]
    
    print(f"Training data shape: {df_train.shape}")
    print(f"Test data shape: {df_test.shape}")
    
    # Encode categorical features
    label_encoders = {}
    categorical_features = ['Protocol Type', 'Service', 'Flag']
    
    for feature in categorical_features:
        le = LabelEncoder()
        # Combine train and test data for consistent encoding
        combined_values = pd.concat([df_train[feature], df_test[feature]])
        le.fit(combined_values)
        
        df_train[feature] = le.transform(df_train[feature])
        df_test[feature] = le.transform(df_test[feature])
        label_encoders[feature] = le
        
    # Encode target labels
    target_encoder = LabelEncoder()
    known_labels = set(df_train["Class"])
    df_train["Class"] = target_encoder.fit_transform(df_train["Class"])
    
    # Filter test set for known labels only
    df_test = df_test[df_test["Class"].isin(known_labels)]
    df_test["Class"] = target_encoder.transform(df_test["Class"])
    
    print(f"Number of attack classes: {len(target_encoder.classes_)}")
    
    # Prepare features and labels
    X_train = df_train[selected_features]
    y_train = df_train["Class"]
    X_test = df_test[selected_features]
    y_test = df_test["Class"]
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("Training model...")
    
    # Train model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train_scaled, y_train)
    
    # Test model
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model accuracy: {accuracy:.4f}")
    
    # Create model package
    model_package = {
        'model': model,
        'scaler': scaler,
        'label_encoders': label_encoders,
        'target_encoder': target_encoder,
        'selected_features': selected_features,
        'training_timestamp': datetime.now().isoformat(),
        'model_type': 'RandomForestClassifier',
        'model_params': model.get_params()
    }
    
    # Create models directory
    if not os.path.exists("models"):
        os.makedirs("models")
        
    # Save model
    model_path = "models/intrusion_detection_model.pkl"
    with open(model_path, 'wb') as f:
        pickle.dump(model_package, f)
        
    print(f"Model saved to: {model_path}")
    print("Training completed successfully!")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
