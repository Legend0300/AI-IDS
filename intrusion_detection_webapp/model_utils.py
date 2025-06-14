"""
Model Loading Utility
This module provides functions to load the trained intrusion detection model
and make predictions on network traffic data.
"""

import pickle
import os
import pandas as pd
import numpy as np
from datetime import datetime

class ModelLoader:
    def __init__(self, model_path="models/intrusion_detection_model.pkl"):
        self.model_path = model_path
        self.model_package = None
        self.is_loaded = False
        
    def load_model(self):
        """Load the trained model and preprocessing components"""
        try:
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
                
            with open(self.model_path, 'rb') as f:
                self.model_package = pickle.load(f)
                
            # Verify model package contents
            required_keys = ['model', 'scaler', 'label_encoders', 'target_encoder', 'selected_features']
            for key in required_keys:
                if key not in self.model_package:
                    raise ValueError(f"Missing required component in model package: {key}")
                    
            self.is_loaded = True
            print(f"Model loaded successfully from {self.model_path}")
            print(f"Training timestamp: {self.model_package.get('training_timestamp', 'Unknown')}")
            print(f"Model type: {self.model_package.get('model_type', 'Unknown')}")
            
            return True
            
        except Exception as e:
            print(f"Error loading model: {e}")
            self.is_loaded = False
            return False
            
    def get_model_info(self):
        """Get information about the loaded model"""
        if not self.is_loaded:
            return None
            
        return {
            'model_type': self.model_package.get('model_type', 'Unknown'),
            'training_timestamp': self.model_package.get('training_timestamp', 'Unknown'),
            'selected_features': self.model_package['selected_features'],
            'num_classes': len(self.model_package['target_encoder'].classes_),
            'classes': list(self.model_package['target_encoder'].classes_),
            'model_params': self.model_package.get('model_params', {})
        }
        
    def preprocess_data(self, data):
        """Preprocess input data for prediction"""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")
            
        # Ensure data is a DataFrame
        if isinstance(data, dict):
            data = pd.DataFrame([data])
        elif not isinstance(data, pd.DataFrame):
            raise ValueError("Data must be a dictionary or pandas DataFrame")
            
        # Select required features
        selected_features = self.model_package['selected_features']
        
        # Check if all required features are present
        missing_features = set(selected_features) - set(data.columns)
        if missing_features:
            raise ValueError(f"Missing required features: {missing_features}")
            
        # Select only required features
        data_subset = data[selected_features].copy()
        
        # Encode categorical features
        label_encoders = self.model_package['label_encoders']
        categorical_features = ['Protocol Type', 'Service', 'Flag']
        
        for feature in categorical_features:
            if feature in data_subset.columns:
                le = label_encoders[feature]
                # Handle unknown categories
                try:
                    data_subset[feature] = le.transform(data_subset[feature])
                except ValueError:
                    # If unknown category, use the most common class (0)
                    print(f"Warning: Unknown category in {feature}, using default encoding")
                    data_subset[feature] = 0
                    
        # Scale features
        scaler = self.model_package['scaler']
        data_scaled = scaler.transform(data_subset)
        
        return data_scaled
        
    def predict(self, data):
        """Make predictions on input data"""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")
            
        # Preprocess data
        data_scaled = self.preprocess_data(data)
        
        # Make predictions
        model = self.model_package['model']
        predictions = model.predict(data_scaled)
        probabilities = model.predict_proba(data_scaled)
        
        # Decode predictions
        target_encoder = self.model_package['target_encoder']
        class_names = target_encoder.inverse_transform(predictions)
        
        # Get confidence scores
        confidence_scores = np.max(probabilities, axis=1)
        
        # Format results
        results = []
        for i in range(len(predictions)):
            results.append({
                'prediction': class_names[i],
                'confidence': float(confidence_scores[i]),
                'is_attack': class_names[i] != 'normal',
                'probability_distribution': {
                    target_encoder.classes_[j]: float(probabilities[i][j])
                    for j in range(len(target_encoder.classes_))
                }
            })
            
        return results if len(results) > 1 else results[0]
        
    def predict_single(self, duration=0, protocol_type='tcp', service='http', flag='SF', 
                      src_bytes=0, dst_bytes=0, urgent=0):
        """Make prediction on a single network connection record"""
        data = {
            'Duration': duration,
            'Protocol Type': protocol_type,
            'Service': service,
            'Flag': flag,
            'Src Bytes': src_bytes,
            'Dst Bytes': dst_bytes,
            'Urgent': urgent
        }
        
        return self.predict(data)

# Global model loader instance
_model_loader = None

def get_model_loader():
    """Get the global model loader instance"""
    global _model_loader
    if _model_loader is None:
        _model_loader = ModelLoader()
    return _model_loader

def load_model(model_path="models/intrusion_detection_model.pkl"):
    """Load the model using the global loader"""
    loader = get_model_loader()
    loader.model_path = model_path
    return loader.load_model()

def predict_traffic(data):
    """Make predictions using the global model loader"""
    loader = get_model_loader()
    return loader.predict(data)

def get_model_info():
    """Get model information using the global loader"""
    loader = get_model_loader()
    return loader.get_model_info()

if __name__ == "__main__":
    # Test the model loader
    loader = ModelLoader()
    if loader.load_model():
        print("Model loaded successfully!")
        
        # Test prediction
        test_data = {
            'Duration': 0.1,
            'Protocol Type': 'tcp',
            'Service': 'http',
            'Flag': 'SF',
            'Src Bytes': 1000,
            'Dst Bytes': 500,
            'Urgent': 0
        }
        
        result = loader.predict(test_data)
        print(f"Test prediction: {result}")
    else:
        print("Failed to load model!")
