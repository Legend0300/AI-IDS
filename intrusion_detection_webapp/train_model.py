"""
Intrusion Detection Model Training Script
This script trains a Random Forest model for network intrusion detection
and saves the trained model and preprocessing components as pickle files.
"""

import numpy as np
import pandas as pd
import pickle
import os
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from datetime import datetime

class IntrusionDetectionTrainer:
    def __init__(self):
        self.selected_features = [
            'Duration',        # Time-based feature (connection duration)
            'Protocol Type',   # Protocol (TCP, UDP, ICMP equivalent)
            'Service',         # Service/Port concept
            'Flag',           # TCP flags
            'Src Bytes',      # Source packet size
            'Dst Bytes',      # Destination packet size  
            'Urgent'          # Urgent pointer flag
        ]
        self.label_encoders = {}
        self.target_encoder = None
        self.scaler = None
        self.model = None
        
    def load_data(self):
        """Load and prepare the NSL-KDD dataset"""
        print("Loading NSL-KDD dataset...")
        
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
        
        # Load training and test data
        train_path = "../data/KDDTrain+.txt"
        test_path = "../data/KDDTest+.txt"
        
        if not os.path.exists(train_path) or not os.path.exists(test_path):
            raise FileNotFoundError(f"Dataset files not found. Please ensure {train_path} and {test_path} exist.")
        
        self.df_train = pd.read_csv(train_path, names=columns)
        self.df_test = pd.read_csv(test_path, names=columns)
        
        # Keep only selected features and target
        self.df_train = self.df_train[self.selected_features + ['Class']]
        self.df_test = self.df_test[self.selected_features + ['Class']]
        
        print(f"Training data shape: {self.df_train.shape}")
        print(f"Test data shape: {self.df_test.shape}")
        print(f"Selected features: {self.selected_features}")
        
    def preprocess_data(self):
        """Encode categorical features and scale numerical features"""
        print("Preprocessing data...")
        
        # Encode categorical features
        categorical_features = ['Protocol Type', 'Service', 'Flag']
        
        for feature in categorical_features:
            le = LabelEncoder()
            # Combine train and test data for consistent encoding
            combined_values = pd.concat([self.df_train[feature], self.df_test[feature]])
            le.fit(combined_values)
            
            self.df_train[feature] = le.transform(self.df_train[feature])
            self.df_test[feature] = le.transform(self.df_test[feature])
            self.label_encoders[feature] = le
            
        # Encode target labels
        self.target_encoder = LabelEncoder()
        known_labels = set(self.df_train["Class"])
        self.df_train["Class"] = self.target_encoder.fit_transform(self.df_train["Class"])
        
        # Filter test set for known labels only
        self.df_test = self.df_test[self.df_test["Class"].isin(known_labels)]
        self.df_test["Class"] = self.target_encoder.transform(self.df_test["Class"])
        
        print(f"Number of attack classes: {len(self.target_encoder.classes_)}")
        print(f"Attack types: {list(self.target_encoder.classes_)}")
        
        # Prepare features and labels
        self.X_train = self.df_train[self.selected_features]
        self.y_train = self.df_train["Class"]
        self.X_test = self.df_test[self.selected_features]
        self.y_test = self.df_test["Class"]
        
        # Scale features
        self.scaler = StandardScaler()
        self.X_train_scaled = self.scaler.fit_transform(self.X_train)
        self.X_test_scaled = self.scaler.transform(self.X_test)
        
        print(f"Training features shape: {self.X_train_scaled.shape}")
        print(f"Test features shape: {self.X_test_scaled.shape}")
        
    def train_model(self):
        """Train the Random Forest model"""
        print("Training Random Forest model...")
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        # Train the model
        self.model.fit(self.X_train_scaled, self.y_train)
        
        # Make predictions
        y_pred = self.model.predict(self.X_test_scaled)
        
        # Calculate accuracy
        accuracy = accuracy_score(self.y_test, y_pred)
        print(f"Model accuracy: {accuracy:.4f}")
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'Feature': self.selected_features,
            'Importance': self.model.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        print("\nFeature Importance:")
        for _, row in feature_importance.iterrows():
            print(f"  {row['Feature']}: {row['Importance']:.4f}")
            
        # Classification report
        print("\nClassification Report:")
        present_labels = np.unique(self.y_test)
        present_class_names = self.target_encoder.classes_[present_labels]
        report = classification_report(
            self.y_test, y_pred,
            labels=present_labels,
            target_names=present_class_names
        )
        print(report)
        
        return accuracy
        
    def save_model(self, model_dir="models"):
        """Save the trained model and preprocessing components"""
        print("Saving model and preprocessing components...")
        
        # Create models directory if it doesn't exist
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
            
        # Create model package
        model_package = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'target_encoder': self.target_encoder,
            'selected_features': self.selected_features,
            'training_timestamp': datetime.now().isoformat(),
            'model_type': 'RandomForestClassifier',
            'model_params': self.model.get_params()
        }
        
        # Save as pickle file
        model_path = os.path.join(model_dir, "intrusion_detection_model.pkl")
        with open(model_path, 'wb') as f:
            pickle.dump(model_package, f)
            
        print(f"Model saved to: {model_path}")
        
        # Also save individual components for compatibility
        individual_files = {
            'model.pkl': self.model,
            'scaler.pkl': self.scaler,
            'label_encoders.pkl': self.label_encoders,
            'target_encoder.pkl': self.target_encoder
        }
        
        for filename, component in individual_files.items():
            file_path = os.path.join(model_dir, filename)
            with open(file_path, 'wb') as f:
                pickle.dump(component, f)
                
        print("Individual components also saved for compatibility")
        
    def run_training_pipeline(self):
        """Run the complete training pipeline"""
        print("Starting intrusion detection model training pipeline...")
        print("=" * 60)
        
        try:
            # Load data
            self.load_data()
            print()
            
            # Preprocess data
            self.preprocess_data()
            print()
            
            # Train model
            accuracy = self.train_model()
            print()
            
            # Save model
            self.save_model()
            print()
            
            print("=" * 60)
            print(f"Training completed successfully!")
            print(f"Final model accuracy: {accuracy:.4f}")
            print("Model files saved in 'models/' directory")
            
        except Exception as e:
            print(f"Training failed with error: {e}")
            raise

def main():
    """Main training function"""
    trainer = IntrusionDetectionTrainer()
    trainer.run_training_pipeline()

if __name__ == "__main__":
    main()
