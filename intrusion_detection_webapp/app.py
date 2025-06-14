from flask import Flask, render_template, jsonify
import numpy as np
import pandas as pd
import time
import threading
import random
from datetime import datetime
import pickle
import os
import queue
from collections import deque
from model_utils import ModelLoader

app = Flask(__name__)

# Global variables
traffic_queue = queue.Queue(maxsize=1000)
model_data = {}
traffic_stats = {
    'total_packets': 0,
    'normal_packets': 0,
    'attack_packets': 0,
    'last_update': datetime.now()
}
traffic_buffer = deque(maxlen=100)

class DatasetTrafficSimulator:
    def __init__(self):
        self.is_running = False
        self.selected_features = ['Duration', 'Protocol Type', 'Service', 'Flag', 'Src Bytes', 'Dst Bytes', 'Urgent']
        self.current_index = 0
        self.model_loader = ModelLoader()
        
    def load_model_and_data(self):
        """Load the trained model and actual dataset"""
        try:
            # Try to load the pickle model first
            model_path = "models/intrusion_detection_model.pkl"
            if os.path.exists(model_path):
                success = self.model_loader.load_model()
                if success:
                    print("Model loaded successfully from pickle file")
                    # Load dataset for simulation
                    return self._load_dataset()
                else:
                    print("Failed to load pickle model, falling back to training new model")
                    return self._train_new_model()
            else:
                print("Pickle model not found, training new model")
                return self._train_new_model()
                
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
            
    def _load_dataset(self):
        """Load dataset for traffic simulation"""
        try:
            columns = ['Duration', 'Protocol Type', 'Service', 'Flag', 'Src Bytes', 'Dst Bytes', 'Land', 'Wrong Fragment', 'Urgent', 'Hot', 'Num Failed Logins', 'Logged In', 'Num Compromised', 'Root Shell', 'Su Attempted', 'Num Root', 'Num File Creations', 'Num Shells', 'Num Access Files', 'Num Outbound Cmds', 'Is Hot Logins', 'Is Guest Login', 'Count', 'Srv Count', 'Serror Rate', 'Srv Serror Rate', 'Rerror Rate', 'Srv Rerror Rate', 'Same Srv Rate', 'Diff Srv Rate', 'Srv Diff Host Rate', 'Dst Host Count', 'Dst Host Srv Count', 'Dst Host Same Srv Rate', 'Dst Host Diff Srv Rate', 'Dst Host Same Src Port Rate', 'Dst Host Srv Diff Host Rate', 'Dst Host Serror Rate', 'Dst Host Srv Serror Rate', 'Dst Host Rerror Rate', 'Dst Host Srv Rerror Rate', 'Class', 'Difficulty Level']
            
            df_train = pd.read_csv("../data/KDDTrain+.txt", names=columns)
            df_test = pd.read_csv("../data/KDDTest+.txt", names=columns)
            df_combined = pd.concat([df_train, df_test]).reset_index(drop=True)
            
            # Select and prepare features
            self.dataset = df_combined[self.selected_features + ['Class']].copy()
            self.dataset = self.dataset.sample(frac=1).reset_index(drop=True)
            
            # Store globally for compatibility
            global model_data
            model_data = {
                'dataset': self.dataset,
                'model_loader': self.model_loader
            }
            
            return True
        except Exception as e:
            print(f"Error loading dataset: {e}")
            return False
            
    def _train_new_model(self):
        """Fallback: train a new model if pickle model is not available"""
        try:
            from sklearn.preprocessing import LabelEncoder, StandardScaler
            from sklearn.ensemble import RandomForestClassifier
            
            columns = ['Duration', 'Protocol Type', 'Service', 'Flag', 'Src Bytes', 'Dst Bytes', 'Land', 'Wrong Fragment', 'Urgent', 'Hot', 'Num Failed Logins', 'Logged In', 'Num Compromised', 'Root Shell', 'Su Attempted', 'Num Root', 'Num File Creations', 'Num Shells', 'Num Access Files', 'Num Outbound Cmds', 'Is Hot Logins', 'Is Guest Login', 'Count', 'Srv Count', 'Serror Rate', 'Srv Serror Rate', 'Rerror Rate', 'Srv Rerror Rate', 'Same Srv Rate', 'Diff Srv Rate', 'Srv Diff Host Rate', 'Dst Host Count', 'Dst Host Srv Count', 'Dst Host Same Srv Rate', 'Dst Host Diff Srv Rate', 'Dst Host Same Src Port Rate', 'Dst Host Srv Diff Host Rate', 'Dst Host Serror Rate', 'Dst Host Srv Serror Rate', 'Dst Host Rerror Rate', 'Dst Host Srv Rerror Rate', 'Class', 'Difficulty Level']
            
            df_train = pd.read_csv("../data/KDDTrain+.txt", names=columns)
            df_test = pd.read_csv("../data/KDDTest+.txt", names=columns)
            df_combined = pd.concat([df_train, df_test]).reset_index(drop=True)
            
            # Select and prepare features
            df_features = df_combined[self.selected_features + ['Class']].copy()
            
            # Encode categorical features
            label_encoders = {}
            for feature in ['Protocol Type', 'Service', 'Flag']:
                le = LabelEncoder()
                le.fit(df_features[feature])
                df_features[feature + '_encoded'] = le.transform(df_features[feature])
                label_encoders[feature] = le
            
            # Encode target
            target_encoder = LabelEncoder()
            df_features['Class_encoded'] = target_encoder.fit_transform(df_features['Class'])
            
            # Train model
            feature_cols = ['Duration', 'Protocol Type_encoded', 'Service_encoded', 'Flag_encoded', 'Src Bytes', 'Dst Bytes', 'Urgent']
            X = df_features[feature_cols]
            y = df_features['Class_encoded']
            
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            rf_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
            rf_model.fit(X_scaled, y)
            
            # Store globally
            global model_data
            model_data = {
                'model': rf_model,
                'scaler': scaler,
                'label_encoders': label_encoders,
                'target_encoder': target_encoder,
                'dataset': df_features.sample(frac=1).reset_index(drop=True),
                'feature_cols': feature_cols
            }
            return True
        except Exception as e:
            print(f"Error training new model: {e}")
            return False
    
    def generate_network_info(self):
        """Generate realistic network details"""
        return {
            'src_ip': f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}",
            'dst_ip': f"10.0.{random.randint(1, 255)}.{random.randint(1, 254)}",
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 22, 21, 25, 53, 23]),
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'service': random.choice(['HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP', 'DNS', 'TELNET'])        }
    
    def get_next_record(self):
        """Get next record from dataset"""
        if not hasattr(self, 'dataset') or self.dataset is None:
            # Try to get from global model_data for compatibility
            if 'dataset' in model_data:
                self.dataset = model_data['dataset']
            else:
                return None
            
        if self.current_index >= len(self.dataset):
            self.current_index = 0
            
        record = self.dataset.iloc[self.current_index].copy()
        self.current_index += 1
        return record
    
    def predict_traffic(self, record):
        """Make prediction on traffic record"""
        try:
            # First try using the pickle model loader
            if hasattr(self.model_loader, 'is_loaded') and self.model_loader.is_loaded:
                # Prepare data for the model loader
                data = {
                    'Duration': record['Duration'],
                    'Protocol Type': record['Protocol Type'],
                    'Service': record['Service'],
                    'Flag': record['Flag'],
                    'Src Bytes': record['Src Bytes'],
                    'Dst Bytes': record['Dst Bytes'],
                    'Urgent': record['Urgent']
                }
                
                result = self.model_loader.predict(data)
                return result['prediction'], result['confidence']
            
            # Fallback to the old method if pickle model not available
            elif 'model' in model_data:
                # Create DataFrame with proper column names to match training data
                features_df = pd.DataFrame({
                    'Duration': [record['Duration']],
                    'Protocol Type_encoded': [record['Protocol Type_encoded']],
                    'Service_encoded': [record['Service_encoded']],
                    'Flag_encoded': [record['Flag_encoded']],
                    'Src Bytes': [record['Src Bytes']],
                    'Dst Bytes': [record['Dst Bytes']],
                    'Urgent': [record['Urgent']]
                })
                
                features_scaled = model_data['scaler'].transform(features_df)
                prediction = model_data['model'].predict(features_scaled)[0]
                probability = model_data['model'].predict_proba(features_scaled)[0]
                class_name = model_data['target_encoder'].inverse_transform([prediction])[0]
                confidence = max(probability)
                return class_name, confidence
            else:
                return "unknown", 0.0
        except Exception as e:
            print(f"Prediction error: {e}")
            return "unknown", 0.0
    
    def process_record(self):
        """Process a single dataset record"""
        record = self.get_next_record()
        if record is None:
            return
            
        network_info = self.generate_network_info()
        prediction, confidence = self.predict_traffic(record)
        
        packet = {
            'timestamp': datetime.now().isoformat(),
            **network_info,
            'duration': float(record['Duration']),
            'src_bytes': int(record['Src Bytes']),
            'dst_bytes': int(record['Dst Bytes']),
            'prediction': prediction,
            'confidence': float(confidence),
            'is_attack': prediction != 'normal',
            'actual_class': record['Class'],
            'features': {
                'protocol_type': record['Protocol Type'],
                'service': record['Service'],
                'flag': record['Flag'],
                'urgent': int(record['Urgent'])
            }
        }
        
        # Update stats
        global traffic_stats
        traffic_stats['total_packets'] += 1
        if packet['is_attack']:
            traffic_stats['attack_packets'] += 1
        else:
            traffic_stats['normal_packets'] += 1
        traffic_stats['last_update'] = datetime.now()
        
        # Add to queues
        if not traffic_queue.full():
            traffic_queue.put(packet)
        traffic_buffer.append(packet)
    
    def start_traffic_simulation(self):
        """Start dataset-based simulation"""
        self.is_running = True
        
        def generate_traffic():
            while self.is_running:
                self.process_record()
                time.sleep(random.uniform(0.2, 1.0))
        
        thread = threading.Thread(target=generate_traffic, daemon=True)
        thread.start()
    
    def stop_traffic_simulation(self):
        """Stop simulation"""
        self.is_running = False

# Initialize
simulator = DatasetTrafficSimulator()

# Routes
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/start_simulation')
def start_simulation():
    if simulator.load_model_and_data():
        simulator.start_traffic_simulation()
        return jsonify({'status': 'started', 'message': 'Dataset traffic simulation started'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to load model and dataset'})

@app.route('/api/stop_simulation')
def stop_simulation():
    simulator.stop_traffic_simulation()
    return jsonify({'status': 'stopped', 'message': 'Traffic simulation stopped'})

@app.route('/api/traffic_data')
def get_traffic_data():
    packets = []
    while not traffic_queue.empty() and len(packets) < 20:
        try:
            packet = traffic_queue.get_nowait()
            packets.append(packet)
        except:
            break
    return jsonify({'packets': packets, 'stats': traffic_stats})

@app.route('/api/statistics')
def get_statistics():
    attack_types = {}
    for packet in list(traffic_buffer):
        if packet['is_attack']:
            attack_type = packet['prediction']
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
    
    return jsonify({
        'total_packets': traffic_stats['total_packets'],
        'normal_packets': traffic_stats['normal_packets'],
        'attack_packets': traffic_stats['attack_packets'],
        'attack_types': attack_types,
        'last_update': traffic_stats['last_update'].isoformat(),
        'attack_rate': (traffic_stats['attack_packets'] / max(traffic_stats['total_packets'], 1)) * 100
    })

@app.route('/api/live_feed')
def get_live_feed():
    recent_packets = list(traffic_buffer)[-10:]
    return jsonify({'packets': recent_packets, 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
