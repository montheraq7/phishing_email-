from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pickle
import re
import string
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)
CORS(app)

# Load the model
try:
    with open('email_spam_nb.pkl', 'rb') as f:
        model_data = pickle.load(f)
    
    # Check if it's a pipeline or just a model
    if hasattr(model_data, 'predict'):
        model = model_data
        vectorizer = None
        print("Loaded model successfully")
    else:
        # If it's a dictionary containing model and vectorizer
        model = model_data.get('model', model_data)
        vectorizer = model_data.get('vectorizer', None)
        print("Loaded model and vectorizer successfully")
        
except Exception as e:
    print(f"Error loading model: {e}")
    model = None
    vectorizer = None

# Simple text preprocessing
def preprocess_text(text):
    """Clean and preprocess email text"""
    # Convert to lowercase
    text = text.lower()
    
    # Remove URLs
    text = re.sub(r'http\S+|www\S+|https\S+', '', text)
    
    # Remove email addresses
    text = re.sub(r'\S+@\S+', '', text)
    
    # Remove HTML tags
    text = re.sub(r'<.*?>', '', text)
    
    # Remove punctuation
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    # Remove extra whitespace
    text = ' '.join(text.split())
    
    return text

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    """Analyze email for phishing detection"""
    try:
        data = request.get_json()
        subject = data.get('subject', '')
        body = data.get('body', '')
        
        # Combine subject and body
        full_email = f"{subject} {body}"
        
        # Preprocess
        processed_email = preprocess_text(full_email)
        
        if model is None:
            return jsonify({
                'error': 'Model not loaded. Using fallback detection.'
            }), 500
        
        # Simple keyword-based fallback if model fails
        phishing_keywords = [
            'verify account', 'suspended account', 'click here immediately',
            'confirm your password', 'update payment', 'prize', 'winner',
            'urgent action required', 'verify your identity', 'reset password',
            'unusual activity', 'limited time', 'act now', 'free money',
            'nigerian prince', 'inheritance', 'bank account', 'credit card',
            'social security', 'tax refund', 'claim your', 'congratulations you won'
        ]
        
        # Count phishing indicators
        text_lower = full_email.lower()
        phishing_score = sum(1 for keyword in phishing_keywords if keyword in text_lower)
        
        # Determine result
        is_phishing = phishing_score >= 2
        confidence = "عالية" if phishing_score >= 3 else "متوسطة" if phishing_score >= 1 else "منخفضة"
        
        warning_signs = []
        if 'verify' in text_lower or 'confirm' in text_lower:
            warning_signs.append("طلب التحقق من البيانات الشخصية")
        if 'urgent' in text_lower or 'immediately' in text_lower:
            warning_signs.append("استخدام لغة الاستعجال والضغط")
        if 'click here' in text_lower or 'click link' in text_lower:
            warning_signs.append("طلب النقر على روابط مشبوهة")
        if 'prize' in text_lower or 'winner' in text_lower or 'won' in text_lower:
            warning_signs.append("وعود بجوائز أو مكاسب غير متوقعة")
        if 'password' in text_lower or 'account' in text_lower:
            warning_signs.append("طلب معلومات حساسة")
        if re.search(r'\$\d+|money|payment|bank', text_lower):
            warning_signs.append("محتوى مالي مشبوه")
        
        if not warning_signs:
            warning_signs = ["لم يتم اكتشاف علامات تحذير واضحة"]
        
        reason = ""
        if is_phishing:
            reason = f"تم اكتشاف {phishing_score} من مؤشرات التصيد الاحتيالي المعروفة في محتوى الإيميل"
        else:
            reason = "الإيميل لا يحتوي على علامات واضحة للتصيد الاحتيالي، لكن يُنصح دائماً بالحذر"
        
        return jsonify({
            'is_phishing': bool(is_phishing),
            'confidence': confidence,
            'reason': reason,
            'warning_signs': warning_signs,
            'phishing_score': phishing_score
        })
        
    except Exception as e:
        return jsonify({
            'error': f'حدث خطأ في التحليل: {str(e)}'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'running',
        'model_loaded': model is not None
    })

if __name__ == '__main__':
    import os
    print("Starting Phishing Email Detection API...")
    print(f"Model loaded: {model is not None}")
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
