import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

def train_and_save_model():
    print("Training NLP ML model for malicious text classification...")
    
    # Basic dummy training dataset based on common attack vectors
    texts = [
        "This is a normal document with regular text and notes.",
        "Please find the meeting notes attached for Q3 revenue.",
        "Revenue grew by 20 percent in the last financial quarter.",
        "The quick brown fox jumps over the lazy dog.",
        "Hello, how are you today? Let's catch up.",
        
        "Click here to run this executable file and install the virus.",
        "Download the powershell script to bypass security immediately.",
        "Your account is compromised, please run this cmd.exe command.",
        "eval(base64_decode('some malicious payload here'));",
        "WScript.Shell execute malware.exe immediately to gain root."
    ]
    labels = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1] # 0 = Safe, 1 = Malicious
    
    # Text extract and TF-IDF Vectorization
    vectorizer = TfidfVectorizer(lowercase=True, stop_words='english')
    X = vectorizer.fit_transform(texts)
    
    # ML model classify training
    model = MultinomialNB()
    model.fit(X, labels)
    
    # Save the model
    os.makedirs("models", exist_ok=True)
    with open("models/vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)
    with open("models/classifier.pkl", "wb") as f:
        pickle.dump(model, f)
        
    print("Model trained and saved locally in 'models' folder.")

if __name__ == "__main__":
    train_and_save_model()
