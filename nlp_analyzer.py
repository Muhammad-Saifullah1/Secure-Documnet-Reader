import os
import pickle
import re

# Safely import spacy to handle underlying Torch DLL WinErrors
try:
    import spacy
    try:
        nlp = spacy.load("en_core_web_sm")
    except OSError:
        import subprocess
        print("Downloading spaCy model...")
        subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
        nlp = spacy.load("en_core_web_sm")
except Exception as e:
    print(f"Warning: Disabling SpaCy due to system DLL errors ({e}).")
    nlp = None

def load_ml_model():
    try:
        with open("models/vectorizer.pkl", "rb") as f:
            vectorizer = pickle.load(f)
        with open("models/classifier.pkl", "rb") as f:
            classifier = pickle.load(f)
        return vectorizer, classifier
    except FileNotFoundError:
        return None, None

def analyze_text(text):
    """
    Phase 3: ML powered intelligent text analysis
    """
    if not text.strip():
        return {
            "verdict": "SAFE",
            "confidence_score": 0.0,
            "suspicious_words": [],
            "suspicious_entities": []
        }
    
    vectorizer, classifier = load_ml_model()
    
    confidence_score = 0.0
    verdict = "SAFE"
    suspicious_words = []
    
    if vectorizer and classifier:
        # TF-IDF Vectorization
        X = vectorizer.transform([text])
        
        # ML Model classify
        prob = classifier.predict_proba(X)[0]
        malicious_prob = float(prob[1] * 100)
        
        confidence_score = malicious_prob
        
        # Determine Verdict
        if malicious_prob > 70:
            verdict = "MALICIOUS"
        elif malicious_prob > 40:
            verdict = "SUSPICIOUS"
            
        # Extract features (words) that contributed
        feature_names = vectorizer.get_feature_names_out()
        for i in X.nonzero()[1]:
            word = feature_names[i]
            if word in ['executable', 'virus', 'powershell', 'cmd', 'eval', 'payload', 'script']:
                suspicious_words.append(word)

    # spaCy suspicious entities extract
    suspicious_entities = []
    if nlp is not None:
        try:
            doc = nlp(text[:10000]) # chunk size
            for ent in doc.ents:
                if ent.label_ in ["URL", "IP_ADDRESS"] or ent.text.startswith("http"):
                    suspicious_entities.append(ent.text)
        except Exception:
            pass
            
    # Regex fallback for IPs and Common Command strings
    ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', text)
    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
    suspicious_entities.extend(ips)
    suspicious_entities.extend(urls)

    return {
        "verdict": verdict,
        "confidence_score": confidence_score,
        "suspicious_words": list(set(suspicious_words)),
        "suspicious_entities": list(set(suspicious_entities))
    }
