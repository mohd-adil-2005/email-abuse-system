import os
import math
import re
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from typing import List, Tuple

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    char_counts = {}
    for char in text.lower():
        char_counts[char] = char_counts.get(char, 0) + 1
    length = len(text)
    entropy_value = 0.0
    for count in char_counts.values():
        if count > 0:
            prob = count / length
            entropy_value -= prob * math.log2(prob)
    return entropy_value

def extract_features(email: str) -> List[float]:
    local_part = email.split('@')[0].lower() if '@' in email else email.lower()
    
    length = len(local_part)
    digit_count = sum(c.isdigit() for c in local_part)
    letter_count = sum(c.isalpha() for c in local_part)
    special_count = length - digit_count - letter_count
    
    digit_ratio = digit_count / length if length > 0 else 0
    letter_ratio = letter_count / length if length > 0 else 0
    special_ratio = special_count / length if length > 0 else 0
    
    vowels = set("aeiou")
    vowel_count = sum(1 for c in local_part if c in vowels)
    vowel_ratio = vowel_count / letter_count if letter_count > 0 else 0
    
    # Presence of common separators (often legit)
    has_dot = 1 if "." in local_part else 0
    has_underscore = 1 if "_" in local_part else 0
    
    # Max consecutive digits (high in spam/system generated)
    max_consecutive_digits = 0
    current_consecutive = 0
    for char in local_part:
        if char.isdigit():
            current_consecutive += 1
            max_consecutive_digits = max(max_consecutive_digits, current_consecutive)
        else:
            current_consecutive = 0
            
    entropy = calculate_entropy(local_part)
    
    # Keyword check
    keywords = ["spam", "test", "fake", "temp", "trash", "promo", "free", "gift", "win", "reward"]
    has_keyword = 1 if any(kw in local_part for kw in keywords) else 0
    
    return [
        float(length), 
        float(digit_count), 
        float(digit_ratio), 
        float(letter_ratio), 
        float(special_ratio), 
        float(vowel_ratio),
        float(has_dot),
        float(has_underscore),
        float(max_consecutive_digits),
        float(entropy), 
        float(has_keyword)
    ]

def train_model():
    print("Generating enhanced synthetic training data...")
    # 0 = Legitimate, 1 = Abuse
    data = []
    labels = []
    
    # Legitimate email patterns
    legit_names = [
        "john.doe", "alice.smith", "bob.wilson", "marketing.team", 
        "support", "contact", "info", "hr_department", "j.smith",
        "sarah123", "mike_ross", "emma.brown22", "david.jones.88",
        "pete", "a.kumar", "mohd.adil", "user.name", "first.last",
        "office.manager", "sales_lead", "it.support"
    ]
    for email in legit_names:
        data.append(extract_features(email))
        labels.append(0)
        
    # Abusive email patterns
    abuse_emails = [
        "asdfghjkl123", "qer12345678", "user9876543210", "temp_mail_88",
        "test_spam_001", "free_promo_cheap", "xzy_99_abc_123", "a1b2c3d4e5f6",
        "random.junk.12345", "trashmail888", "fake.account.99", "1234567890",
        "bot.account.007", "spammy.mcss", "win.gift.now", "reward.card.123",
        "kjhgfdsazxcv", "998877665544", "temp098123", "trash.box.99"
    ]
    for email in abuse_emails:
        data.append(extract_features(email))
        labels.append(1)

    # Add more synthetic variety
    for _ in range(100):
        # Legit variety: names with dots, underscores, some numbers
        first = "".join(np.random.choice(list("abcdefghijklmnopqrstuvwxyz"), np.random.randint(3, 8)))
        last = "".join(np.random.choice(list("abcdefghijklmnopqrstuvwxyz"), np.random.randint(3, 8)))
        sep = np.random.choice([".", "_", ""])
        num = str(np.random.randint(1, 99)) if np.random.random() > 0.7 else ""
        data.append(extract_features(f"{first}{sep}{last}{num}"))
        labels.append(0)
        
        # Abuse variety: long random strings, high numbers
        junk = "".join(np.random.choice(list("abcdefghijklmnopqrstuvwxyz0123456789"), np.random.randint(10, 25)))
        data.append(extract_features(junk))
        labels.append(1)
        
        # Stealthy abuse: looks like names but random mix
        fake_name = "".join(np.random.choice(list("bcdfghjklmnpqrstvwxyz"), np.random.randint(8, 15))) # No vowels
        data.append(extract_features(fake_name))
        labels.append(1)

    X = np.array(data)
    y = np.array(labels)

    print(f"Training Smarter Random Forest on {len(X)} samples...")
    # Increase estimators and depth for "smarter" model
    model = RandomForestClassifier(n_estimators=200, max_depth=15, min_samples_split=2, random_state=42)
    model.fit(X, y)

    model_path = os.path.join("app", "spam_model.joblib")
    joblib.dump(model, model_path)
    print(f"Smarter Model saved to {model_path}")

if __name__ == "__main__":
    train_model()
