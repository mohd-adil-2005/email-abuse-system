"""
Train spam/abuse detection model on SpamAssassin + Enron-Spam datasets.
Combines ~4,100 SpamAssassin emails + ~33,700 Enron-Spam emails for ~38k total.
"""
import json
import os
import csv
import sys
from datetime import datetime

# Enron CSV has very long Message fields - increase limit
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
import math
import re
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from typing import List, Tuple, Optional

# Base path for data (train_model.py is in backend/)
DATA_DIR = Path(__file__).parent / "data"
SPAMASSASSIN_DIR = DATA_DIR / "archive"
ENRON_CSV = DATA_DIR / "enron_spam" / "enron_spam_data.csv"

# Regex to find email addresses in text
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


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
    """Extract 11 features from email local part (or full text)."""
    local_part = email.split('@')[0].lower() if '@' in email else email.lower()
    # Sanitize: only alphanumeric, dot, underscore for consistent features
    local_part = re.sub(r'[^a-z0-9._]', '', local_part) or 'unknown'

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

    has_dot = 1 if "." in local_part else 0
    has_underscore = 1 if "_" in local_part else 0

    max_consecutive_digits = 0
    current_consecutive = 0
    for char in local_part:
        if char.isdigit():
            current_consecutive += 1
            max_consecutive_digits = max(max_consecutive_digits, current_consecutive)
        else:
            current_consecutive = 0

    entropy = calculate_entropy(local_part)
    keywords = ["spam", "test", "fake", "temp", "trash", "promo", "free", "gift", "win", "reward"]
    has_keyword = 1 if any(kw in local_part for kw in keywords) else 0

    return [
        float(length), float(digit_count), float(digit_ratio), float(letter_ratio),
        float(special_ratio), float(vowel_ratio), float(has_dot), float(has_underscore),
        float(max_consecutive_digits), float(entropy), float(has_keyword)
    ]


def _extract_email_from_text(text: str) -> Optional[str]:
    """Extract first email address from text, or None."""
    if not text or not isinstance(text, str):
        return None
    match = EMAIL_PATTERN.search(text)
    return match.group(0) if match else None


def _extract_local_from_raw_email(content: str) -> Optional[str]:
    """Extract sender email local part from raw email content (From: header)."""
    for line in content.split('\n'):
        if line.lower().startswith('from:'):
            email = _extract_email_from_text(line)
            if email:
                return email.split('@')[0]
            break
    # Fallback: search whole content for any email
    email = _extract_email_from_text(content)
    return email.split('@')[0] if email else None


def load_spamassassin() -> Tuple[List[List[float]], List[int]]:
    """Load SpamAssassin dataset from archive/easy_ham, hard_ham, spam_2."""
    data, labels = [], []
    # (folder_path, label: 0=ham, 1=spam)
    folders = [
        (SPAMASSASSIN_DIR / "easy_ham" / "easy_ham", 0),
        (SPAMASSASSIN_DIR / "hard_ham" / "hard_ham", 0),
        (SPAMASSASSIN_DIR / "spam_2" / "spam_2", 1),
    ]
    for folder, label in folders:
        if not folder.exists():
            print(f"  [skip] SpamAssassin folder not found: {folder}")
            continue
        count = 0
        for fpath in folder.iterdir():
            if fpath.is_file() and not fpath.name.startswith('.'):
                try:
                    content = fpath.read_text(encoding='utf-8', errors='ignore')
                    local = _extract_local_from_raw_email(content)
                    if local and len(local) >= 2:
                        data.append(extract_features(local + '@x.com'))
                        labels.append(label)
                        count += 1
                except Exception:
                    pass
        print(f"  SpamAssassin {folder.name}: {count} emails (label={label})")
    return data, labels


def load_enron_spam() -> Tuple[List[List[float]], List[int]]:
    """Load Enron-Spam CSV. Extracts email from Message/Subject, label from Spam/Ham."""
    data, labels = [], []
    if not ENRON_CSV.exists():
        print(f"  [skip] Enron-Spam CSV not found: {ENRON_CSV}")
        return data, labels
    try:
        with open(ENRON_CSV, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            # Expected columns: Message ID, Subject, Message, Spam/Ham, Date
            spam_ham_col = None
            for col in reader.fieldnames or []:
                if 'spam' in col.lower() and 'ham' in col.lower():
                    spam_ham_col = col
                    break
            if not spam_ham_col:
                spam_ham_col = 'Spam/Ham'
            count_ham, count_spam = 0, 0
            for row in reader:
                msg = (row.get('Message') or '').strip()
                subj = (row.get('Subject') or '').strip()
                spam_ham = (row.get(spam_ham_col) or 'ham').strip().lower()
                label = 1 if spam_ham == 'spam' else 0
                # Prefer email from Message, fallback to Subject (use as local-part proxy)
                email = _extract_email_from_text(msg) or _extract_email_from_text(subj)
                if email:
                    text_for_features = email
                elif subj:
                    text_for_features = re.sub(r'[^a-zA-Z0-9._-]', '', subj)[:80]
                    if len(text_for_features) >= 2:
                        text_for_features = text_for_features + '@x.com'
                    else:
                        text_for_features = None
                else:
                    text_for_features = None
                if text_for_features and len(text_for_features) >= 4:
                    data.append(extract_features(text_for_features))
                    labels.append(label)
                    if label == 0:
                        count_ham += 1
                    else:
                        count_spam += 1
            print(f"  Enron-Spam: {count_ham} ham, {count_spam} spam, total {len(data)}")
    except Exception as e:
        print(f"  [error] Enron-Spam: {e}")
    return data, labels


def train_model():
    print("Loading datasets...")
    data, labels = [], []
    metadata = {"datasets": {}, "training_date": datetime.now().isoformat()}

    # 1. SpamAssassin
    if SPAMASSASSIN_DIR.exists():
        print("SpamAssassin:")
        d1, l1 = load_spamassassin()
        data.extend(d1)
        labels.extend(l1)
        metadata["datasets"]["SpamAssassin"] = {"samples": len(d1), "ham": int(sum(1 for x in l1 if x == 0)), "spam": int(sum(1 for x in l1 if x == 1))}
    else:
        print(f"SpamAssassin dir not found: {SPAMASSASSIN_DIR}")
        metadata["datasets"]["SpamAssassin"] = {"samples": 0}

    # 2. Enron-Spam
    print("Enron-Spam:")
    d2, l2 = load_enron_spam()
    data.extend(d2)
    labels.extend(l2)
    metadata["datasets"]["Enron-Spam"] = {"samples": len(d2), "ham": int(sum(1 for x in l2 if x == 0)), "spam": int(sum(1 for x in l2 if x == 1))}

    if not data:
        print("No data loaded. Falling back to synthetic data.")
        metadata["datasets"]["Synthetic"] = {"samples": 4}
        for local in ["john.doe", "alice", "spam123", "test_fake"]:
            data.append(extract_features(local + "@x.com"))
            labels.append(0 if "spam" not in local and "test" not in local and "fake" not in local else 1)

    X = np.array(data)
    y = np.array(labels)
    ham_count = int(np.sum(y == 0))
    spam_count = int(np.sum(y == 1))
    metadata["total_samples"] = len(X)
    metadata["total_ham"] = ham_count
    metadata["total_spam"] = spam_count
    metadata["model"] = "RandomForestClassifier (n_estimators=200, max_depth=15)"

    print(f"\nTotal: {len(X)} samples ({ham_count} ham, {spam_count} spam)")
    print("Training Random Forest...")
    model = RandomForestClassifier(n_estimators=200, max_depth=15, min_samples_split=2, random_state=42)
    model.fit(X, y)

    app_dir = Path(__file__).parent / "app"
    model_path = app_dir / "spam_model.joblib"
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

    # Save metadata so you can verify training data anytime
    meta_path = app_dir / "spam_model_info.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to {meta_path}")


if __name__ == "__main__":
    train_model()
