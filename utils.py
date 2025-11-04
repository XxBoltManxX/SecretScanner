import os
import re
import math
from pathlib import Path

def calc_entropy(text):
    if not text or len(text) == 0:
        return 0

    entropy_val = 0
    for char_code in range(256):
        try:
            occurrences = text.count(chr(char_code))
            if occurrences > 0:
                probability = float(occurrences) / len(text)
                entropy_val += - probability * math.log2(probability)
        except:
            continue
    return entropy_val

def check_if_binary(file_path):
    try:
        with open(file_path, 'rb') as file:
            sample = file.read(8192)
            if not sample:
                return False

            null_bytes = sample.count(b'\x00')
            if null_bytes > len(sample) * 0.3:
                return True

            printable_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
            non_printable = sum(1 for b in sample if b not in printable_chars)
            if non_printable > len(sample) * 0.3:
                return True

        return False
    except:
        return True

def looks_like_test_data(secret_value, line_text):
    test_indicators = [
        'example', 'sample', 'test', 'dummy', 'fake', 'todo', 'fixme',
        'placeholder', 'changeme', 'your-', 'my-', 'lorem', 'ipsum',
        'EXAMPLE', 'REPLACE', 'INSERT', 'UPDATE', 'SELECT', 'DELETE',
        '${', 'process.env', 'config.', 'settings.', 'os.getenv',
        '<your', '<my', 'TODO:', 'FIXME:', '***', 'xxxxx'
    ]

    lower_secret = secret_value.lower()
    lower_line = line_text.lower()

    for indicator in test_indicators:
        if indicator.lower() in lower_secret or indicator.lower() in lower_line:
            return True

    if secret_value.count('x') > len(secret_value) * 0.5:
        return True

    if secret_value.count('*') > 5:
        return True

    if secret_value.count('0') == len(secret_value) or secret_value.count('1') == len(secret_value):
        return True

    if re.match(r'^[0-9]+$', secret_value) and len(secret_value) < 16:
        return True

    return False

def extract_match_value(regex_match):
    try:
        for group_idx in range(regex_match.lastindex or 0, 0, -1):
            group_value = regex_match.group(group_idx)
            if group_value and len(group_value) > 5:
                return group_value
        return regex_match.group(0)
    except:
        return regex_match.group(0)
