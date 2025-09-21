#!/usr/bin/env python3
"""
kasiski_vigenere.py

Пример реализации атаки на шифр Виженера:
1) метод Казиски — ищем повторяющиеся подстроки и расстояния между их вхождениями,
   собираем частые делители расстояний => кандидаты длины ключа.
2) для каждого кандидата длины ключа — разбиваем текст на "столбцы" и
   для каждого столбца подбираем сдвиг (как в шифре Цезаря), минимизируя chi^2
   относительно частот букв английского языка.

Работает с латиницей (a-z). Для коротких текстов/малого количества данных
Kasiski может ничего не найти — тогда скрипт перебирает разумный диапазон длин.
"""

from collections import defaultdict, Counter
import re
import math

ALPHABET = 'abcdefghijklmnopqrstuvwxyz'
ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702, 'f': 2.228,
    'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153, 'k': 0.772, 'l': 4.025,
    'm': 2.406, 'n': 6.749, 'o': 7.507, 'p': 1.929, 'q': 0.095, 'r': 5.987,
    's': 6.327, 't': 9.056, 'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150,
    'y': 1.974, 'z': 0.074
}

def clean_text(text: str) -> str:
    """Оставляем только буквы a-z в нижнем регистре."""
    return re.sub('[^a-z]', '', text.lower())

def find_repeated_substrings(text: str, min_len=3, max_len=5):
    """
    Ищем повторяющиеся подстроки длины от min_len до max_len.
    Возвращаем словарь {подстрока: [позиции_начала,...]}.
    """
    n = len(text)
    repeats = defaultdict(list)
    for L in range(min_len, max_len + 1):
        seen = {}
        for i in range(n - L + 1):
            sub = text[i:i+L]
            if sub in seen:
                # если уже встречалось — добавим оба индекса (если ещё не добавлены)
                if not repeats[sub]:
                    repeats[sub].append(seen[sub])
                repeats[sub].append(i)
            else:
                seen[sub] = i
    # Оставим только те, которые имеют >1 вхождения
    return {s: sorted(set(pos_list)) for s, pos_list in repeats.items() if len(pos_list) > 1}

def distances_from_positions(positions):
    """По списку позиций возвращает все попарные расстояния."""
    dists = []
    for i in range(len(positions)):
        for j in range(i+1, len(positions)):
            dists.append(positions[j] - positions[i])
    return dists

def divisors_counts(distances, max_div=30):
    """
    Для каждого расстояния считаем делители от 2 до max_div и считаем частоту делителей.
    Возвращаем Counter{делитель: частота}.
    """
    cnt = Counter()
    for d in distances:
        for div in range(2, max_div+1):
            if d % div == 0:
                cnt[div] += 1
    return cnt

def kasiski_candidates(ciphertext, min_sub_len=3, max_sub_len=5, top_n=6):
    cleaned = clean_text(ciphertext)
    repeats = find_repeated_substrings(cleaned, min_sub_len, max_sub_len)
    all_dists = []
    for sub, poses in repeats.items():
        all_dists += distances_from_positions(poses)
    if not all_dists:
        return [], repeats, Counter()
    div_counts = divisors_counts(all_dists)
    candidates = [d for d, _ in div_counts.most_common(top_n)]
    return candidates, repeats, div_counts

def chi_squared_score(sequence: str) -> float:
    """Chi-squared статистика для оценки, насколько распределение букв близко к английскому."""
    N = len(sequence)
    if N == 0:
        return float('inf')
    counts = Counter(sequence)
    chi2 = 0.0
    for ch in ALPHABET:
        observed = counts.get(ch, 0)
        expected = ENGLISH_FREQ[ch] * N / 100.0
        chi2 += (observed - expected) ** 2 / (expected + 1e-9)
    return chi2

def score_key_for_length(cleaned: str, key_len: int):
    """
    Для заданной длины ключа подбираем буквы ключа (сдвиги) по каждому столбцу,
    минимизируя chi^2. Возвращаем ключ и общую сумму chi^2 по столбцам.
    """
    columns = ['' for _ in range(key_len)]
    for i, ch in enumerate(cleaned):
        columns[i % key_len] += ch

    key = []
    total_score = 0.0
    for col in columns:
        best_shift = None
        best_score = float('inf')
        for shift in range(26):
            # применяем обратный сдвиг (дешифруем колонку этим shift)
            shifted = ''.join(ALPHABET[(ALPHABET.index(c) - shift) % 26] for c in col)
            s = chi_squared_score(shifted)
            if s < best_score:
                best_score = s
                best_shift = shift
        key.append(ALPHABET[best_shift])
        total_score += best_score
    return ''.join(key), total_score

def vigenere_decrypt(cleaned: str, key: str) -> str:
    out = []
    klen = len(key)
    for i, ch in enumerate(cleaned):
        ki = ALPHABET.index(key[i % klen])
        ci = ALPHABET.index(ch)
        pi = (ci - ki) % 26
        out.append(ALPHABET[pi])
    return ''.join(out)

def attack_vigenere(ciphertext: str, min_sub_len=3, max_sub_len=5, top_key_candidates=6, fallback_max_key_len=12):
    cleaned = clean_text(ciphertext)
    if not cleaned:
        raise ValueError("No letters found in ciphertext.")

    candidates, repeats, div_counts = kasiski_candidates(cleaned, min_sub_len, max_sub_len, top_key_candidates)

    # Если Kasiski ничего не дал — перебираем разумный диапазон длин
    if not candidates:
        candidates = list(range(1, fallback_max_key_len + 1))

    results = []
    for klen in candidates:
        key, score = score_key_for_length(cleaned, klen)
        plaintext = vigenere_decrypt(cleaned, key)
        # простая эвристика читаемости: доля гласных
        vowel_fraction = sum(plaintext.count(v) for v in 'aeiou') / max(1, len(plaintext))
        results.append({
            'key_len': klen,
            'key': key,
            'score': score,
            'vowel_frac': vowel_fraction,
            'plaintext': plaintext
        })
    # сортируем по лучшему (минимум) chi^2 (score)
    results.sort(key=lambda r: r['score'])
    return {
        'cleaned': cleaned,
        'repeats': repeats,
        'divisor_counts': div_counts,
        'results': results
    }

if __name__ == '__main__':
    # Пример использования:
    ciphertext = "mrttaqrhknsw ih puggrur"
    out = attack_vigenere(ciphertext, min_sub_len=3, max_sub_len=5, top_key_candidates=6, fallback_max_key_len=12)

    print("Cleaned ciphertext:", out['cleaned'])
    print("\nFound repeated substrings (Kasiski):")
    for s, poses in out['repeats'].items():
        print(f"  '{s}' at positions {poses}")
    print("\nMost frequent divisors (counts):")
    for d, cnt in out['divisor_counts'].most_common(10):
        print(f"  {d}: {cnt}")

    print("\nTop candidate keys and decryptions:")
    for i, r in enumerate(out['results'][:10], start=1):
        print(f"{i}. key_len={r['key_len']:2d}, key='{r['key']}', score={r['score']:.2f}, vowel_frac={r['vowel_frac']:.2f}")
        print("   plaintext:", r['plaintext'])
