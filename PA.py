import tkinter as tk
from tkinter import messagebox
import math
import random
import string

#checks password strength and gives improvements on what's missing
def evaluate_password_strength(password, min_length, max_length, common_passwords_list):
    strength_score = 0
    password_issues = {}

    if len(password) < min_length or len(password) > max_length:
        password_issues["length_error"] = True
    else:
        strength_score += 10

    if any(char.islower() for char in password):
        strength_score += 20
    else:
        password_issues["lowercase_error"] = True

    if any(char.isupper() for char in password):
        strength_score += 20
    else:
        password_issues["uppercase_error"] = True

    if any(char.isdigit() for char in password):
        strength_score += 20
    else:
        password_issues["digit_error"] = True

    if any(not char.isalnum() for char in password):
        strength_score += 20
    else:
        password_issues["special_char_error"] = True

    if password.lower() in common_passwords_list:
        password_issues["common_password_error"] = True
        strength_score -= 20

    return {
        "strength_score": strength_score,
        "issues": password_issues
    }

#this calculates how random (entropy) your password is and average crack time
def calculate_entropy_and_time_to_crack(password, common_passwords_list=None, use_dictionary=True):
    character_sets = {
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits": "0123456789",
        "special": "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~"
    }
    total_characters = 0
    entropy = 0

    for charset in character_sets.values():
        if any(char in charset for char in password):
            total_characters += len(charset)

    if total_characters > 0:
        entropy = len(password) * math.log2(total_characters)

    #this applies dictionary logic only if use_dictionary is True
    if use_dictionary and common_passwords_list is not None and password.lower() in common_passwords_list:
        dict_entropy = math.log2(len(common_passwords_list))
        entropy = min(entropy, dict_entropy)

    guesses_per_second = 1e6
    time_to_crack = (2 ** entropy) / guesses_per_second

    return {
        "entropy": entropy,
        "time_to_crack": time_to_crack
    }

#formats the time (in seconds) into years, days, etc so its more readable
def format_time(seconds):
    years = seconds // (365 * 86400)
    seconds %= (365 * 86400)
    days = seconds // 86400
    seconds %= 86400
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return years, days, hours, minutes, seconds

#this is for huge numbers that are barely readable
def human_readable_years(years):
    suffixes = [
        (10**18, "quintillion"),
        (10**15, "quadrillion"),
        (10**12, "trillion"),
        (10**9, "billion"),
        (10**6, "million"),
        (10**3, "thousand")
    ]
    y = float(years)
    for scale, name in suffixes:
        if y >= scale:
            return f"{y / scale:.3f} {name} years"
    return f"{int(y)} years"

#makes the time output easier to understand
def format_time_with_suffixes(time_to_crack):
    years, days, hours, minutes, seconds = format_time(time_to_crack)
    if years >= 1000:
        years_str = human_readable_years(years)
        return f"{years_str}, {int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"
    else:
        return f"{int(years)} years, {int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"

#appends any missing password requirments to the end of the password
def enhance_password_based_on_input(password, min_length, max_length):
    additions = []
    if not any(char.islower() for char in password):
        additions.append(random.choice(string.ascii_lowercase))
    if not any(char.isupper() for char in password):
        additions.append(random.choice(string.ascii_uppercase))
    if not any(char.isdigit() for char in password):
        additions.append(random.choice(string.digits))
    if not any(not char.isalnum() for char in password):
        additions.append(random.choice("!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~"))

    total_length = len(password) + len(additions)
    if total_length < min_length:
        all_characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~"
        additions.extend(random.choices(all_characters, k=min_length - total_length))
        total_length = min_length

    enhanced_password = password + ''.join(additions)
    if len(enhanced_password) > max_length:
        enhanced_password = enhanced_password[:max_length]

    return enhanced_password
#makes a stronger password based off what you had already entered
def generate_related_strong_password(input_password, desired_length):
    lowercase_set = string.ascii_lowercase
    uppercase_set = string.ascii_uppercase
    digit_set = string.digits
    special_set = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~"
    all_chars = lowercase_set + uppercase_set + digit_set + special_set

    half_length = desired_length // 2
    related_chars = list(input_password[:half_length]) if len(input_password) >= half_length else list(input_password)

    has_lower = any(c.islower() for c in related_chars)
    has_upper = any(c.isupper() for c in related_chars)
    has_digit = any(c.isdigit() for c in related_chars)
    has_special = any(not ch.isalnum() for ch in related_chars)

    if not has_lower:
        related_chars.append(random.choice(lowercase_set))
    if not has_upper:
        related_chars.append(random.choice(uppercase_set))
    if not has_digit:
        related_chars.append(random.choice(digit_set))
    if not has_special:
        related_chars.append(random.choice(special_set))

    while len(related_chars) < desired_length:
        related_chars.append(random.choice(all_chars))

    random.shuffle(related_chars)
    return ''.join(related_chars[:desired_length])

#figures cost to crack based on 6 dollars per 2^32 guesses
def calculate_cost_to_crack(entropy):
    cost = 6.0 * (2 ** (entropy - 32)) if entropy > 32 else 6.0 * (2 ** (entropy - 32))
    return cost

#main function to analyze password, outputs a lot of information for the viewer
def analyze_password():
    password = password_entry.get()
    min_length = 12
    max_length = 20

    with open("100k.txt", "r", encoding="utf-8") as f:
        common_passwords_list = [line.strip().lower() for line in f if line.strip()]

    use_dictionary = use_dictionary_var.get()  # Get the state of dictionary usage

    strength_result = evaluate_password_strength(password, min_length, max_length, common_passwords_list)
    entropy_result = calculate_entropy_and_time_to_crack(password, common_passwords_list, use_dictionary=use_dictionary)
    entropy = entropy_result["entropy"]
    cost_to_crack = calculate_cost_to_crack(entropy)

    lowercase_count = sum(1 for char in password if char.islower())
    uppercase_count = sum(1 for char in password if char.isupper())
    digit_count = sum(1 for char in password if char.isdigit())
    special_char_count = sum(1 for char in password if not char.isalnum())

    message = f"Strength Score: {strength_result['strength_score']}/100\n"
    if strength_result['issues']:
        message += "Issues Found:\n"
        if "length_error" in strength_result['issues']:
            if len(password) < min_length:
                needed_length = min_length - len(password)
                message += f"- Length Error: Needs {needed_length} more character(s)\n"
            else:
                message += "- Length Error: Password too long\n"
        if "lowercase_error" in strength_result['issues']:
            message += "- Lowercase Error: Needs at least 1 lowercase letter\n"
        if "uppercase_error" in strength_result['issues']:
            message += "- Uppercase Error: Needs at least 1 uppercase letter\n"
        if "digit_error" in strength_result['issues']:
            message += "- Digit Error: Needs at least 1 digit\n"
        if "special_char_error" in strength_result['issues']:
            message += "- Special Char Error: Needs at least 1 special character\n"
        if "common_password_error" in strength_result['issues']:
            message += "- Common Password Error: This password is too common, choose something else\n"
    else:
        message += "No issues found. Your password is strong.\n"

    crack_time_formatted = format_time_with_suffixes(entropy_result["time_to_crack"])

    message += f"\nEntropy: {entropy:.2f} bits"
    message += f"\nEstimated Time to Crack: {crack_time_formatted}"
    message += f"\nEstimated Cost to Crack: ${cost_to_crack:,.2f}"
    message += f"\n\nCharacter Counts:\n"
    message += f"- Lowercase Letters: {lowercase_count}\n"
    message += f"- Uppercase Letters: {uppercase_count}\n"
    message += f"- Digits: {digit_count}\n"
    message += f"- Special Characters: {special_char_count}"

    if strength_result['strength_score'] < 100:
        suggested_password = enhance_password_based_on_input(password, min_length, max_length)
        second_suggested_password = generate_related_strong_password(password, 16)

        suggested_entropy_result = calculate_entropy_and_time_to_crack(suggested_password, common_passwords_list, use_dictionary=use_dictionary)
        suggested_entropy = suggested_entropy_result["entropy"]
        suggested_crack_time_formatted = format_time_with_suffixes(suggested_entropy_result["time_to_crack"])
        suggested_cost = calculate_cost_to_crack(suggested_entropy)

        second_suggested_entropy_result = calculate_entropy_and_time_to_crack(second_suggested_password, common_passwords_list, use_dictionary=use_dictionary)
        second_suggested_entropy = second_suggested_entropy_result["entropy"]
        second_suggested_crack_time_formatted = format_time_with_suffixes(second_suggested_entropy_result["time_to_crack"])
        second_suggested_cost = calculate_cost_to_crack(second_suggested_entropy)

        message += f"\n\nSuggested Strong Password: {suggested_password}\n(Strength Score: 100)"
        message += f"\nEntropy: {suggested_entropy:.2f} bits"
        message += f"\nEstimated Time to Crack: {suggested_crack_time_formatted}"
        message += f"\nEstimated Cost to Crack: ${suggested_cost:,.2f}"

        message += f"\n\nStronger Password: {second_suggested_password}\n(Strength Score: 100)"
        message += f"\nEntropy: {second_suggested_entropy:.2f} bits"
        message += f"\nEstimated Time to Crack: {second_suggested_crack_time_formatted}"
        message += f"\nEstimated Cost to Crack: ${second_suggested_cost:,.2f}"

    messagebox.showinfo("Password Analysis", message)

#changes visibility of password for user readability
def toggle_password_visibility():
    if password_entry.cget('show') == '':
        password_entry.config(show='*')
        toggle_button.config(text='Show Password')
    else:
        password_entry.config(show='')
        toggle_button.config(text='Hide Password')

root = tk.Tk()
root.title("Password Strength Analyzer")

password_label = tk.Label(root, text="Enter Password:")
password_label.pack(pady=10)

password_entry = tk.Entry(root, width=30, show="*")
password_entry.pack(pady=5)
password_entry.focus_set()

toggle_button = tk.Button(root, text="Show Password", command=toggle_password_visibility)
toggle_button.pack(pady=5)

use_dictionary_var = tk.BooleanVar(value=True)
use_dictionary_check = tk.Checkbutton(root, text="Use Dictionary-Based Entropy", variable=use_dictionary_var)
use_dictionary_check.pack(pady=5)

analyze_button = tk.Button(root, text="Analyze Password", command=analyze_password)
analyze_button.pack(pady=20)

root.mainloop()