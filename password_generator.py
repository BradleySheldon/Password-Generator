"""
Bradley Sheldon
10/28/2025
"""

import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import string, secrets, csv, math, re
from datetime import datetime

AMBIGUOUS = 'O0l1I'

# ------------------------------
# Generate secure passwords
# ------------------------------
def generate_password():
    try:
        length = int(length_entry.get())
        count = int(count_entry.get())
        if length < 4:
            raise ValueError("Length must be at least 4")
        if count < 1:
            raise ValueError("Must generate at least 1 password")
    except ValueError as e:
        messagebox.showerror("Invalid Input", str(e))
        return

    char_pool = ""
    if use_upper.get(): char_pool += string.ascii_uppercase
    if use_lower.get(): char_pool += string.ascii_lowercase
    if use_digits.get(): char_pool += string.digits
    if use_symbols.get(): char_pool += string.punctuation
    if avoid_ambiguous.get():
        char_pool = ''.join(c for c in char_pool if c not in AMBIGUOUS)

    if not char_pool:
        messagebox.showerror("Invalid Selection", "Select at least one character set.")
        return

    output_text.delete("1.0", tk.END)
    global last_passwords
    last_passwords = [''.join(secrets.choice(char_pool) for _ in range(length)) for _ in range(count)]

    if show_separators.get():
        formatted_output = ('\n' + '-' * 30 + '\n').join(f"{i+1}. {pw}" for i, pw in enumerate(last_passwords)) + '\n'
    else:
        formatted_output = '\n'.join(f"{i+1}. {pw}" for i, pw in enumerate(last_passwords)) + '\n'

    output_text.insert(tk.END, formatted_output)
    evaluate_strength_all(last_passwords)

# ------------------------------
# Evaluate all generated passwords
# ------------------------------
def evaluate_strength_all(passwords):
    scores = [evaluate_strength(pw) for pw in passwords]
    avg_score = sum(scores) / len(scores)
    if avg_score <= 2:
        strength, color = "Weak", "red"
    elif avg_score == 3:
        strength, color = "Medium", "orange"
    else:
        strength, color = "Strong", "green"
    strength_overall_label.config(text=f"Strength: {strength}", fg=color)

# ------------------------------
# Simple score used only for generated passwords
# ------------------------------
def evaluate_strength(pw):
    score = 0
    if len(pw) >= 12: score += 1
    if any(c in string.ascii_lowercase for c in pw): score += 1
    if any(c in string.ascii_uppercase for c in pw): score += 1
    if any(c in string.digits for c in pw): score += 1
    if any(c in string.punctuation for c in pw): score += 1
    return score

# ------------------------------
# Utilities
# ------------------------------
def copy_to_clipboard():
    text = output_text.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()
    messagebox.showinfo("Copied", "Password(s) copied to clipboard!")

def save_to_file():
    if not last_passwords:
        messagebox.showwarning("No Passwords", "Please generate passwords first.")
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_filename = f"passwords_{timestamp}.txt"
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default_filename, filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, 'w') as file:
                file.write('\n'.join(last_passwords))
            messagebox.showinfo("Saved", f"Passwords saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

def save_to_csv():
    if not last_passwords:
        messagebox.showwarning("No Passwords", "Please generate passwords first.")
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_filename = f"passwords_{timestamp}.csv"
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=default_filename, filetypes=[("CSV Files", "*.csv")])
    if file_path:
        try:
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Index", "Password"])
                for i, pw in enumerate(last_passwords, start=1):
                    writer.writerow([i, pw])
            messagebox.showinfo("Saved", f"Passwords saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# =================================================================
#                        ROOT + SCROLLABLE UI
# =================================================================
root = tk.Tk()
root.title("Password Generator")
# Let the OS show maximize; allow resizing both ways
root.minsize(800, 600)
root.resizable(True, True)

# Try to start maximized on most platforms
try:
    root.state("zoomed")
except Exception:
    try:
        root.attributes("-zoomed", True)
    except Exception:
        pass  # fall back to default window size

style = ttk.Style(root)
style.theme_use("clam")
style.configure("Custom.TCheckbutton", font=("Segoe UI", 10), background="white", foreground="black", focuscolor="none")
style.map("Custom.TCheckbutton", background=[('selected', '#cce5ff')], foreground=[('selected', 'black')])

# --- Scrollable container pattern: Canvas + inner Frame ---
outer = tk.Frame(root)
outer.pack(fill="both", expand=True)

canvas = tk.Canvas(outer, highlightthickness=0)
vscroll = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
canvas.configure(yscrollcommand=vscroll.set)

vscroll.pack(side="right", fill="y")
canvas.pack(side="left", fill="both", expand=True)

content = tk.Frame(canvas)
content_id = canvas.create_window((0, 0), window=content, anchor="nw")

def _on_content_configure(event=None):
    canvas.configure(scrollregion=canvas.bbox("all"))
    canvas.itemconfig(content_id, width=canvas.winfo_width())

def _on_canvas_configure(event=None):
    canvas.itemconfig(content_id, width=event.width)

content.bind("<Configure>", _on_content_configure)
canvas.bind("<Configure>", _on_canvas_configure)

# Mousewheel scrolling
def _on_mousewheel(event):
    if event.delta:  # Windows / MacOS
        canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    else:
        if event.num == 4:
            canvas.yview_scroll(-3, "units")
        elif event.num == 5:
            canvas.yview_scroll(3, "units")

canvas.bind_all("<MouseWheel>", _on_mousewheel)     # Windows / Mac
canvas.bind_all("<Button-4>", _on_mousewheel)       # Linux up
canvas.bind_all("<Button-5>", _on_mousewheel)       # Linux down

# =================================================================
#                        GENERATOR UI
# =================================================================
length_label = tk.Label(content, text="Password Length:")
length_label.pack(pady=5, anchor="w")
length_entry = tk.Entry(content)
length_entry.pack(pady=5, anchor="w")
length_entry.insert(0, "12")

count_label = tk.Label(content, text="Number of Passwords:")
count_label.pack(pady=5, anchor="w")
count_entry = tk.Entry(content)
count_entry.pack(pady=5, anchor="w")
count_entry.insert(0, "1")

use_upper = tk.BooleanVar(value=True)
use_lower = tk.BooleanVar(value=True)
use_digits = tk.BooleanVar(value=True)
use_symbols = tk.BooleanVar(value=True)
avoid_ambiguous = tk.BooleanVar(value=False)
show_separators = tk.BooleanVar(value=True)

for label, var in [
    ("Include Uppercase (A-Z)", use_upper),
    ("Include Lowercase (a-z)", use_lower),
    ("Include Numbers (0-9)", use_digits),
    ("Include Symbols (!@#...)", use_symbols),
    ("Avoid Ambiguous Characters (O, 0, l, 1)", avoid_ambiguous),
    ("Show Dashed Separators", show_separators),
]:
    ttk.Checkbutton(content, text=label, variable=var, style="Custom.TCheckbutton").pack(anchor='w', padx=20)

tk.Button(content, text="Generate Password", command=generate_password).pack(pady=10, anchor="w")

output_frame = tk.Frame(content)
output_frame.pack(pady=5, fill="both", expand=True)
output_scroll = tk.Scrollbar(output_frame)
output_scroll.pack(side=tk.RIGHT, fill=tk.Y)

# Make Text expand with window
output_text = tk.Text(output_frame, height=10, font=("Courier", 12), yscrollcommand=output_scroll.set)
output_text.pack(side=tk.LEFT, fill="both", expand=True)
output_scroll.config(command=output_text.yview)

strength_overall_label = tk.Label(content, text="Strength: ", font=("Segoe UI", 10, "bold"))
strength_overall_label.pack(pady=5, anchor="w")

btns_frame = tk.Frame(content)
btns_frame.pack(pady=5, anchor="w")
tk.Button(btns_frame, text="Copy to Clipboard", command=copy_to_clipboard).pack(side="left", padx=(0,8))
tk.Button(btns_frame, text="Save to File", command=save_to_file).pack(side="left", padx=(0,8))
tk.Button(btns_frame, text="Save to CSV", command=save_to_csv).pack(side="left")

last_passwords = []

# =================================================================
#                PASSWORD STRENGTH ANALYZER
# =================================================================
COMMON_SUBSTRINGS = [
    "password","letmein","iloveyou","admin","welcome","dragon","football","monkey","qwerty",
    "abc123","123456","111111","654321","baseball","master","shadow","trustno1"
]
KEYBOARD_RUNS = ["qwerty","asdf","zxcv","12345","09876","7890"]

def estimate_entropy_bits(pw: str) -> float:
    pool = 0
    if any(c.islower() for c in pw): pool += 26
    if any(c.isupper() for c in pw): pool += 26
    if any(c.isdigit() for c in pw): pool += 10
    if any(c in string.punctuation for c in pw): pool += len(string.punctuation)
    if pool == 0 and pw:
        pool = 10
    return len(pw) * math.log2(pool) if pw else 0.0

def analyze_password(pw: str):
    detail = {
        "length": len(pw),
        "has_lower": any(c.islower() for c in pw),
        "has_upper": any(c.isupper() for c in pw),
        "has_digit": any(c.isdigit() for c in pw),
        "has_symbol": any(c in string.punctuation for c in pw),
        "repeats": bool(re.search(r'(.)\1{2,}', pw)),
        "sequential_inc": bool(re.search(r'0123|1234|2345|3456|4567|5678|6789', pw)),
        "sequential_dec": bool(re.search(r'9876|8765|7654|6543|5432|4321|3210', pw)),
        "keyboard_run": any(k in pw.lower() for k in KEYBOARD_RUNS),
        "common_substring": any(word in pw.lower() for word in COMMON_SUBSTRINGS),
        "has_space": " " in pw
    }
    entropy_bits = estimate_entropy_bits(pw)
    base = min(80, entropy_bits)
    variety = sum([detail["has_lower"], detail["has_upper"], detail["has_digit"], detail["has_symbol"]])
    bonus = (variety - 1) * 5
    score = base + bonus
    penalties = 0
    if detail["length"] < 12: penalties += (12 - detail["length"]) * 2
    if detail["repeats"]: penalties += 8
    if detail["sequential_inc"] or detail["sequential_dec"]: penalties += 8
    if detail["keyboard_run"]: penalties += 10
    if detail["common_substring"]: penalties += 15
    score = max(0, min(100, score - penalties))
    if score < 35: rating = "Weak"
    elif score < 60: rating = "Medium"
    elif score < 85: rating = "Strong"
    else: rating = "Very Strong"
    suggestions = []
    if detail["length"] < 16: suggestions.append("Increase length (aim for 16+).")
    if variety < 3: suggestions.append("Use a mix of upper/lowercase, digits, and symbols.")
    if detail["repeats"]: suggestions.append("Avoid repeated characters (e.g., 'aaa').")
    if detail["sequential_inc"] or detail["sequential_dec"]: suggestions.append("Avoid sequences like '1234' or '9876'.")
    if detail["keyboard_run"]: suggestions.append("Avoid keyboard runs like 'qwerty' or 'asdf'.")
    if detail["common_substring"]: suggestions.append("Avoid common words/phrases (e.g., 'password', 'admin').")
    if not suggestions and rating != "Very Strong":
        suggestions.append("Consider using a random passphrase with 4–5 words.")
    return {"rating": rating, "score": int(round(score)), "entropy_bits": round(entropy_bits, 1), "detail": detail, "suggestions": suggestions}

def on_toggle_show():
    if pw_entry.cget("show") == "":
        pw_entry.config(show="•")
        show_btn.config(text="Show")
    else:
        pw_entry.config(show="")
        show_btn.config(text="Hide")

def on_check_strength():
    pw = pw_var.get()
    if not pw:
        analyzer_status.config(text="Enter a password to analyze.", fg="gray")
        analyzer_progress["value"] = 0
        rating_value.config(text="—", fg="black")
        entropy_value.config(text="—")
        feedback_list.config(state="normal"); feedback_list.delete("1.0", tk.END); feedback_list.config(state="disabled")
        return
    result = analyze_password(pw)
    rating_value.config(text=result["rating"])
    entropy_value.config(text=f"{result['entropy_bits']} bits")
    analyzer_progress["value"] = result["score"]
    color = {"Weak": "red", "Medium": "orange", "Strong": "green", "Very Strong": "darkgreen"}[result["rating"]]
    rating_value.config(fg=color)
    feedback_list.config(state="normal"); feedback_list.delete("1.0", tk.END)
    if result["suggestions"]:
        for s in result["suggestions"]:
            feedback_list.insert(tk.END, f"• {s}\n")
    else:
        feedback_list.insert(tk.END, "Looks great. No immediate improvements needed.\n")
    feedback_list.config(state="disabled")
    analyzer_status.config(text="Analysis complete. (Local & offline; nothing is stored.)", fg="black")

# ---- Analyzer UI ----
separator = ttk.Separator(content, orient="horizontal")
separator.pack(fill="x", pady=10)

analyzer_frame = tk.Frame(content, bd=1, relief=tk.GROOVE, padx=10, pady=10)
analyzer_frame.pack(fill="x", padx=10, pady=10)

title = tk.Label(analyzer_frame, text="Password Strength Analyzer (Add-On)", font=("Segoe UI", 12, "bold"))
title.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0,8))

pw_label = tk.Label(analyzer_frame, text="Enter a password to check:")
pw_label.grid(row=1, column=0, sticky="w")

pw_var = tk.StringVar()
pw_entry = tk.Entry(analyzer_frame, textvariable=pw_var, width=50, show="•")
pw_entry.grid(row=1, column=1, sticky="we", padx=(6,6))
analyzer_frame.grid_columnconfigure(1, weight=1)

show_btn = tk.Button(analyzer_frame, text="Show", command=on_toggle_show, width=6)
show_btn.grid(row=1, column=2, sticky="w")

check_btn = tk.Button(analyzer_frame, text="Check Strength", command=on_check_strength)
check_btn.grid(row=1, column=3, sticky="w", padx=(6,0))

progress_label = tk.Label(analyzer_frame, text="Score:")
progress_label.grid(row=2, column=0, sticky="w", pady=(10,0))
analyzer_progress = ttk.Progressbar(analyzer_frame, orient="horizontal", mode="determinate", maximum=100)
analyzer_progress.grid(row=2, column=1, columnspan=3, sticky="we", pady=(10,0))

rating_label2 = tk.Label(analyzer_frame, text="Rating:")
rating_label2.grid(row=3, column=0, sticky="w", pady=(6,0))
rating_value = tk.Label(analyzer_frame, text="—", font=("Segoe UI", 10, "bold"))
rating_value.grid(row=3, column=1, sticky="w", pady=(6,0))

entropy_label = tk.Label(analyzer_frame, text="Estimated entropy:")
entropy_label.grid(row=4, column=0, sticky="w", pady=(2,0))
entropy_value = tk.Label(analyzer_frame, text="—")
entropy_value.grid(row=4, column=1, sticky="w", pady=(2,0))

sugg_label = tk.Label(analyzer_frame, text="Suggestions:")
sugg_label.grid(row=5, column=0, sticky="nw", pady=(8,0))
feedback_list = tk.Text(analyzer_frame, width=60, height=5, wrap="word")
feedback_list.grid(row=5, column=1, columnspan=3, sticky="we", pady=(8,0))
feedback_list.config(state="disabled")

analyzer_status = tk.Label(analyzer_frame, text="Offline analysis. Your input is not stored.", fg="gray")
analyzer_status.grid(row=6, column=0, columnspan=4, sticky="w", pady=(6,0))

# ------------------------------
# Main loop
# ------------------------------
last_passwords = []
root.mainloop()
