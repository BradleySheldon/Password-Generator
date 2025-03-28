import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import string, secrets, csv
from datetime import datetime

AMBIGUOUS = 'O0l1I'

# Generate secure passwords
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

# Evaluate all passwords

def evaluate_strength_all(passwords):
    scores = [evaluate_strength(pw) for pw in passwords]
    avg_score = sum(scores) / len(scores)
    if avg_score <= 2:
        strength, color = "Weak", "red"
    elif avg_score == 3:
        strength, color = "Medium", "orange"
    else:
        strength, color = "Strong", "green"
    strength_label.config(text=f"Strength: {strength}", fg=color)

# Score per password

def evaluate_strength(pw):
    score = 0
    if len(pw) >= 12: score += 1
    if any(c in string.ascii_lowercase for c in pw): score += 1
    if any(c in string.ascii_uppercase for c in pw): score += 1
    if any(c in string.digits for c in pw): score += 1
    if any(c in string.punctuation for c in pw): score += 1
    return score

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

root = tk.Tk()
root.title("Password Generator")
root.geometry("800x800")
root.resizable(False, False)

style = ttk.Style(root)
style.theme_use("clam")
style.configure("Custom.TCheckbutton", font=("Segoe UI", 10), background="white", foreground="black", focuscolor="none")
style.map("Custom.TCheckbutton", background=[('selected', '#cce5ff')], foreground=[('selected', 'black')])

length_label = tk.Label(root, text="Password Length:")
length_label.pack(pady=5)
length_entry = tk.Entry(root)
length_entry.pack(pady=5)
length_entry.insert(0, "12")

count_label = tk.Label(root, text="Number of Passwords:")
count_label.pack(pady=5)
count_entry = tk.Entry(root)
count_entry.pack(pady=5)
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
    ttk.Checkbutton(root, text=label, variable=var, style="Custom.TCheckbutton").pack(anchor='w', padx=20)

tk.Button(root, text="Generate Password", command=generate_password).pack(pady=10)

output_frame = tk.Frame(root)
output_frame.pack(pady=5)
output_scroll = tk.Scrollbar(output_frame)
output_scroll.pack(side=tk.RIGHT, fill=tk.Y)
output_text = tk.Text(output_frame, height=10, width=60, font=("Courier", 12), yscrollcommand=output_scroll.set)
output_text.pack()
output_scroll.config(command=output_text.yview)

strength_label = tk.Label(root, text="Strength: ", font=("Segoe UI", 10, "bold"))
strength_label.pack(pady=5)

tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard).pack(pady=5)
tk.Button(root, text="Save to File", command=save_to_file).pack(pady=5)
tk.Button(root, text="Save to CSV", command=save_to_csv).pack(pady=5)

last_passwords = []

root.mainloop()
