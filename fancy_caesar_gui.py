import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk

# Caesar Cipher Functions
def encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            shifted = ((ord(char) - ord('a') + key) % 26) + ord('a')
            result += chr(shifted)
        else:
            result += char
    return result

def decrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            shifted = ((ord(char) - ord('a') - key) % 26) + ord('a')
            result += chr(shifted)
        else:
            result += char
    return result

# GUI Setup
def run_gui():
    def process_text(mode):
        try:
            key = int(key_entry.get())
            if not (1 <= key <= 25):
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Key", "Please enter a key between 1 and 25.")
            return

        text = input_text.get("1.0", tk.END).lower().strip()
        if not text:
            messagebox.showwarning("Empty Input", "Please enter some text.")
            return

        result = encrypt(text, key) if mode == 'e' else decrypt(text, key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)

    def clear_all():
        input_text.delete("1.0", tk.END)
        output_text.delete("1.0", tk.END)
        key_entry.delete(0, tk.END)

    def import_file():
        filepath = filedialog.askopenfilename(
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filepath:
            with open(filepath, "r", encoding="utf-8") as file:
                data = file.read()
                input_text.delete("1.0", tk.END)
                input_text.insert(tk.END, data)

    def export_file():
        result = output_text.get("1.0", tk.END).strip()
        if not result:
            messagebox.showinfo("No Output", "There is no result to export.")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filepath:
            with open(filepath, "w", encoding="utf-8") as file:
                file.write(result)
            messagebox.showinfo("Success", f"Result saved to {filepath}")

    # Main Window
    root = tk.Tk()
    root.title("🔐 Caesar Cipher - Encrypt/Decrypt with File Support")
    root.geometry("620x530")
    root.configure(bg="#f8f8f8")

    style = ttk.Style()
    style.configure("TLabel", font=("Segoe UI", 11), background="#f8f8f8")
    style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)

    tk.Label(root, text="Caesar Cipher Encryptor / Decryptor", font=("Segoe UI", 18, "bold"), bg="#f8f8f8", fg="#2a2a2a")\
        .grid(row=0, column=0, columnspan=4, pady=20)

    # Input Text
    ttk.Label(root, text="Enter text:").grid(row=1, column=0, sticky="w", padx=20)
    input_text = tk.Text(root, height=5, width=65, font=("Consolas", 11), wrap=tk.WORD, bd=2, relief="sunken")
    input_text.grid(row=2, column=0, columnspan=4, padx=20)

    # File Import Button
    ttk.Button(root, text="📂 Import from File", command=import_file).grid(row=3, column=0, padx=20, pady=5, sticky="w")

    # Key
    ttk.Label(root, text="Key (1-25):").grid(row=4, column=0, sticky="w", padx=20, pady=(10, 0))
    key_entry = ttk.Entry(root, width=10)
    key_entry.grid(row=4, column=1, sticky="w", pady=(10, 0))

    # Action Buttons
    button_frame = tk.Frame(root, bg="#f8f8f8")
    button_frame.grid(row=5, column=0, columnspan=4, pady=15)

    ttk.Button(button_frame, text="🔐 Encrypt", command=lambda: process_text('e')).grid(row=0, column=0, padx=10)
    ttk.Button(button_frame, text="🔓 Decrypt", command=lambda: process_text('d')).grid(row=0, column=1, padx=10)
    ttk.Button(button_frame, text="🧹 Clear", command=clear_all).grid(row=0, column=2, padx=10)

    # Output Text
    ttk.Label(root, text="Output:").grid(row=6, column=0, sticky="w", padx=20)
    output_text = tk.Text(root, height=5, width=65, font=("Consolas", 11), wrap=tk.WORD, bd=2, relief="sunken", fg="#006600")
    output_text.grid(row=7, column=0, columnspan=4, padx=20)

    # Export Button
    ttk.Button(root, text="💾 Export Output to File", command=export_file).grid(row=8, column=0, padx=20, pady=10, sticky="w")

    root.mainloop()

# Run it
run_gui()
