import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from PIL import Image, ImageTk
import os
import sys

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# Cargar imagen
try:
    logo_path = resource_path("images.png")
    logo = Image.open(logo_path)
    logo = logo.resize((100, 100))
    logo_img = ImageTk.PhotoImage(logo)
    label_logo = tk.Label(root, image=logo_img, bg="red")
    label_logo.image = logo_img  # prevenir garbage collection
    label_logo.pack()
except Exception as e:
    print(f"No se pudo cargar el logo: {e}")

class PhishingGUI:
    def __init__(self, root):
        self.root = root
        root.title("Detector de Phishing - Desafío INCIBE")
        root.geometry("900x650")
        root.configure(bg="#e0e6f0")
        root.resizable(False, False)

        # Estilo
        style = ttk.Style()
        style.configure("TNotebook", background="#ffffff")
        style.configure("TNotebook.Tab", font=("Helvetica", 12, "bold"), padding=[10, 5])
        style.configure("TButton", font=("Helvetica", 12), padding=10)

        # Header
        header_frame = tk.Frame(root, bg="#b71c1c", pady=15)
        header_frame.pack(fill=tk.X)

        title_label = tk.Label(
            header_frame,
            text="Desafío INCIBE - Detector de Phishing",
            font=("Helvetica", 24, "bold"),
            bg="#b71c1c",
            fg="#ffffff"
        )
        title_label.pack()

        # Cargar imagen
        image_path = resource_path("images.png")
        try:
            print(f"Intentando cargar la imagen desde: {image_path}")
            img = Image.open(image_path)
            img = img.resize((200, 50), Image.Resampling.LANCZOS)
            self.logo = ImageTk.PhotoImage(img)
            logo_label = tk.Label(header_frame, image=self.logo, bg="#b71c1c")
            logo_label.pack(pady=10)
        except Exception as e:
            error_label = tk.Label(
                header_frame,
                text=f"No se pudo cargar el logo: {str(e)}",
                font=("Helvetica", 10),
                bg="#b71c1c",
                fg="#ffffff"
            )
            error_label.pack()

        author_label = tk.Label(
            header_frame,
            text="Autores: Álvaro Sánchez-Palencia Gómez & Pablo Sánchez-Palencia Gómez",
            font=("Helvetica", 11, "italic"),
            bg="#b71c1c",
            fg="#ffffff"
        )
        author_label.pack(pady=5)

        # Notebook
        notebook = ttk.Notebook(root)
        notebook.pack(pady=15, padx=10, fill=tk.BOTH, expand=True)

        # Introducción
        intro_frame = tk.Frame(notebook, bg="#ffffff")
        notebook.add(intro_frame, text="Introducción")

        intro_text = tk.Label(
            intro_frame,
            text=(
                "Bienvenido al Detector de Phishing del Desafío INCIBE\n\n"
                "Protege tu bandeja de entrada identificando correos sospechosos de phishing.\n"
                "Este programa analiza tu correo de Gmail para detectar amenazas potenciales "
                "mediante un sistema avanzado de puntuación y verificación de enlaces.\n\n"
                "Instrucciones:\n"
                "1. Conecta tu cuenta de Gmail usando el botón 'Conectar a Gmail'.\n"
                "2. Una vez conectado, haz clic en 'Revisar Correos' para analizar tu bandeja.\n"
                "3. Revisa los resultados en el área de salida y verifica los correos etiquetados."
            ),
            font=("Helvetica", 12),
            bg="#ffffff",
            fg="#333333",
            wraplength=800,
            justify="left"
        )
        intro_text.pack(pady=20, padx=20)

        # Programa
        program_frame = tk.Frame(notebook, bg="#ffffff")
        notebook.add(program_frame, text="Ejecutar Programa")

        button_frame = tk.Frame(program_frame, bg="#ffffff")
        button_frame.pack(pady=10)

        self.connect_btn = tk.Button(
            button_frame,
            text="Conectar a Gmail",
            command=self.connect,
            bg="#b71c1c",
            fg="#ffffff",
            font=("Helvetica", 12, "bold"),
            relief=tk.FLAT,
            padx=15,
            pady=8,
            activebackground="#d32f2f",
            cursor="hand2"
        )
        self.connect_btn.pack(pady=10)

        self.check_btn = tk.Button(
            button_frame,
            text="Revisar Correos",
            command=self.check_emails,
            state=tk.DISABLED,
            bg="#757575",
            fg="#ffffff",
            font=("Helvetica", 12, "bold"),
            relief=tk.FLAT,
            padx=15,
            pady=8,
            activebackground="#9e9e9e",
            cursor="hand2"
        )
        self.check_btn.pack(pady=10)

        output_frame = tk.Frame(program_frame, bg="#ffffff")
        output_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.output = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            width=100,
            height=15,
            font=("Courier", 10),
            bg="#f5f5f5",
            fg="#333333",
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground="#cccccc"
        )
        self.output.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Registro
        log_frame = tk.Frame(notebook, bg="#ffffff")
        notebook.add(log_frame, text="Registro")

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            width=100,
            height=20,
            font=("Courier", 10),
            bg="#f5f5f5",
            fg="#333333",
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground="#cccccc"
        )
        self.log_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.update_log()
        self.root.after(5000, self.auto_update_log)

        self.mail = None

    def connect(self):
        try:
            from check_google_file_email import connect_to_mail
            self.mail = connect_to_mail()
            if self.mail:
                messagebox.showinfo("Éxito", "Conectado a Gmail correctamente.")
                self.connect_btn.config(bg="#4caf50")
                self.check_btn.config(state=tk.NORMAL, bg="#b71c1c")
                self.output.delete(1.0, tk.END)
                self.output.insert(tk.END, "Conexión establecida. Listo para revisar correos.\n")
            else:
                messagebox.showerror("Error", "No se pudo conectar a Gmail.")
        except Exception as e:
            messagebox.showerror("Error", f"Error de conexión: {e}")
            self.output.delete(1.0, tk.END)
            self.output.insert(tk.END, f"Error de conexión: {e}\n")

    def check_emails(self):
        try:
            from check_google_file_email import read_emails
            self.output.delete(1.0, tk.END)
            self.output.insert(tk.END, "Analizando correos... Por favor, espera.\n")
            self.root.config(cursor="watch")
            self.root.update()

            phishing_count = read_emails(self.mail, max_emails=10)
            self.output.insert(tk.END, f"\nAnálisis completado.\n")
            self.output.insert(tk.END, f"Se han encontrado {phishing_count} correos con posible phishing.\n")
            self.output.insert(tk.END, "Por favor, revisa los correos etiquetados como 'posible-phishing' en tu bandeja de entrada.\n")
            self.output.insert(tk.END, "Consulta el log (phishing_detector.log) para más detalles.\n")
        except Exception as e:
            self.output.insert(tk.END, f"Error durante el análisis: {e}\n")
            messagebox.showerror("Error", f"Error: {e}")
        finally:
            self.root.config(cursor="")

    def update_log(self):
        if os.path.exists("phishing_detector.log"):
            with open("phishing_detector.log", "r", encoding="utf-8") as f:
                lines = f.readlines()
                if len(lines) > 100:
                    lines = lines[-100:]
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, "".join(lines))

    def auto_update_log(self):
        self.update_log()
        self.root.after(5000, self.auto_update_log)

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingGUI(root)
    root.mainloop()
