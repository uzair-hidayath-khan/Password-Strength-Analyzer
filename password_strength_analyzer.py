"""Password Strength Analyzer.

A GUI and CLI application for evaluating password strength and
generating cryptographically secure passwords.

Features:
- Password strength analysis using zxcvbn
- Password complexity validation
- Common and banned password detection
- Secure password generation using the secrets module
- Improvement recommendations
- JSON export without storing plaintext passwords
- Activity logging without recording passwords
- GUI and CLI interfaces
"""

import argparse
import json
import logging
import re
import secrets
import string
import sys
import tkinter as tk
from tkinter import filedialog, messagebox

from zxcvbn import zxcvbn


# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------

logging.basicConfig(
    filename="password_checker.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# ---------------------------------------------------------------------------
# Wordlist Handling
# ---------------------------------------------------------------------------

class Wordlist:
    """Load and manage password wordlists efficiently."""

    _cache = {}

    def __init__(self, file_path):
        self.file_path = file_path
        self.words = self.load_wordlist()

    def load_wordlist(self):
        """Load a wordlist and cache it for future use."""

        if self.file_path in self._cache:
            return self._cache[self.file_path]

        try:
            with open(
                self.file_path,
                "r",
                encoding="utf-8"
            ) as file:
                wordlist = {
                    line.strip().lower()
                    for line in file
                    if line.strip()
                }

            self._cache[self.file_path] = wordlist
            return wordlist

        except FileNotFoundError as error:
            raise FileNotFoundError(
                f"Wordlist file '{self.file_path}' was not found."
            ) from error

        except OSError as error:
            raise RuntimeError(
                f"Unable to read wordlist '{self.file_path}': {error}"
            ) from error

    def is_word_in_list(self, word):
        """Check whether a word exists in the wordlist."""

        return word.lower() in self.words


# ---------------------------------------------------------------------------
# Strength Result
# ---------------------------------------------------------------------------

class StrengthResult:
    """Store the result of a password strength analysis."""

    def __init__(
        self,
        strength,
        score,
        message,
        suggestions=None
    ):
        self.strength = strength
        self.score = score
        self.message = message
        self.suggestions = suggestions or []


# ---------------------------------------------------------------------------
# Password Strength Analysis
# ---------------------------------------------------------------------------

class PasswordStrength:
    """Perform password strength analysis and secure generation."""

    def __init__(
        self,
        weak_wordlist_path="./weak_passwords.txt",
        banned_wordlist_path="./banned_passwords.txt"
    ):
        self.weak_wordlist = (
            Wordlist(weak_wordlist_path)
            if weak_wordlist_path
            else None
        )

        self.banned_wordlist = (
            Wordlist(banned_wordlist_path)
            if banned_wordlist_path
            else None
        )

        self.min_password_length = 12

        self.strength_mapping = {
            0: "Very Weak",
            1: "Weak",
            2: "Moderate",
            3: "Strong",
            4: "Very Strong"
        }

        self.special_characters = "!@#$%^&*(),.?\":{}|<>[]_-+=~`'\\/;"

    # -----------------------------------------------------------------------
    # Password Strength Checking
    # -----------------------------------------------------------------------

    def check_password_strength(self, password):
        """Evaluate the strength of a password."""

        if not password:
            return StrengthResult(
                "Invalid",
                0,
                "Password cannot be empty."
            )

        # Length check
        if len(password) < self.min_password_length:
            return StrengthResult(
                "Too Short",
                0,
                (
                    f"Password should be at least "
                    f"{self.min_password_length} characters long."
                ),
                [
                    (
                        f"Increase the password length to at least "
                        f"{self.min_password_length} characters."
                    )
                ]
            )

        # Banned password check
        if (
            self.banned_wordlist
            and self.banned_wordlist.is_word_in_list(password)
        ):
            return StrengthResult(
                "Banned",
                0,
                (
                    "This password is not allowed because it is "
                    "commonly found in password breach databases."
                ),
                [
                    "Choose a completely different password.",
                    "Avoid passwords that have appeared in data breaches."
                ]
            )

        # Weak/common password check
        if (
            self.weak_wordlist
            and self.weak_wordlist.is_word_in_list(password)
        ):
            return StrengthResult(
                "Weak",
                0,
                "This password is commonly used and easily guessable.",
                [
                    "Avoid common passwords.",
                    "Use a longer and more unpredictable password."
                ]
            )

        # zxcvbn analysis
        password_strength = zxcvbn(password)

        score = password_strength["score"]
        strength = self.strength_mapping.get(score, "Unknown")

        # Complexity analysis
        complexity_issues = []

        if not re.search(r"[A-Z]", password):
            complexity_issues.append("uppercase letters")

        if not re.search(r"[a-z]", password):
            complexity_issues.append("lowercase letters")

        if not re.search(r"\d", password):
            complexity_issues.append("numbers")

        if not re.search(
            r"""[!@#$%^&*(),.?":{}|<>\[\]_\-+=~`'/\\;]""",
            password
        ):
            complexity_issues.append("special characters")

        # zxcvbn suggestions
        feedback = password_strength.get("feedback", {})
        zxcvbn_suggestions = feedback.get("suggestions", [])

        suggestions = list(zxcvbn_suggestions)

        if complexity_issues:
            complexity_message = (
                "Password lacks some recommended character types. "
                f"Missing: {', '.join(complexity_issues)}."
            )

            for issue in complexity_issues:
                suggestion = f"Add {issue}."

                if suggestion not in suggestions:
                    suggestions.append(suggestion)

            return StrengthResult(
                "Weak" if score < 3 else strength,
                score,
                complexity_message,
                suggestions
            )

        # Strong password
        if score >= 3:
            return StrengthResult(
                strength,
                score,
                (
                    "Password meets the recommended security "
                    f"requirements. Score: {score}/4."
                ),
                suggestions
            )

        # Moderate/weak password
        return StrengthResult(
            strength,
            score,
            (
                f"Password is {strength.lower()}. "
                "Consider making it longer and less predictable."
            ),
            suggestions
        )

    # -----------------------------------------------------------------------
    # Improvement Suggestions
    # -----------------------------------------------------------------------

    def suggest_improvements(self, password):
        """Generate actionable recommendations for a password."""

        result = self.check_password_strength(password)

        suggestions = []

        if len(password) < self.min_password_length:
            suggestions.append(
                f"Increase length to at least "
                f"{self.min_password_length} characters."
            )

        if not re.search(r"[A-Z]", password):
            suggestions.append("Add uppercase letters.")

        if not re.search(r"[a-z]", password):
            suggestions.append("Add lowercase letters.")

        if not re.search(r"\d", password):
            suggestions.append("Add numbers.")

        if not re.search(
            r"""[!@#$%^&*(),.?":{}|<>\[\]_\-+=~`'/\\;]""",
            password
        ):
            suggestions.append("Add special characters.")

        # Add zxcvbn suggestions
        for suggestion in result.suggestions:
            if suggestion and suggestion not in suggestions:
                suggestions.append(suggestion)

        if not suggestions:
            return "No major improvements required."

        return (
            "Suggested improvements:\n\n"
            + "\n".join(f"- {item}" for item in suggestions)
        )

    # -----------------------------------------------------------------------
    # Secure Password Generation
    # -----------------------------------------------------------------------

    def generate_random_password(self, length=16):
        """Generate a cryptographically secure random password.

        The generated password contains at least:
        - One uppercase letter
        - One lowercase letter
        - One number
        - One special character
        """

        if length < 12:
            raise ValueError(
                "Generated passwords must be at least 12 characters long."
            )

        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = self.special_characters

        # Guarantee required character categories.
        password_characters = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]

        all_characters = (
            uppercase
            + lowercase
            + digits
            + special
        )

        # Fill remaining positions.
        for _ in range(length - 4):
            password_characters.append(
                secrets.choice(all_characters)
            )

        # Securely shuffle the generated characters.
        for index in range(len(password_characters) - 1, 0, -1):
            random_index = secrets.randbelow(index + 1)
            password_characters[index], password_characters[random_index] = (
                password_characters[random_index],
                password_characters[index]
            )

        return "".join(password_characters)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class PasswordStrengthGUI:
    """Graphical user interface for the password analyzer."""

    def __init__(self, master):
        self.master = master

        master.title("Password Strength Analyzer")
        master.geometry("600x600")
        master.resizable(False, False)

        self.password_strength = PasswordStrength()

        self.results = []

        # ---------------------------------------------------------------
        # Title
        # ---------------------------------------------------------------

        self.title_label = tk.Label(
            master,
            text="Password Strength Analyzer",
            font=("Arial", 18, "bold")
        )
        self.title_label.pack(pady=15)

        # ---------------------------------------------------------------
        # Password Input
        # ---------------------------------------------------------------

        self.label = tk.Label(
            master,
            text="Enter password:"
        )
        self.label.pack()

        self.password_entry = tk.Entry(
            master,
            show="*",
            width=45
        )
        self.password_entry.pack(pady=5)

        self.password_entry.bind(
            "<Return>",
            lambda event: self.check_password()
        )

        # ---------------------------------------------------------------
        # Check Button
        # ---------------------------------------------------------------

        self.check_button = tk.Button(
            master,
            text="Check Strength",
            command=self.check_password
        )
        self.check_button.pack(pady=5)

        # ---------------------------------------------------------------
        # Result
        # ---------------------------------------------------------------

        self.result_label = tk.Label(
            master,
            text="",
            wraplength=550,
            justify="left"
        )
        self.result_label.pack(pady=5)

        self.suggestion_label = tk.Label(
            master,
            text="",
            wraplength=550,
            justify="left"
        )
        self.suggestion_label.pack(pady=5)

        # ---------------------------------------------------------------
        # Generate Password
        # ---------------------------------------------------------------

        self.generate_button = tk.Button(
            master,
            text="Generate Strong Password",
            command=self.generate_password
        )
        self.generate_button.pack(pady=5)

        # ---------------------------------------------------------------
        # Generated Password Display
        # ---------------------------------------------------------------

        self.password_display = tk.Text(
            master,
            height=2,
            width=50,
            wrap=tk.WORD
        )
        self.password_display.pack(pady=5)

        self.copy_button = tk.Button(
            master,
            text="Copy to Clipboard",
            command=self.copy_password
        )
        self.copy_button.pack(pady=5)

        # ---------------------------------------------------------------
        # Export
        # ---------------------------------------------------------------

        self.export_button = tk.Button(
            master,
            text="Export Results",
            command=self.export_results
        )
        self.export_button.pack(pady=5)

        # ---------------------------------------------------------------
        # Security Tips
        # ---------------------------------------------------------------

        self.tip_label = tk.Label(
            master,
            text=(
                "\nSecurity Tips:\n\n"
                "• Avoid personal information in passwords\n"
                "• Use long and unique passwords\n"
                "• Combine different character types\n"
                "• Avoid common words and predictable patterns\n"
                "• Use a different password for every account\n"
                "• Consider using a reputable password manager"
            ),
            justify="left",
            fg="light blue"
        )
        self.tip_label.pack(pady=5)

        # ---------------------------------------------------------------
        # Quit
        # ---------------------------------------------------------------

        self.quit_button = tk.Button(
            master,
            text="Quit",
            command=master.quit
        )
        self.quit_button.pack(pady=10)

    # -------------------------------------------------------------------
    # Check Password
    # -------------------------------------------------------------------

    def check_password(self):
        """Analyse the password entered by the user."""

        password = self.password_entry.get()

        if not password:
            messagebox.showwarning(
                "Input Required",
                "Please enter a password to analyse."
            )
            return

        result = self.password_strength.check_password_strength(password)

        self.result_label.config(
            text=(
                f"Strength: {result.strength}\n"
                f"Score: {result.score}/4\n"
                f"Message: {result.message}"
            )
        )

        suggestions = self.password_strength.suggest_improvements(
            password
        )

        self.suggestion_label.config(
            text=suggestions
        )

        # IMPORTANT:
        # Do not store or export the plaintext password.
        self.results.append({
            "strength": result.strength,
            "score": result.score,
            "message": result.message,
            "password_length": len(password)
        })

        # Never log the password itself.
        logging.info(
            "Password checked: %s",
            result.strength
        )

    # -------------------------------------------------------------------
    # Generate Password
    # -------------------------------------------------------------------

    def generate_password(self):
        """Generate a cryptographically secure password."""

        try:
            password = self.password_strength.generate_random_password()

        except ValueError as error:
            messagebox.showerror(
                "Generation Error",
                str(error)
            )
            return

        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

        self.password_display.delete(
            "1.0",
            tk.END
        )

        self.password_display.insert(
            tk.END,
            password
        )

        messagebox.showinfo(
            "Password Generated",
            "A secure password has been generated.\n\n"
            "Use the 'Copy to Clipboard' button to copy it."
        )

        logging.info("Secure password generated.")

    # -------------------------------------------------------------------
    # Copy Password
    # -------------------------------------------------------------------

    def copy_password(self):
        """Copy the generated password to the clipboard."""

        password = self.password_display.get(
            "1.0",
            tk.END
        ).strip()

        if not password:
            messagebox.showwarning(
                "Nothing to Copy",
                "Generate a password first."
            )
            return

        self.master.clipboard_clear()
        self.master.clipboard_append(password)

        messagebox.showinfo(
            "Clipboard",
            "Password copied to clipboard."
        )

        logging.info("Generated password copied to clipboard.")

    # -------------------------------------------------------------------
    # Export Results
    # -------------------------------------------------------------------

    def export_results(self):
        """Export password analysis results without plaintext passwords."""

        if not self.results:
            messagebox.showerror(
                "Error",
                "No password analysis results available."
            )
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )

        if not file_path:
            return

        try:
            with open(
                file_path,
                "w",
                encoding="utf-8"
            ) as file:
                json.dump(
                    self.results,
                    file,
                    indent=4
                )

            messagebox.showinfo(
                "Export Successful",
                (
                    "Analysis results were exported successfully.\n\n"
                    "For security reasons, plaintext passwords "
                    "were not included."
                )
            )

            logging.info(
                "Password analysis results exported."
            )

        except OSError as error:
            messagebox.showerror(
                "Export Error",
                f"Unable to export results:\n{error}"
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class PasswordStrengthCLI:
    """Command-line interface for the password analyzer."""

    def __init__(self):
        self.password_strength = PasswordStrength()

    def check_password(self, password):
        """Analyse and display password strength."""

        result = self.password_strength.check_password_strength(
            password
        )

        print("\n" + "=" * 50)
        print("PASSWORD STRENGTH ANALYSIS")
        print("=" * 50)

        print(f"Strength : {result.strength}")
        print(f"Score    : {result.score}/4")
        print(f"Message  : {result.message}")

        print("\n" + self.password_strength.suggest_improvements(
            password
        ))

        print("=" * 50)

    def generate_password(self, length=16):
        """Generate and display a secure password."""

        try:
            password = (
                self.password_strength.generate_random_password(
                    length
                )
            )

        except ValueError as error:
            print(f"\nError: {error}")
            return None

        print("\n" + "=" * 50)
        print("SECURE PASSWORD GENERATED")
        print("=" * 50)

        print(f"Password: {password}")
        print(f"Length  : {len(password)}")

        print("=" * 50)

        return password


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------

def main():
    """Application entry point."""

    parser = argparse.ArgumentParser(
        description=(
            "Password Strength Analyzer - "
            "Analyse and generate secure passwords."
        )
    )

    parser.add_argument(
        "--cli",
        action="store_true",
        help="Launch the interactive CLI."
    )

    parser.add_argument(
        "--check",
        type=str,
        help="Analyse the strength of a specified password."
    )

    parser.add_argument(
        "--generate",
        action="store_true",
        help="Generate a secure random password."
    )

    parser.add_argument(
        "--length",
        type=int,
        default=16,
        help=(
            "Specify the generated password length. "
            "Minimum: 12. Default: 16."
        )
    )

    args = parser.parse_args()

    # ---------------------------------------------------------------
    # CLI Mode
    # ---------------------------------------------------------------

    if args.cli or args.check or args.generate:

        cli = PasswordStrengthCLI()

        # Direct password check
        if args.check is not None:
            cli.check_password(args.check)

        # Direct password generation
        elif args.generate:
            cli.generate_password(args.length)

        # Interactive CLI
        elif args.cli:

            while True:

                print("\n")
                print("=" * 50)
                print("PASSWORD STRENGTH ANALYZER")
                print("=" * 50)
                print("1. Check Password Strength")
                print("2. Generate Secure Password")
                print("3. Exit")
                print("=" * 50)

                choice = input(
                    "\nEnter your choice (1-3): "
                ).strip()

                if choice == "1":

                    password = input(
                        "Enter password to analyse: "
                    )

                    cli.check_password(password)

                elif choice == "2":

                    length_input = input(
                        "Enter desired password length "
                        "(minimum 12, default 16): "
                    ).strip()

                    try:

                        length = (
                            int(length_input)
                            if length_input
                            else 16
                        )

                        cli.generate_password(length)

                    except ValueError:

                        print(
                            "Invalid length. "
                            "Using default length of 16."
                        )

                        cli.generate_password(16)

                elif choice == "3":

                    print("\nGoodbye!")
                    sys.exit(0)

                else:

                    print(
                        "\nInvalid choice. "
                        "Please select an option from 1-3."
                    )

    # ---------------------------------------------------------------
    # GUI Mode
    # ---------------------------------------------------------------

    else:

        root = tk.Tk()

        PasswordStrengthGUI(root)

        root.mainloop()


# ---------------------------------------------------------------------------
# Program Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()