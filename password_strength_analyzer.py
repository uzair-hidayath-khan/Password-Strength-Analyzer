"""Password Strength Analyzer.

A cybersecurity-themed GUI and CLI application for evaluating
password strength and generating cryptographically secure passwords.

Features:
- Password strength analysis using zxcvbn
- Banned password detection
- Common/weak password detection
- Password complexity validation
- Cryptographically secure password generation
- Password improvement recommendations
- JSON export without storing plaintext passwords
- Activity logging without recording passwords
- Cybersecurity-themed GUI
- CLI interface

Dependencies:
- Python 3.x
- tkinter
- zxcvbn
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


# ============================================================================
# CYBERSECURITY THEME
# ============================================================================

BG_COLOR = "#080B12"
PANEL_COLOR = "#101620"
PANEL_DARK = "#0C1119"

RED = "#FF3B3B"
RED_DARK = "#B51F2A"

GREEN = "#00E676"
YELLOW = "#FFD740"
ORANGE = "#FF9100"

CYAN = "#00E5FF"
WHITE = "#F5F7FA"
LIGHT_GRAY = "#B8C2CC"
GRAY = "#687482"

BORDER = "#1E2936"


# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    filename="password_checker.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# ============================================================================
# WORDLIST
# ============================================================================

class Wordlist:
    """Load and manage password wordlists efficiently."""

    _cache = {}

    def __init__(self, file_path):
        self.file_path = file_path
        self.words = self.load_wordlist()

    def load_wordlist(self):
        """Load a wordlist and cache it."""

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
        """Check whether a password exists in the wordlist."""

        return word.lower() in self.words


# ============================================================================
# STRENGTH RESULT
# ============================================================================

class StrengthResult:
    """Store password strength analysis results."""

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


# ============================================================================
# PASSWORD STRENGTH ENGINE
# ============================================================================

class PasswordStrength:
    """Analyze password strength and generate secure passwords."""

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

        self.special_characters = (
            "!@#$%^&*(),.?\":{}|<>[]_-+=~`'\\/;"
        )

    # ------------------------------------------------------------------------
    # PASSWORD STRENGTH ANALYSIS
    # ------------------------------------------------------------------------

    def check_password_strength(self, password):
        """Evaluate the strength of a password.

        Banned passwords always take priority over weak passwords.
        """

        if not password:

            return StrengthResult(
                "Invalid",
                0,
                "Password cannot be empty."
            )

        # ====================================================================
        # 1. BANNED PASSWORD CHECK
        # ====================================================================
        # This check intentionally happens FIRST.
        #
        # If a password appears in banned_passwords.txt, it will ALWAYS
        # be classified as BANNED, even if it also appears in
        # weak_passwords.txt or is shorter than the recommended length.
        # ====================================================================

        if (
            self.banned_wordlist
            and self.banned_wordlist.is_word_in_list(password)
        ):

            return StrengthResult(
                "Banned",
                0,
                (
                    "This password is banned because it is commonly "
                    "associated with compromised or leaked credentials."
                ),
                [
                    "Choose a completely different password.",
                    "Do not use passwords that have appeared in data breaches."
                ]
            )

        # ====================================================================
        # 2. MINIMUM LENGTH CHECK
        # ====================================================================

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

        # ====================================================================
        # 3. WEAK PASSWORD CHECK
        # ====================================================================

        if (
            self.weak_wordlist
            and self.weak_wordlist.is_word_in_list(password)
        ):

            return StrengthResult(
                "Weak",
                0,
                "This password is commonly used and easily guessable.",
                [
                    "Avoid commonly used passwords.",
                    "Use a longer and more unpredictable password."
                ]
            )

        # ====================================================================
        # 4. ZXCVBN ANALYSIS
        # ====================================================================

        password_strength = zxcvbn(password)

        score = password_strength["score"]

        strength = self.strength_mapping.get(
            score,
            "Unknown"
        )

        # ====================================================================
        # 5. CHARACTER COMPLEXITY CHECK
        # ====================================================================

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

        # ====================================================================
        # 6. ZXCVBN FEEDBACK
        # ====================================================================

        feedback = password_strength.get(
            "feedback",
            {}
        )

        zxcvbn_suggestions = feedback.get(
            "suggestions",
            []
        )

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

        # ====================================================================
        # 7. STRONG PASSWORD
        # ====================================================================

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

        # ====================================================================
        # 8. MODERATE / WEAK ZXCVBN RESULT
        # ====================================================================

        return StrengthResult(
            strength,
            score,
            (
                f"Password is {strength.lower()}. "
                "Consider making it longer and less predictable."
            ),
            suggestions
        )

    # ------------------------------------------------------------------------
    # IMPROVEMENT SUGGESTIONS
    # ------------------------------------------------------------------------

    def suggest_improvements(self, password):
        """Generate actionable password improvement suggestions."""

        result = self.check_password_strength(password)

        suggestions = []

        # Banned password
        if result.strength == "Banned":

            suggestions.extend(
                [
                    "Do not use this password.",
                    "Choose a completely different password.",
                    "Use a unique password that has not appeared in breaches."
                ]
            )

        else:

            if len(password) < self.min_password_length:

                suggestions.append(
                    f"Increase length to at least "
                    f"{self.min_password_length} characters."
                )

            if not re.search(r"[A-Z]", password):
                suggestions.append(
                    "Add uppercase letters."
                )

            if not re.search(r"[a-z]", password):
                suggestions.append(
                    "Add lowercase letters."
                )

            if not re.search(r"\d", password):
                suggestions.append(
                    "Add numbers."
                )

            if not re.search(
                r"""[!@#$%^&*(),.?":{}|<>\[\]_\-+=~`'/\\;]""",
                password
            ):
                suggestions.append(
                    "Add special characters."
                )

        # Add zxcvbn recommendations
        for suggestion in result.suggestions:

            if suggestion and suggestion not in suggestions:

                suggestions.append(
                    suggestion
                )

        if not suggestions:

            return "No major improvements required."

        return (
            "Suggested improvements:\n"
            + "\n".join(
                f"• {item}"
                for item in suggestions
            )
        )

    # ------------------------------------------------------------------------
    # SECURE PASSWORD GENERATION
    # ------------------------------------------------------------------------

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

        # Guarantee each required character category.
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

        # Cryptographically secure Fisher-Yates shuffle.
        for index in range(
            len(password_characters) - 1,
            0,
            -1
        ):

            random_index = secrets.randbelow(
                index + 1
            )

            (
                password_characters[index],
                password_characters[random_index]
            ) = (
                password_characters[random_index],
                password_characters[index]
            )

        return "".join(password_characters)


# ============================================================================
# CYBERSECURITY GUI
# ============================================================================

class PasswordStrengthGUI:
    """Cybersecurity-themed Tkinter interface."""

    def __init__(self, master):

        self.master = master

        self.master.title(
            "Password Strength Analyzer"
        )

        self.master.geometry(
            "850x720"
        )

        self.master.configure(
            bg=BG_COLOR
        )

        self.master.resizable(
            False,
            False
        )

        self.password_strength = PasswordStrength()

        self.results = []

        self.password_visible = False

        self.setup_gui()

    # ------------------------------------------------------------------------
    # GUI SETUP
    # ------------------------------------------------------------------------

    def setup_gui(self):

        # ====================================================================
        # HEADER
        # ====================================================================

        header = tk.Frame(
            self.master,
            bg=BG_COLOR
        )

        header.pack(
            fill="x",
            padx=30,
            pady=(25, 10)
        )

        logo = tk.Label(
            header,
            text="🔐",
            font=("Segoe UI Emoji", 30),
            bg=BG_COLOR,
            fg=RED
        )

        logo.pack(
            side="left",
            padx=(0, 12)
        )

        title_container = tk.Frame(
            header,
            bg=BG_COLOR
        )

        title_container.pack(
            side="left"
        )

        title = tk.Label(
            title_container,
            text="PASSWORD STRENGTH ANALYZER",
            font=("Consolas", 20, "bold"),
            bg=BG_COLOR,
            fg=WHITE
        )

        title.pack(
            anchor="w"
        )

        subtitle = tk.Label(
            title_container,
            text="CYBERSECURITY • PASSWORD INTELLIGENCE",
            font=("Consolas", 9),
            bg=BG_COLOR,
            fg=CYAN
        )

        subtitle.pack(
            anchor="w",
            pady=(3, 0)
        )

        # ====================================================================
        # STATUS BAR
        # ====================================================================

        status_bar = tk.Frame(
            self.master,
            bg=PANEL_DARK,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        status_bar.pack(
            fill="x",
            padx=30,
            pady=(0, 15)
        )

        status_left = tk.Label(
            status_bar,
            text="● SYSTEM READY",
            font=("Consolas", 9, "bold"),
            bg=PANEL_DARK,
            fg=GREEN
        )

        status_left.pack(
            side="left",
            padx=15,
            pady=8
        )

        status_right = tk.Label(
            status_bar,
            text="LOCAL ANALYSIS • NO EXTERNAL API",
            font=("Consolas", 9),
            bg=PANEL_DARK,
            fg=GRAY
        )

        status_right.pack(
            side="right",
            padx=15
        )

        # ====================================================================
        # MAIN CONTENT
        # ====================================================================

        main_frame = tk.Frame(
            self.master,
            bg=BG_COLOR
        )

        main_frame.pack(
            fill="both",
            expand=True,
            padx=30
        )

        # ====================================================================
        # LEFT PANEL
        # ====================================================================

        left_panel = tk.Frame(
            main_frame,
            bg=PANEL_COLOR,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        left_panel.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 10)
        )

        left_title = tk.Label(
            left_panel,
            text="PASSWORD ANALYSIS",
            font=("Consolas", 12, "bold"),
            bg=PANEL_COLOR,
            fg=RED
        )

        left_title.pack(
            anchor="w",
            padx=20,
            pady=(18, 12)
        )

        separator = tk.Frame(
            left_panel,
            height=1,
            bg=BORDER
        )

        separator.pack(
            fill="x",
            padx=20
        )

        input_label = tk.Label(
            left_panel,
            text="ENTER PASSWORD",
            font=("Consolas", 9, "bold"),
            bg=PANEL_COLOR,
            fg=LIGHT_GRAY
        )

        input_label.pack(
            anchor="w",
            padx=20,
            pady=(18, 5)
        )

        input_frame = tk.Frame(
            left_panel,
            bg=PANEL_DARK,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        input_frame.pack(
            fill="x",
            padx=20
        )

        self.password_entry = tk.Entry(
            input_frame,
            show="•",
            font=("Consolas", 12),
            bg=PANEL_DARK,
            fg=WHITE,
            insertbackground=CYAN,
            relief="flat",
            width=32
        )

        self.password_entry.pack(
            side="left",
            padx=10,
            pady=10,
            fill="x",
            expand=True
        )

        self.visibility_button = tk.Button(
            input_frame,
            text="SHOW",
            command=self.toggle_password_visibility,
            bg=PANEL_DARK,
            fg=CYAN,
            activebackground=PANEL_DARK,
            activeforeground=WHITE,
            relief="flat",
            font=("Consolas", 8, "bold"),
            cursor="hand2"
        )

        self.visibility_button.pack(
            side="right",
            padx=8
        )

        self.password_entry.bind(
            "<Return>",
            lambda event: self.check_password()
        )

        # ====================================================================
        # ANALYZE BUTTON
        # ====================================================================

        self.check_button = tk.Button(
            left_panel,
            text="▶  ANALYZE PASSWORD",
            command=self.check_password,
            bg=RED_DARK,
            fg=WHITE,
            activebackground=RED,
            activeforeground=WHITE,
            font=("Consolas", 10, "bold"),
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=8
        )

        self.check_button.pack(
            fill="x",
            padx=20,
            pady=12
        )

        # ====================================================================
        # STRENGTH DISPLAY
        # ====================================================================

        strength_title = tk.Label(
            left_panel,
            text="SECURITY ASSESSMENT",
            font=("Consolas", 9, "bold"),
            bg=PANEL_COLOR,
            fg=GRAY
        )

        strength_title.pack(
            anchor="w",
            padx=20,
            pady=(8, 5)
        )

        self.strength_label = tk.Label(
            left_panel,
            text="WAITING FOR INPUT",
            font=("Consolas", 18, "bold"),
            bg=PANEL_COLOR,
            fg=GRAY
        )

        self.strength_label.pack(
            pady=5
        )

        # Strength meter
        meter_frame = tk.Frame(
            left_panel,
            bg=PANEL_DARK,
            height=14
        )

        meter_frame.pack(
            fill="x",
            padx=20,
            pady=8
        )

        meter_frame.pack_propagate(False)

        self.meter_fill = tk.Frame(
            meter_frame,
            bg=GRAY
        )

        self.meter_fill.place(
            x=0,
            y=0,
            relheight=1,
            relwidth=0
        )

        self.score_label = tk.Label(
            left_panel,
            text="SCORE: -- / 4",
            font=("Consolas", 9, "bold"),
            bg=PANEL_COLOR,
            fg=LIGHT_GRAY
        )

        self.score_label.pack(
            pady=(0, 10)
        )

        # Result box
        self.result_text = tk.Label(
            left_panel,
            text="Enter a password to begin analysis.",
            font=("Consolas", 9),
            bg=PANEL_DARK,
            fg=LIGHT_GRAY,
            wraplength=340,
            justify="left",
            padx=12,
            pady=12
        )

        self.result_text.pack(
            fill="x",
            padx=20,
            pady=5
        )

        # Suggestions
        self.suggestion_text = tk.Label(
            left_panel,
            text="",
            font=("Consolas", 8),
            bg=PANEL_COLOR,
            fg=LIGHT_GRAY,
            wraplength=340,
            justify="left"
        )

        self.suggestion_text.pack(
            anchor="w",
            padx=20,
            pady=(8, 15)
        )

        # ====================================================================
        # RIGHT PANEL
        # ====================================================================

        right_panel = tk.Frame(
            main_frame,
            bg=PANEL_COLOR,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        right_panel.pack(
            side="right",
            fill="both",
            expand=True,
            padx=(10, 0)
        )

        generator_title = tk.Label(
            right_panel,
            text="SECURE GENERATOR",
            font=("Consolas", 12, "bold"),
            bg=PANEL_COLOR,
            fg=CYAN
        )

        generator_title.pack(
            anchor="w",
            padx=20,
            pady=(18, 12)
        )

        generator_separator = tk.Frame(
            right_panel,
            height=1,
            bg=BORDER
        )

        generator_separator.pack(
            fill="x",
            padx=20
        )

        generator_description = tk.Label(
            right_panel,
            text=(
                "Generate a cryptographically secure password "
                "using Python's secrets module."
            ),
            font=("Consolas", 9),
            bg=PANEL_COLOR,
            fg=LIGHT_GRAY,
            wraplength=340,
            justify="left"
        )

        generator_description.pack(
            anchor="w",
            padx=20,
            pady=(18, 15)
        )

        self.generate_button = tk.Button(
            right_panel,
            text="⚡  GENERATE SECURE PASSWORD",
            command=self.generate_password,
            bg="#12303A",
            fg=CYAN,
            activebackground="#174653",
            activeforeground=WHITE,
            font=("Consolas", 10, "bold"),
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=10
        )

        self.generate_button.pack(
            fill="x",
            padx=20,
            pady=5
        )

        generated_label = tk.Label(
            right_panel,
            text="GENERATED PASSWORD",
            font=("Consolas", 9, "bold"),
            bg=PANEL_COLOR,
            fg=GRAY
        )

        generated_label.pack(
            anchor="w",
            padx=20,
            pady=(20, 5)
        )

        self.password_display = tk.Text(
            right_panel,
            height=3,
            width=35,
            wrap=tk.WORD,
            font=("Consolas", 11, "bold"),
            bg=PANEL_DARK,
            fg=GREEN,
            insertbackground=GREEN,
            relief="flat",
            padx=10,
            pady=10
        )

        self.password_display.pack(
            fill="x",
            padx=20
        )

        self.copy_button = tk.Button(
            right_panel,
            text="▣  COPY TO CLIPBOARD",
            command=self.copy_password,
            bg=PANEL_DARK,
            fg=WHITE,
            activebackground="#1A2532",
            activeforeground=CYAN,
            font=("Consolas", 9, "bold"),
            relief="flat",
            cursor="hand2"
        )

        self.copy_button.pack(
            fill="x",
            padx=20,
            pady=8
        )

        # ====================================================================
        # SECURITY TIPS
        # ====================================================================

        tips_title = tk.Label(
            right_panel,
            text="SECURITY PROTOCOLS",
            font=("Consolas", 10, "bold"),
            bg=PANEL_COLOR,
            fg=YELLOW
        )

        tips_title.pack(
            anchor="w",
            padx=20,
            pady=(20, 8)
        )

        tips = (
            "01  Use long, unique passwords\n"
            "02  Avoid personal information\n"
            "03  Avoid common words and patterns\n"
            "04  Never reuse important passwords\n"
            "05  Consider using a password manager\n"
            "06  Never share your passwords"
        )

        tips_label = tk.Label(
            right_panel,
            text=tips,
            font=("Consolas", 8),
            bg=PANEL_DARK,
            fg=LIGHT_GRAY,
            justify="left",
            anchor="w",
            padx=12,
            pady=12
        )

        tips_label.pack(
            fill="x",
            padx=20
        )

        # ====================================================================
        # EXPORT
        # ====================================================================

        self.export_button = tk.Button(
            right_panel,
            text="⇩  EXPORT ANALYSIS RESULTS",
            command=self.export_results,
            bg=PANEL_DARK,
            fg=WHITE,
            activebackground="#1A2532",
            activeforeground=CYAN,
            font=("Consolas", 9, "bold"),
            relief="flat",
            cursor="hand2"
        )

        self.export_button.pack(
            fill="x",
            padx=20,
            pady=(15, 5)
        )

        # ====================================================================
        # EXIT
        # ====================================================================

        self.quit_button = tk.Button(
            right_panel,
            text="EXIT APPLICATION",
            command=self.master.quit,
            bg=PANEL_DARK,
            fg=RED,
            activebackground="#1A1015",
            activeforeground=RED,
            font=("Consolas", 8, "bold"),
            relief="flat",
            cursor="hand2"
        )

        self.quit_button.pack(
            fill="x",
            padx=20,
            pady=5
        )

        # ====================================================================
        # FOOTER
        # ====================================================================

        footer = tk.Frame(
            self.master,
            bg=BG_COLOR
        )

        footer.pack(
            fill="x",
            padx=30,
            pady=(10, 15)
        )

        footer_left = tk.Label(
            footer,
            text="PASSWORD SECURITY TOOL",
            font=("Consolas", 8),
            bg=BG_COLOR,
            fg=GRAY
        )

        footer_left.pack(
            side="left"
        )

        footer_right = tk.Label(
            footer,
            text="LOCAL PROCESSING • NO PLAINTEXT STORAGE",
            font=("Consolas", 8),
            bg=BG_COLOR,
            fg=GRAY
        )

        footer_right.pack(
            side="right"
        )

    # ------------------------------------------------------------------------
    # PASSWORD VISIBILITY
    # ------------------------------------------------------------------------

    def toggle_password_visibility(self):
        """Toggle password visibility."""

        self.password_visible = (
            not self.password_visible
        )

        if self.password_visible:

            self.password_entry.config(
                show=""
            )

            self.visibility_button.config(
                text="HIDE"
            )

        else:

            self.password_entry.config(
                show="•"
            )

            self.visibility_button.config(
                text="SHOW"
            )

    # ------------------------------------------------------------------------
    # STRENGTH METER
    # ------------------------------------------------------------------------

    def update_strength_meter(
        self,
        score,
        strength
    ):
        """Update the visual password strength meter."""

        colors = {
            "Very Weak": RED,
            "Weak": RED,
            "Moderate": ORANGE,
            "Strong": GREEN,
            "Very Strong": CYAN,
            "Too Short": RED,
            "Banned": RED,
            "Invalid": GRAY
        }

        color = colors.get(
            strength,
            GRAY
        )

        if score <= 0:

            width = 0

        elif score == 1:

            width = 25

        elif score == 2:

            width = 50

        elif score == 3:

            width = 75

        else:

            width = 100

        self.meter_fill.config(
            bg=color
        )

        self.meter_fill.place(
            relwidth=width / 100,
            relheight=1,
            x=0,
            y=0
        )

        self.strength_label.config(
            text=strength.upper(),
            fg=color
        )

        self.score_label.config(
            text=f"SCORE: {score} / 4",
            fg=color
        )

    # ------------------------------------------------------------------------
    # CHECK PASSWORD
    # ------------------------------------------------------------------------

    def check_password(self):
        """Analyse the entered password."""

        password = self.password_entry.get()

        if not password:

            messagebox.showwarning(
                "Input Required",
                "Please enter a password to analyse."
            )

            return

        result = (
            self.password_strength
            .check_password_strength(password)
        )

        self.update_strength_meter(
            result.score,
            result.strength
        )

        self.result_text.config(
            text=(
                f"STATUS: {result.strength}\n\n"
                f"{result.message}"
            )
        )

        suggestions = (
            self.password_strength
            .suggest_improvements(password)
        )

        self.suggestion_text.config(
            text=suggestions
        )

        # Never store plaintext passwords.
        self.results.append(
            {
                "strength": result.strength,
                "score": result.score,
                "message": result.message,
                "password_length": len(password)
            }
        )

        # Never log passwords.
        logging.info(
            "Password checked: %s",
            result.strength
        )

    # ------------------------------------------------------------------------
    # GENERATE PASSWORD
    # ------------------------------------------------------------------------

    def generate_password(self):
        """Generate a cryptographically secure password."""

        try:

            password = (
                self.password_strength
                .generate_random_password()
            )

        except ValueError as error:

            messagebox.showerror(
                "Generation Error",
                str(error)
            )

            return

        self.password_entry.delete(
            0,
            tk.END
        )

        self.password_entry.insert(
            0,
            password
        )

        self.password_display.delete(
            "1.0",
            tk.END
        )

        self.password_display.insert(
            tk.END,
            password
        )

        logging.info(
            "Secure password generated."
        )

        # Analyse generated password.
        result = (
            self.password_strength
            .check_password_strength(password)
        )

        self.update_strength_meter(
            result.score,
            result.strength
        )

        self.result_text.config(
            text=(
                "GENERATED PASSWORD STATUS\n\n"
                f"{result.strength}\n"
                f"Score: {result.score}/4\n\n"
                f"{result.message}"
            )
        )

        self.suggestion_text.config(
            text=(
                "Generated using cryptographically secure "
                "randomness."
            )
        )

    # ------------------------------------------------------------------------
    # COPY PASSWORD
    # ------------------------------------------------------------------------

    def copy_password(self):
        """Copy generated password to clipboard."""

        password = (
            self.password_display
            .get(
                "1.0",
                tk.END
            )
            .strip()
        )

        if not password:

            messagebox.showwarning(
                "Nothing to Copy",
                "Generate a password first."
            )

            return

        self.master.clipboard_clear()

        self.master.clipboard_append(
            password
        )

        messagebox.showinfo(
            "Clipboard",
            "Password copied to clipboard."
        )

        logging.info(
            "Generated password copied to clipboard."
        )

    # ------------------------------------------------------------------------
    # EXPORT RESULTS
    # ------------------------------------------------------------------------

    def export_results(self):
        """Export analysis results without plaintext passwords."""

        if not self.results:

            messagebox.showerror(
                "No Results",
                "No password analysis results are available."
            )

            return

        file_path = (
            filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[
                    ("JSON files", "*.json"),
                    ("All files", "*.*")
                ]
            )
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
                "Export Complete",
                (
                    "Analysis results exported successfully.\n\n"
                    "Plaintext passwords were intentionally "
                    "excluded for security."
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


# ============================================================================
# CLI
# ============================================================================

class PasswordStrengthCLI:
    """Command-line interface for the password analyzer."""

    def __init__(self):

        self.password_strength = (
            PasswordStrength()
        )

    def check_password(self, password):
        """Analyse and display password strength."""

        result = (
            self.password_strength
            .check_password_strength(password)
        )

        print("\n" + "=" * 55)
        print("PASSWORD STRENGTH ANALYSIS")
        print("=" * 55)

        print(
            f"Strength : {result.strength}"
        )

        print(
            f"Score    : {result.score}/4"
        )

        print(
            f"Message  : {result.message}"
        )

        print(
            "\n"
            + self.password_strength
            .suggest_improvements(password)
        )

        print("=" * 55)

    def generate_password(self, length=16):
        """Generate and display a secure password."""

        try:

            password = (
                self.password_strength
                .generate_random_password(
                    length
                )
            )

        except ValueError as error:

            print(
                f"\nError: {error}"
            )

            return None

        print("\n" + "=" * 55)
        print("SECURE PASSWORD GENERATED")
        print("=" * 55)

        print(
            f"Password: {password}"
        )

        print(
            f"Length  : {len(password)}"
        )

        print("=" * 55)

        return password


# ============================================================================
# MAIN APPLICATION
# ============================================================================

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
            "Specify generated password length. "
            "Minimum: 12. Default: 16."
        )
    )

    args = parser.parse_args()

    # ========================================================================
    # CLI MODE
    # ========================================================================

    if (
        args.cli
        or args.check is not None
        or args.generate
    ):

        cli = PasswordStrengthCLI()

        # Direct password check
        if args.check is not None:

            cli.check_password(
                args.check
            )

        # Direct password generation
        elif args.generate:

            cli.generate_password(
                args.length
            )

        # Interactive CLI
        elif args.cli:

            while True:

                print("\n")
                print("=" * 55)
                print("        PASSWORD STRENGTH ANALYZER")
                print("=" * 55)
                print("1. Check Password Strength")
                print("2. Generate Secure Password")
                print("3. Exit")
                print("=" * 55)

                choice = input(
                    "\nEnter your choice (1-3): "
                ).strip()

                if choice == "1":

                    password = input(
                        "Enter password to analyse: "
                    )

                    cli.check_password(
                        password
                    )

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

                        cli.generate_password(
                            length
                        )

                    except ValueError:

                        print(
                            "Invalid length. "
                            "Using default length of 16."
                        )

                        cli.generate_password(
                            16
                        )

                elif choice == "3":

                    print(
                        "\nGoodbye!"
                    )

                    sys.exit(0)

                else:

                    print(
                        "\nInvalid choice. "
                        "Please select 1, 2, or 3."
                    )

    # ========================================================================
    # GUI MODE
    # ========================================================================

    else:

        root = tk.Tk()

        PasswordStrengthGUI(
            root
        )

        root.mainloop()


# ============================================================================
# PROGRAM ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()