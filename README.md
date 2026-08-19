🔐 Password Strength Analyzer

A cybersecurity-focused password security assessment tool with both Graphical User Interface (GUI) and Command-Line Interface (CLI) support.

The application evaluates password strength using a combination of rule-based security checks and the zxcvbn password-strength estimation library. It identifies common and prohibited passwords, detects password weaknesses, provides actionable recommendations, and generates cryptographically secure passwords.

The project was developed to demonstrate practical concepts in password security, secure random generation, basic cryptography, input validation, and cybersecurity best practices.

Features
🖥️ Dual Interface
1) User-friendly graphical interface built with Tkinter
2) Lightweight command-line interface for terminal-based usage
3) Interactive password analysis and secure password generation

🔍 Advanced Password Strength Analysis
Uses the zxcvbn password-strength estimation library to evaluate:
1) Password predictability
2) Common patterns
3) Estimated password strength
4) Overall security score from 0–4

🚫 Banned Password Detection
Passwords are checked against banned_passwords.txt.
Banned passwords always take priority over weak-password classification.
If a password appears in the banned wordlist, it is immediately classified as:

Banned

This prevents compromised or explicitly prohibited passwords from being incorrectly classified as merely "Weak."

⚠️ Weak Password Detection
The application checks passwords against weak_passwords.txt to identify commonly used or easily guessable passwords.

🔐 Password Complexity Analysis
The application checks for:

1) Minimum password length
2) Uppercase letters
3) Lowercase letters
4) Numbers
5) Special characters

The recommended minimum password length is 12 characters.

⚡ Secure Password Generation
Generates strong passwords using Python's built-in secrets module rather than the standard random module.

Generated passwords:

1) Are at least 12 characters long
2) Contain uppercase letters
3) Contain lowercase letters
4) Contain numbers
5) Contain special characters
6) Use cryptographically secure random selection

💡 Password Improvement Recommendations
Provides actionable recommendations based on the detected weaknesses in a password.

Examples include:

Increasing password length
Adding uppercase characters
Adding lowercase characters
Adding numbers
Adding special characters
Avoiding predictable patterns
Avoiding commonly used passwords

📋 Clipboard Support
Generated passwords can be copied directly to the system clipboard through the GUI.

📊 Result Export
Password analysis results can be exported to a JSON file.
For security reasons, plaintext passwords are never included in exported results.

📝 Security Logging
The application maintains an activity log containing non-sensitive information such as:

1) Timestamp
2) Operation performed
3) Password strength result

Passwords themselves are never written to the log.

🛠️ Technologies Used
Technology	Purpose
1) Python 3	Core application development
2) Tkinter	Graphical User Interface
3) zxcvbn	Password strength estimation
4) secrets	Cryptographically secure password generation
5) re	Password complexity validation
6) JSON	Result export
7) logging	Application activity logging
8) Git & GitHub	Version control and project hosting

📁 Project Structure
Password-Strength-Analyzer/
│
├── password_strength_analyzer.py
├── weak_passwords.txt
├── banned_passwords.txt
├── screenshots
├── LICENSE
├── README.md
└── password_checker.log

password_checker.log is generated automatically when the application is used and should not be committed to the repository.

🚀 Installation
1. Clone the Repository
git clone https://github.com/uzair-hidayath-khan/Password-Strength-Analyzer.git

Navigate into the project directory:
cd Password-Strength-Analyzer

2. Install Dependencies
Install the required Python package:
python -m pip install zxcvbn

3. Verify the Wordlists
Ensure the following files are present in the project directory:
weak_passwords.txt
banned_passwords.txt

The banned-password list takes priority over the weak-password list during analysis.

▶️ Usage

🖥️ GUI Mode
Run the application without any command-line arguments:
python password_strength_analyzer.py

The graphical interface provides:

Password analysis
Password visibility toggle
Visual strength meter
Security score
Password recommendations
Secure password generation
Clipboard support
JSON result export
Cybersecurity-focused security tips

💻 CLI Mode
Interactive CLI

Launch the interactive command-line interface:

python password_strength_analyzer.py --cli

You will be presented with:

1. Check Password Strength
2. Generate Secure Password
3. Exit
Check a Specific Password
python password_strength_analyzer.py --check "your_password_here"

The application returns:

Password strength
Score out of 4
Security analysis
Improvement recommendations

Use test passwords when experimenting with command-line arguments. Avoid entering passwords that you currently use for real accounts.

Generate a Secure Password

Generate a password using the default length of 16 characters:

python password_strength_analyzer.py --generate

Generate a password with a custom length:

python password_strength_analyzer.py --generate --length 20

The minimum supported generated password length is 12 characters.

⚙️ Command-Line Arguments
Argument	Description
--cli	Launches the interactive command-line interface
--check PASSWORD	Analyses the strength of the specified password
--generate	Generates a cryptographically secure password
--length N	Specifies the generated password length. Default: 16

🔐 Secure Password Generation
Password generation uses Python's built-in secrets module.
Unlike the standard random module, secrets is specifically designed for generating values suitable for security-sensitive applications.

Every generated password contains at least:

1 uppercase letter
1 lowercase letter
1 number
1 special character

The remaining characters are selected using cryptographically secure randomness.

🛡️ Security & Privacy
Security and privacy are important design considerations of this project.

Local Processing

1) Password analysis is performed locally on the user's computer.
2) No password is transmitted to an external API or online service.
3) No Plaintext Password Storage
4) The application does not permanently store plaintext passwords.
5) No Password Logging
6) Application logs contain only non-sensitive information.

For example:

2026-08-19 20:15:42 - INFO - Password checked: Strong

The password itself is never logged.

7) Secure Random Generation
Generated passwords use the Python secrets module for cryptographically secure random selection.
8) Banned Password Priority
If a password appears in banned_passwords.txt, it is classified as Banned before other password-strength checks are performed.


📋 Logging
Application activity is recorded in:
password_checker.log

The log contains non-sensitive information including:

1) Timestamp
2) Operation performed
3) Password strength result


📦 Requirements
Python 3.x
Tkinter
zxcvbn

Tkinter is included with most standard Python installations.

⚠️ Responsible Use
This project is intended for educational, cybersecurity training, and password-security assessment purposes.
Do not use real passwords belonging to yourself or others when testing or demonstrating the application.
For testing purposes, use deliberately created test passwords.

📄 License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

See the LICENSE file for the complete license terms.