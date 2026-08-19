Password Strength Analyzer

A comprehensive password security assessment tool featuring both Graphical User Interface (GUI) and Command-Line Interface (CLI) modes. The application evaluates password strength using advanced password analysis techniques, identifies potential security weaknesses, provides recommendations for improvement, and enables users to generate strong, secure passwords.

Features
Dual Interface Support: Provides both an intuitive GUI for ease of use and a lightweight CLI for efficient command-line operation.
Advanced Password Strength Analysis: Utilises the zxcvbn password-strength estimation library to provide realistic assessments based on password patterns and predictability.
Secure Password Generation: Generates strong, random passwords with configurable lengths.

Comprehensive Security Checks:
Minimum password length validation
Uppercase and lowercase character verification
Numeric character validation
Special character verification
Detection of commonly used passwords
Detection of prohibited or banned passwords

Actionable Recommendations: Provides targeted suggestions to help users improve weak or vulnerable passwords.
Result Export: Allows password analysis results to be exported in JSON format through the GUI.
Activity Logging: Maintains detailed logs of password analysis activities and results.

Installation
1. Clone the Repository
git clone https://github.com/yourusername/password-strength-analyzer.git
cd password-strength-analyzer
2. Install Required Dependencies
pip install zxcvbn
3. Configure Required Wordlists

Ensure that the following wordlist files are available in the project directory:

weak_passwords.txt — Contains a collection of commonly used and weak passwords.
banned_passwords.txt — Contains passwords that are explicitly prohibited from use.

Usage

GUI Mode
Launch the application without any command-line arguments to open the graphical interface:

python password_strength_analyzer.py

The GUI provides an interactive environment for analysing passwords, generating secure passwords, viewing security recommendations, and exporting results.

CLI Mode
1. Interactive CLI

Launch the interactive command-line interface:

python password_strength_analyzer.py --cli
2. Analyse a Specific Password

Check the strength of a password directly from the command line:

python password_strength_analyzer.py --check "your_password_here"
3. Generate a Secure Password

Generate a password using the default length of 16 characters:

python password_strength_analyzer.py --generate

Generate a password with a custom length:

python password_strength_analyzer.py --generate --length 20
Command-Line Arguments
Argument	Description
--cli	Launches the interactive command-line interface
--check PASSWORD	Analyses the strength of the specified password
--generate	Generates a secure random password
--length N	Sets the length of the generated password. Default: 16

Password Security Analysis

The application evaluates passwords against multiple security criteria.

Strength Requirements
Minimum recommended length of 12 characters
Presence of uppercase letters
Presence of lowercase letters
Presence of numerical characters
Presence of special characters
Detection of commonly used weak passwords
Detection of banned passwords
Advanced password-pattern analysis using zxcvbn

The combination of rule-based validation and zxcvbn analysis allows the application to assess not only password complexity but also common patterns and predictability.

GUI Capabilities

The graphical interface provides the following functionality:

Visual representation of password strength
Interactive password analysis
Secure password generation
Clipboard support for generated passwords
Export of analysis results in JSON format
Security recommendations and password-strength tips
Interactive feedback based on password characteristics
CLI Capabilities

The command-line interface provides a lightweight alternative for users who prefer terminal-based tools.

Available functionality includes:

Interactive password analysis
Direct password-strength assessment
Secure password generation
Custom password-length configuration
Detailed analysis results and recommendations
Logging

Password analysis activities are recorded in:

password_analyzer.log

The log records relevant non-sensitive information such as:

Timestamp of the operation
Type of action performed
Result of the strength assessment

Note: The application does not permanently store users' plaintext passwords.

Security Considerations

The application is designed with basic security and privacy principles in mind:

Passwords are processed locally.
Passwords are not permanently stored.
No external APIs are required for password-strength analysis.
Password generation uses secure randomisation techniques.
Analysis results can be exported without requiring an external service.

Users should avoid sharing real passwords when testing applications or tools, particularly passwords that are currently used for personal or professional accounts.

Requirements
Python 3.x
Tkinter — included with most standard Python installations
zxcvbn — password-strength estimation library

Install the primary Python dependency with:
pip install zxcvbn

License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).
See the LICENSE file for the complete license terms.