# Fake Login Detector

A beginner-friendly cybersecurity project built with Python that analyzes URLs for potentially suspicious characteristics associated with phishing and fraudulent login pages.

## Project Overview

Phishing websites often use misleading domain names, unusual URL structures, and brand impersonation to trick users into trusting them.

Fake Login Detector examines a URL using simple rules and assigns a suspiciousness score based on certain indicators. It also provides warnings to help users understand what may deserve further investigation.

This project was developed to practice Python programming, cybersecurity fundamentals, input validation, and automated testing.

## Features

- **URL analysis:** Examines a URL for potentially suspicious characteristics.
- **Risk scoring:** Assigns points to selected suspicious indicators.
- **Brand impersonation detection:** Flags domains that contain known brand names without matching the official domain.
- **IP address detection:** Identifies URLs that use an IP address as their hostname.
- **URL structure checks:** Detects characteristics such as unusually long URLs and consecutive dots in hostnames.
- **Informational warnings:** Identifies keywords such as `login`, `secure`, and `verify` without automatically treating them as proof of phishing.
- **Input validation:** Handles empty inputs, spaces, and invalid URL components.
- **Automated testing:** Uses Python's built-in `unittest` framework to verify expected behavior.

## Technologies Used

- Python
- `urllib.parse`
- `ipaddress`
- `unittest`
- Git and GitHub

## How the Scoring Works

The program uses a rule-based scoring system. Certain indicators increase the score, while other observations generate warnings without adding points.

Examples of indicators that can increase the score include:

- A URL that is unusually long
- The presence of an `@` symbol in the URL
- A hostname that is an IP address
- Consecutive dots in the hostname
- A domain that may be impersonating a known brand

Keywords such as `login` and `password` are treated as informational indicators because legitimate websites can use them too.

A higher score means more suspicious indicators were detected. **The score is not a probability that a website is malicious.**

## Getting Started

### Requirements

- Python 3
- A terminal or command prompt

### Run the Program

1. Clone or download this repository.
2. Open a terminal in the project directory.
3. Run:

```bash
py main.py
```

On systems where `py` is unavailable, use:

```bash
python main.py
```

4. Enter a URL when prompted.

### Run the Tests

Run the automated test suite with:

```bash
py -m unittest -v
```

Or, if needed:

```bash
python -m unittest -v
```

The tests cover URL input validation, official brand domains, suspicious domains, IP addresses, informational keywords, and risk scoring.

## Limitations

This project is an educational prototype and should not be used as the sole basis for deciding whether a website is safe.

- It analyzes URL characteristics using predefined rules.
- It does not visit the website or inspect its contents.
- It does not verify SSL/TLS certificates.
- It does not query external threat intelligence services.
- It does not use a machine learning model.
- Its known-brand list is limited and manually maintained.
- A low score does not guarantee that a URL is legitimate, and a high score does not prove that it is malicious.

## Privacy and Safety

The project is designed to analyze URLs only. It does not collect, store, or transmit passwords or other login credentials.

Only analyze URLs you are authorized to examine, and avoid submitting sensitive URLs containing personal tokens or private information to external services.

## Future Improvements

- Expand URL analysis rules and test coverage.
- Add more robust domain parsing and validation.
- Create a larger collection of labeled test URLs.
- Explore a machine learning classifier.
- Develop a simple web interface.
- Improve reporting so users can better understand each detected indicator.

## Learning Goals

This project demonstrates practical experience with Python functions, conditional logic, lists, string processing, exception handling, URL parsing, modular code, and automated unit testing.

It is an ongoing project focused on learning cybersecurity concepts while building reliable, testable software.