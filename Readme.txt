# SSL Analyzer Flask Application

## Overview

This is a simple web-based tool built with Flask that allows you to analyze SSL/TLS certificates of any given hostname or IP address. It connects to the specified target, retrieves its SSL certificate, and displays various details about the certificate, including subject, issuer, validity period, serial number, fingerprints, public key information, and key usages.

## Features

* **Certificate Information:** Displays details like Subject, Issuer, Valid From/Until dates, Serial Number, SHA256 Fingerprint.
* **Public Key Details:** Shows Public Key Type (e.g., RSA) and Key Bits.
* **Subject Alternative Names (SANs):** Lists all DNS names and IP addresses associated with the certificate.
* **Key Usage & Extended Key Usage:** Provides a breakdown of how the certificate's key is intended to be used.
* **CRL Distribution Points:** Identifies URLs where Certificate Revocation Lists can be found.
* **User-Friendly Interface:** Simple web form to input hostnames or IP addresses.
* **Error Handling:** Provides informative messages for common connection or SSL errors.

## Prerequisites

Before you can run this application, you need to have the following installed on your system:

* **Python 3.7+**: This application is developed using Python.
* **pip**: Python's package installer, usually comes with Python installations.

### How to Check if Python and pip are Installed

Open your terminal or command prompt and run the following commands:

```bash
python --version
# or
python3 --version

You should see something like pip 21.2.4.

If Python or pip are not installed, please follow the instructions below.

Installing Python (and pip)
For Windows:

Download the latest Python 3 installer from the official website: python.org/downloads/windows/.
Run the installer. IMPORTANT: Make sure to check the box that says "Add Python X.X to PATH" during installation. This will make it easier to run Python from the command prompt.
Follow the on-screen instructions to complete the installation.
For macOS:

Using Homebrew (Recommended): If you have Homebrew installed, open your terminal and run:
Bash

brew install python
Using Official Installer: Download the latest Python 3 installer from python.org/downloads/mac-os-x/ and follow the installation prompts.
For Linux (Debian/Ubuntu):

Python 3 is usually pre-installed. If not, or if you need a specific version, use your package manager:

Bash

sudo apt update
sudo apt install python3 python3-pip
For Linux (CentOS/RHEL):

Bash

sudo yum install python3 python3-pip
Installation
Follow these steps to get the SSL Analyzer application up and running on your local machine:

Clone the Repository:
Open your terminal or command prompt and run:

Bash

git clone [https://github.com/YourUsername/ssl-analyzer-flask-app.git](https://github.com/YourUsername/ssl-analyzer-flask-app.git)
# Replace 'YourUsername' with your actual GitHub username and the repository name if it's different.
Navigate into the cloned directory:

Bash

cd ssl-analyzer-flask-app
Create a Virtual Environment (Recommended):
It's best practice to use a virtual environment to manage project dependencies.

Bash

python3 -m venv venv
# On some systems, you might use 'python -m venv venv'
Activate the Virtual Environment:

On Windows:
Bash

.\venv\Scripts\activate
On macOS/Linux:
Bash

source venv/bin/activate
You'll see (venv) prepended to your terminal prompt, indicating the virtual environment is active.

Install Dependencies:
First, create a requirements.txt file in your ssl-analyzer-flask-app directory with the following content:

Flask
pyOpenSSL
cryptography
requests
Then, install the required Python packages:

Bash

pip install -r requirements.txt
How to Run the Application
With your virtual environment activated and dependencies installed, you can now run the Flask application:

Start the Flask Server:
Bash

python app.py
You should see output similar to this:
 * Serving Flask app 'app'
 * Debug mode: on
 WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on [http://127.0.0.1:5000](http://127.0.0.1:5000)
 Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: XXX-XXX-XXX
Usage
Access the Application:
Open your web browser and go to the address indicated in the terminal, usually:
http://127.0.0.1:5000/

Analyze a Certificate:

In the input field, enter a hostname (e.g., www.google.com, example.org) or an IP address (e.g., 8.8.8.8).
Click the "Analyze" button.
The page will display the SSL certificate details for the entered target.
License
This project is licensed under the MIT License - see the LICENSE file for details (if you have one).
