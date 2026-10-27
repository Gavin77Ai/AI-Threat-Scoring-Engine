# AI Threat Scoring Engine

**An AI-powered security log analysis platform that combines rule-based threat scoring, machine learning classification, anomaly detection, and an interactive dashboard to support security alert investigation.**

Author: Gavin Polynice


### Overview

The AI Threat Scoring Engine analyzes authentication log data to identify potentially suspicious activity. It combines predefined security rules with machine learning predictions to help security analysts prioritize events for further investigation.

This project demonstrates practical cybersecurity concepts, Python development, security analytics, and applied machine learning.

### Key Features

Rule-Based Threat Scoring: Assigns risk scores based on suspicious authentication activity.

Severity Classification: Categorizes events as Low, Medium, or High based on their threat scores.

Machine Learning Classification: Predicts whether an event is Benign or Suspicious.

Prediction Confidence: Displays the model's confidence in its classification.

Anomaly Detection: Identifies events that differ from learned patterns.

Alert Explanations: Provides information to help users understand suspicious activity.

Interactive Dashboard: Uses Streamlit to present security analysis and investigation information.

Input Validation: Checks log fields and rejects invalid values.

Local Alert Storage: Uses SQLite to store alert records locally.

### Technologies Used

Python - Core application development

Pandas - Data processing and analysis

Scikit-learn - Machine learning and classification

Streamlit - Interactive dashboard 

SQLite - Local alert storage 

SHAP - Model prediction explanations

Git and GitHub - Version control and project hosting 

## Threat Scoring Methodology

The rule-based scoring system evaluates several authentication indicators:

Detection Rule

Points

Unusual country: +25

Unknown IP address: +20

Unusual login time: +10

Five or more failed attempts: +25

Three or four failed attempts: +15

Successful login after failures: +20

Maximum Threat Score: 100

### Severity Levels

Threat Score

Severity

0–39: Low

40–69: Medium

70–100: High

The machine learning model separately classifies events as Benign or Suspicious. Its prediction is intended to complement the rule-based score, not replace human investigation.

### Project Architecture

1) Authentication logs are provided as CSV input.

2) Input validation checks required fields and data types.

3) The rule-based engine calculates a threat score and severity.

4) The machine learning model predicts whether an event is Benign or Suspicious.

5) Anomaly detection and explanation components provide additional investigative context.

6) The Streamlit dashboard presents results for review.

7) The Streamlit interface presents analysis results for investigation 

### Running the Project

The project is developed in Python and uses Streamlit for its dashboard.

Clone the repository:

git clone https://github.com/Gavin77Ai/AI-Threat-Scoring-Engine.git

Enter the project directory:

cd AI-Threat-Scoring-Engine

Install the required dependencies after the project's requirements.txt file is added:

pip install -r requirements.txt

Run the dashboard from the directory containing the Streamlit application:

streamlit run app.py

Note: Update the setup instructions if your actual application filename or folder structure differs from these examples.

### Testing and Evaluation

The project includes automated tests for input validation, threat scoring, alert sorting, and threat summary calculations.

Model evaluation and test results will be documented alongside the final verified results. Performance metrics should be interpreted in the context of the available training data and test set.

### Limitations

Results depend on the quality and completeness of the input logs.

The training dataset is limited and does not represent every real-world attack scenario.

A suspicious prediction or anomaly is an investigative signal, not proof of malicious activity.

Human review is required before making security decisions.

### Future Improvements

Expand the training dataset with more diverse authentication events.

Improve detection performance using additional security indicators.

Add integrations with SIEM platforms and other security data sources.

Improve alert investigation workflows and reporting.

Evaluate the model against larger, more representative datasets.

### Disclaimer

This project is an educational cybersecurity prototype. It is intended for authorized testing, learning, and security analysis. It is not a replacement for a production security monitoring system or professional incident response procedures.

Author

Gavin Polynice

Cybersecurity and IT student interested in security operations, threat detection, and applied artificial intelligence.

GitHub: Gavin77Ai
