# DeepSight: AI-Driven SIEM Realtime Operator&#x20;

## Overview

In this project, I developed an AI-powered, real-time Security Information and Event Management (SIEM) system that detects, analyzes, and responds to threats as they occur. With AI for intrusion detection, Natural Language Processing (NLP) for generating concise alerts, and advanced integration with the Groq API for high-performance analysis, this system offers a robust solution for modern cybersecurity challenges.

### Technologies & Highlights

- **NLP-Powered Alerts**:\
  Automatically generates concise notifications and alarms to provide clear insights into security statuses.

- **Real-Time Monitoring**:\
  Continuously tracks system metrics (CPU, RAM, GPU), network packets, and event logs. The data is visualized on a dynamic dashboard built with Tailwind, Chart.js, Flask, and Socket.IO.

- **Database Integration for Logging and Analysis**:\
  Logs system metrics, network data, and event logs in a SQLite database to ensure comprehensive traceability and support forensic analysis.

### Project UI

The system features a **dynamic dashboard** that enables real-time visualization of system metrics, logs, and network events:

- **Live Charts** display CPU, memory, and disk usage.
- **AI-Generated Alerts** appear in a dedicated chat area.
- **Flask SocketIO** streams live updates to the client, ensuring continuous monitoring.

### Objective & Benefits

This SIEM system is designed to empower organizations by providing:

- **Real-Time Threat Detection**: Automated monitoring and alerting allow for immediate responses to cyber threats.
- **Actionable Insights**: AI-powered analysis transforms raw data into clear, actionable intelligence.
- **Enhanced Decision-Making**: AI integration boosts analysis speed, supporting proactive security operations.
- **Scalability & Traceability**: With robust logging and database integration, the system supports scalable and traceable security monitoring in critical environments.

### Installation

Follow these steps to get started:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/TheWhiteTower16/DeepSight.git
   cd DeepSight
   ```

2. **Install Dependencies:** scapy, transformers, GPUtil, flask_socketio

3. **Configure API Keys:**
   Create `config.py` in the project root with your configuration settings. For example:

   ```python
   #config.py

   import os
   from dotenv import load_dotenv

   load_dotenv()

   GROQ_API_KEY = os.getenv("GROQ_API_KEY")
   if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY environment variable is not set.")

   HF_TOKEN = os.getenv("HF_TOKEN")
   if not HF_TOKEN:
    raise ValueError("HF_TOKEN environment variable is not set.")

   PORT = int(os.getenv("PORT", 5000))
   ```

   Set the appropriate environment variables or directly update the file with your keys.

4. **Run the Application:**
   The main application file is named `DeepSight.py`. Start the application with:

   ```bash
   python DeepSight.py
   ```

5. **View Dashboard:** Navigate to http://localhost:5000
