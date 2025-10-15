🛡️ Password Strength Analyzer
🔍 Description

A smart Password Strength Analyzer built using Python, which evaluates passwords based on:

Entropy calculation

Pattern detection (like sequences, repeats, digits-only, etc.)

Commonly breached password check using public datasets

Practical suggestions to strengthen weak passwords

It also provides an estimated “time to compromise” metric — showing approximately how long it would take for your password to be cracked based on its strength.

🚀 Features	

✅ Entropy Scoring — calculates bits of entropy to measure unpredictability.
✅ Regex-based Pattern Detection — flags weak patterns like 1234, qwerty, or repeated characters.
✅ Breach List Comparison — checks against the top 100k leaked passwords.
✅ Smart Suggestions — recommends short non-revealing additions (e.g., a9@).
✅ Estimated Crack Time — gives approximate time (“days”, “weeks”, “years”).
✅ Interactive CLI — user-friendly command-line interface.
✅ Offline or Online Mode — can work without internet after downloading the dataset.

🧰 Tech Stack
Component	Technology
Language	Python 3.10+
Libraries Used	requests, math, re, string, random
Dataset Source	NCSC / SecLists (Top 100k common passwords)
📂 Project Structure
📦 Password-Strength-Analyzer
│
├── passwords.py              # Main analyzer script
├── pwned_top100k.txt         # (Auto-downloaded breached password list)
├── README.md                 # Documentation file
└── requirements.txt          # Dependencies (optional)

⚙️ Installation & Setup
1️⃣ Clone the Repository
git clone https://github.com/<your-username>/password-strength-analyzer.git
cd password-strength-analyzer

2️⃣ Install Dependencies
pip install requests

3️⃣ (Optional) Download Breached Password List
python -c "import passwords as p; p.download_top_list()"


This will download the pwned_top100k.txt file automatically.

🧪 Usage
Run the Analyzer
python passwords.py

Sample Output
Password Analyzer — defensive checks only (no password is stored or printed).
Loaded local top list (100000 entries) for rank-based warnings.

Enter password to check (or just press Enter to exit): qwerty123

=== Analysis ===
Estimated entropy (bits): 37.6
Strength: Weak
!! Warning: This password appears in breached lists (rank: 92) !!
Estimated time to compromise (very coarse): days to weeks

Short Suggestions (non-revealing):
- This password appears in public breached lists — do NOT use it.
- Weak pattern detected: keyboard-pattern
- Try adding: g4@  (suggestion — add these characters somewhere in your password)

🧠 Example Use Cases

Educational tool for cybersecurity awareness

Integrate with sign-up systems for real-time feedback

Use in security hackathons or portfolio projects

Demonstrate regex and entropy logic in placement resumes

🧩 Future Enhancements

🌐 Add Flask or Streamlit web UI

🎨 Animated password strength bar (HTML/CSS/JS front-end)

🔒 Integration with haveibeenpwned API

📊 Visualization of entropy and crack time distribution

📜 License

This project is released under the MIT License — free to use and modify.

👨‍💻 Author

Mohan Kumar G B
💼 GitHub: @mohankumar-2107

📧 Email: mohankumargb666@gmail.com

🚀 Passionate about building secure, smart, and simple applications.