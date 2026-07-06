# **Paillier Bank**
A secure, privacy-preserving banking backend system built with Django and PostgreSQL. This project implements homomorphic encryption to secure sensitive financial transactions and client data, ensuring that mathematical operations can be performed on ciphertexts without decrypting them first.The cryptographic infrastructure relies on the Paillier cryptosystem, which has been manually programmed from scratch to meet rigorous academic standards and provide complete control over the encryption logic.
## Key Features
- Custom Homomorphic Encryption: Full manual implementation of the Paillier cryptosystem, allowing for secure operations like homomorphic addition and subtraction on encrypted balances.
- Decoupled Architecture: Follows best practices for Django project structures by strictly isolating user access models within the authentication app and housing all transaction models within a dedicated banking app.  
- Security Through Obscurity: Implements stringent security principles by intentionally obfuscating detailed account status messages and limiting exposed system metadata.
- Role-Based Access Dashboards: Provides distinct interfaces and functionalities for administrators (e.g., manual cash deposits/withdrawals) and standard clients (e.g., transfers, balance viewing).  
- Comprehensive Testing Suite: Includes extensive automated testing to measure and validate the time (waktu) and memory (memori) overhead of key generation, encryption, decryption, and homomorphic operations.  
## Technology Stack
- Backend Framework: Python, Django  
- Database: PostgreSQL
- Frontend: HTML, CSS  
- Cryptosystem: Paillier (Asymmetric, Homomorphic)
## Project Structure
The project directory is structured as follows:  
- paillier_bank/: The core Django project configuration directory containing settings, URLs, and ASGI/WSGI configurations.  
- authentication/: Handles user authentication, models, and login/index views.  
- banking/: The core application managing transaction logic, data models, and cryptography.  
- - templates/pages/: Contains role-specific HTML views such as admin_bank_dashboard.html, nasabah_transfer.html, and riwayat_transaksi.html.  
- - text_encrypt.py: Houses the manual cryptographic utility functions.  
- - tests/: Contains rigorous performance tests categorized by memori (space) and waktu (time) metrics.  
- manage.py: The command-line utility for administrative Django tasks.  
- requirements.txt: Lists all Python dependencies required to run the project.