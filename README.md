

\# BLINDSPOT AI



\### Closing the Privacy \& Prompt-Injection Gap Between Humans and Cloud AI



\## Project Overview



BLINDSPOT AI aims to protect users from accidentally sharing confidential information with public AI tools and from malicious prompt injection attacks.



Our proposed solution, \*\*AegisVault\*\*, is a local AI Security Gateway that checks user inputs before they reach external AI services.



\## Problem Statement



Users frequently share sensitive information such as personal details, confidential documents, source code, and business data with public AI tools.



At the same time, malicious instructions can manipulate AI systems through prompt injection attacks.



Traditional security systems do not adequately understand the meaning and context of AI interactions.



\## Proposed Solution – AegisVault



AegisVault acts as a security layer between users and cloud-based AI tools.



It aims to:



\- Detect sensitive information in text.

\- Identify confidential information in images.

\- Detect malicious prompt injection instructions.

\- Mask sensitive information before data is sent externally.

\- Block unsafe interactions.



\## Key Features



\- \*\*PII Detection:\*\* Identify personal and confidential information.

\- \*\*Prompt Injection Detection:\*\* Identify suspicious or malicious instructions.

\- \*\*Image Privacy Protection:\*\* Detect and blur sensitive regions in images.

\- \*\*Local Processing:\*\* Inspect data locally before external transmission.

\- \*\*Security Gateway:\*\* Allow, mask, or block unsafe requests.



\## Proposed Technology Stack



\- Frontend: HTML, CSS, JavaScript

\- Backend: Python

\- Security Engine: Python-based detection modules

\- Image Processing: OpenCV / OCR

\- Testing: Pytest



\## Project Structure



```text

BLINDSPOT-AI/

├── docs/

├── frontend/

├── backend/

├── security-engine/

├── models/

├── tests/

├── README.md

└── .gitignore

```



\## Privacy Approach



The proposed system is designed to inspect and protect sensitive information locally before it is shared with external AI services.



\## Development Status



Initial project structure and prototype implementation are present.



Core functionality, testing, and security validation are ongoing.

\## Future Scope



\- Integration with multiple AI platforms.

\- Improved detection accuracy.

\- Advanced image privacy protection.

\- Real-time security monitoring.



