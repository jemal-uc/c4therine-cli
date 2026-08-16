# C4therine CLI

> An AI-powered command-line assistant for cybersecurity research, OSINT workflows, web intelligence, and authorized security auditing.

C4therine CLI is a Python-based terminal assistant that combines natural-language interaction with modular tools for web search, scraping, OSINT collection, domain reconnaissance, and defensive website security analysis.

Built as a personal portfolio and experimental project, C4therine demonstrates how an AI-powered CLI can coordinate research and security workflows from a single terminal interface. It is more than a chatbot: commands are routed to specialized modules, while the AI engine provides explanations, summaries, and report generation.

> [!WARNING]
> C4therine is intended for education, ethical research, and authorized security testing only. Never scan, scrape, investigate, or collect information from systems, websites, accounts, or individuals without explicit permission.

## Highlights

- Interactive AI assistant powered by the Groq API
- Command-based workflows with a modular tool registry
- Short-term conversation memory and user profiles
- Prompt-response caching
- Token usage, cost estimation, and budget monitoring
- Automated web search and CSS-selector-based scraping
- OSINT collection and intelligence pipelines
- DNS, WHOIS, subdomain, and certificate reconnaissance
- GitHub, username, email, and breach intelligence modules
- Graph-based relationship analysis with NetworkX and Neo4j
- Defensive website security auditing
- SSL/TLS and HTTP security-header analysis
- Technology-stack detection
- Basic open-redirect and CSRF-protection checks
- AI-assisted Markdown security reports
- CSV, HTML, and JSON exports
- Futuristic terminal UI with a boot sequence and typing animation

## How It Works

C4therine uses a custom command router to determine whether an input should be handled as a normal AI conversation or delegated to a specialized tool.

```text
User input
   ├── Natural-language prompt → AI engine → Response
   └── /command               → Command router → Registered tool
                                                    ├── Search and scraping
                                                    ├── OSINT pipeline
                                                    ├── Domain reconnaissance
                                                    ├── Security scanner
                                                    └── Export utilities
```

The AI engine connects to Groq's OpenAI-compatible API, while the surrounding application manages memory, caching, usage tracking, budget limits, rendering, and tool execution.

## Core Capabilities

### AI Assistant

- Natural-language interaction inside the terminal
- Conversation memory for the active session
- Configurable user profile
- Cached responses for repeated prompts
- Token usage and estimated cost tracking
- Budget-limit validation before API requests

The default model is:

```text
llama-3.1-8b-instant
```

### Web Search and Scraping

C4therine can automate web searches and extract page content using CSS selectors.

```text
/search cybersecurity news 10
/scraping https://example.com h1 20
```

Scraped results can be exported for further research and analysis.

### OSINT and Web Intelligence

The OSINT modules support ethical, authorized research involving:

- Name-based lookup
- Username intelligence
- Email intelligence
- GitHub intelligence
- Breach-related intelligence
- Domain reconnaissance
- DNS resolution
- WHOIS records
- Subdomain enumeration
- Certificate-record searches
- Graph-based relationship analysis
- Report generation and structured exports

### Defensive Security Scanner

The `/scan` command performs a basic defensive audit of a permitted website.

```text
/scan https://example.com
```

The scanner checks:

- SSL/TLS certificate validity
- HTTP security headers
- Detected technology stack
- Potential open-redirect indicators
- Basic CSRF-protection indicators
- A basic security score

After collecting the telemetry, C4therine can generate an AI-assisted security report in Markdown.

> [!IMPORTANT]
> Only run security scans against websites you own or have explicit authorization to test. The scanner is not a substitute for a professional penetration test.

## Available Commands

### System and AI

| Command | Description |
| --- | --- |
| `/help` | Display all available commands |
| `/status` | Show the current system status |
| `/model` | Display the active AI model |
| `/usage` | Show token usage and estimated cost |
| `/budget` | View or configure the budget limit |
| `/profile` | View or update the user profile |
| `/history` | Show the current conversation history |
| `/restart` | Clear the active session memory |
| `/clear` | Clear the terminal screen |
| `/exit` | Close the application |

### Search and Scraping

| Command | Description |
| --- | --- |
| `/search` | Run a web search |
| `/scraping` | Extract website content with a CSS selector |

### OSINT and Reconnaissance

| Command | Description |
| --- | --- |
| `/osint` | Run the legacy OSINT lookup |
| `/osint-pipeline` | Run the advanced intelligence pipeline |
| `/domain-recon` | Perform domain reconnaissance |
| `/dns-lookup` | Query DNS records |
| `/whois` | Retrieve WHOIS information |
| `/subdomain` | Enumerate subdomains |
| `/cert-search` | Search certificate records |
| `/github-intel` | Collect GitHub-related intelligence |
| `/breach-check` | Check breach-related intelligence |

### Export

| Command | Description |
| --- | --- |
| `/export-csv` | Export results as CSV |
| `/export-html` | Export results as HTML |
| `/export-json` | Export results as JSON |

Run `/help` inside the application to view the latest syntax and command options.

## Technology Stack

| Area | Technologies |
| --- | --- |
| Core | Python, Python Dotenv |
| AI | Groq API |
| HTTP and parsing | Requests, BeautifulSoup4 |
| Terminal UI | Rich, PyFiglet |
| Search | DuckDuckGo Search / DDGS |
| Network intelligence | DNSPython |
| Graph analysis | NetworkX, Neo4j |
| Computer vision | OpenCV, Face Recognition, Pillow |
| Data and machine learning | Scikit-learn, NLTK |
| Visualization | Matplotlib |

## Project Structure

```text
c4therine-cli/
├── main.py
├── requirements.txt
├── .env.example
├── .gitignore
├── config/
│   └── settings.py
├── core/
│   ├── ai_engine.py
│   ├── cache.py
│   ├── command_router.py
│   ├── memory.py
│   ├── tool_registry.py
│   └── usage_tracker.py
├── tools/
│   ├── scraper.py
│   ├── search.py
│   ├── osint/
│   └── security/
├── ui/
│   └── renderer.py
└── tests/
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/jemal-uc/c4therine-cli.git
cd c4therine-cli
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\activate
```

Activate it on macOS or Linux:

```bash
source venv/bin/activate
```

### 3. Install the dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the environment

Copy the example environment file:

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

macOS or Linux:

```bash
cp .env.example .env
```

Add your Groq API key to `.env`:

```env
GROQ_API_KEY=your_groq_api_key_here
```

> [!CAUTION]
> Never commit `.env` or expose your API key publicly. The file is excluded through `.gitignore`.

## Running C4therine

Start the application with:

```bash
python main.py
```

After the boot sequence, you can chat with the assistant directly:

```text
You > Explain what HTTP security headers are.
```

Or run a built-in command:

```text
You > /scan https://example.com
```

## Responsible Use

By using C4therine CLI, you agree to:

- Operate only on systems and data you own or are authorized to access
- Respect privacy, platform terms, robots.txt policies, and applicable laws
- Avoid harassment, stalking, credential attacks, unauthorized profiling, or invasive data collection
- Treat automated findings as preliminary indicators that require manual verification
- Protect exported intelligence and reports from unauthorized access

The author is not responsible for misuse, unauthorized activity, or damage resulting from this software.

## Project Status

C4therine CLI is an experimental personal project and portfolio showcase. It demonstrates experience in:

- Python CLI application development
- AI API integration
- Modular software architecture
- Cybersecurity automation
- OSINT and web-intelligence workflows
- Search and scraping automation
- Usage tracking and report generation

The project is under active experimentation and may contain incomplete modules or changing command behavior.

## Roadmap

- [ ] Expand command documentation and examples
- [ ] Improve automated test coverage
- [ ] Strengthen validation and error handling
- [ ] Introduce plugin-based tool loading
- [ ] Add persistent database storage
- [ ] Improve security and intelligence report templates
- [ ] Add safer OSINT workflow controls
- [ ] Build an optional web dashboard

## Contributing

This is currently a personal experimental project. Suggestions and responsible contributions are welcome through GitHub issues or pull requests.

When contributing to security-related modules, ensure that new functionality includes clear authorization boundaries, safe defaults, and appropriate documentation.

## Author

Created by **J3MAL** as a personal AI, OSINT, and cybersecurity CLI experiment.

## License

No license has been specified yet. Until a license is added, all rights remain reserved by the author.
