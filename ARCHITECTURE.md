# BugMe Architecture Overview

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         BugMe v3.0                              │
│                  XSS Vulnerability Scanner                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      CLI Interface                              │
│                      (bugme.py)                                 │
│  • Argument parsing                                             │
│  • Component orchestration                                      │
│  • Error handling                                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Configuration Layer                          │
│                     (core/config.py)                            │
│  • Parse CLI arguments                                          │
│  • Manage settings                                              │
│  • Handle headers/cookies                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌──────────────┐    ┌──────────────────┐    ┌──────────────┐
│   Crawler    │    │  XSS Detector    │    │   Reporter   │
│              │    │                  │    │              │
│ • URL disc.  │───▶│ • Injection      │───▶│ • Terminal   │
│ • Form ext.  │    │ • Testing        │    │ • JSON       │
│ • Scope ctrl │    │ • Verification   │    │ • HTML       │
└──────────────┘    └──────────────────┘    └──────────────┘
                              │
        ┌─────────────────────┼─────────────────────┬─────────────┐
        ▼                     ▼                     ▼             ▼
┌──────────────┐    ┌──────────────────┐    ┌──────────────┐ ┌──────────────┐
│   Payload    │    │Source Analyzer   │    │  Verifier    │ │  Callback    │
│  Generator   │    │                  │    │              │ │  Manager     │
│              │    │ • Context det.   │    │ • Browser    │ │              │
│ • Context    │    │ • Sink/Source    │    │ • Alert det. │ │ • Interactsh │
│ • Encoding   │    │ • Filter det.    │    │ • Execution  │ │ • Burp Collab│
│ • Bypass     │    │ • CSP analysis   │    │   confirm    │ │ • XSS Hunter │
│              │    │                  │    │              │ │ • Custom API │
└──────────────┘    └──────────────────┘    └──────────────┘ └──────────────┘
        │                     │                     │                 │
        └─────────────────────┼─────────────────────┴─────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Utility Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ HTTP Client  │  │    Parser    │  │    Logger    │         │
│  │              │  │              │  │              │         │
│  │ • Requests   │  │ • HTML/JS    │  │ • Colored    │         │
│  │ • Retry      │  │ • URL manip  │  │ • Leveled    │         │
│  │ • Proxy      │  │ • Reflection │  │ • Formatted  │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagram

```
┌─────────┐
│  Input  │ (URL or Domain)
└────┬────┘
     │
     ▼
┌─────────────┐
│   Crawler   │ Discover URLs
└─────┬───────┘
      │
      │ List of URLs
      ▼
┌─────────────────┐
│  XSS Detector   │ For each URL:
└─────┬───────────┘
      │
      ├─▶ Parse parameters
      │
      ├─▶ Fetch page
      │
      ├─▶ Analyze source ──▶ Source Analyzer
      │                      • Detect context
      │                      • Find sinks/sources
      │                      • Check headers
      │
      ├─▶ Generate payloads ─▶ Payload Generator
      │                        • Context-aware
      │                        • Encoding
      │                        • Bypass
      │
      ├─▶ Inject & test
      │   • Send requests
      │   • Check reflection
      │   • Detect filters
      │
      ├─▶ Verify ──────────▶ Verifier
      │                      • Browser automation
      │                      • Alert detection
      │                      • Execution confirm
      │
      ├─▶ Generate PoC
      │
      └─▶ Collect results
           │
           ▼
      ┌─────────┐
      │Reporter │ Generate reports
      └─────────┘
           │
           ├─▶ Terminal (live)
           ├─▶ JSON file
           └─▶ HTML report
```

## Component Interaction

```
┌──────────────────────────────────────────────────────────────┐
│                    Scanning Workflow                         │
└──────────────────────────────────────────────────────────────┘

1. INITIALIZATION
   bugme.py
      ├─▶ Parse arguments
      ├─▶ Setup logger
      ├─▶ Print banner
      ├─▶ Initialize config
      └─▶ Create components

2. DISCOVERY (if domain mode)
   Crawler
      ├─▶ Start from base URL
      ├─▶ Extract links (BFS)
      ├─▶ Extract forms
      ├─▶ Filter by scope
      └─▶ Return URL list

3. ANALYSIS
   For each URL:
      Source Analyzer
         ├─▶ Parse HTML
         ├─▶ Extract scripts
         ├─▶ Find sinks (innerHTML, eval, etc.)
         ├─▶ Find sources (location.href, etc.)
         ├─▶ Check security headers
         └─▶ Return analysis

4. TESTING
   For each parameter:
      XSS Detector
         ├─▶ Generate marker
         ├─▶ Test reflection
         │
         ├─▶ If reflected:
         │   ├─▶ Detect context
         │   ├─▶ Get payloads
         │   ├─▶ Inject each payload
         │   ├─▶ Check if unencoded
         │   └─▶ Detect filters
         │
         └─▶ If successful:
             └─▶ Proceed to verification

5. VERIFICATION (if enabled)
   Verifier
      ├─▶ Setup browser
      ├─▶ Load URL with payload
      ├─▶ Wait for execution
      ├─▶ Check for alerts
      ├─▶ Monitor console
      └─▶ Return result

6. REPORTING
   Reporter
      ├─▶ Print live results
      ├─▶ Collect all findings
      ├─▶ Generate summary
      ├─▶ Export JSON (if requested)
      └─▶ Export HTML (if requested)
```

## Module Dependencies

```
bugme.py
  ├─▶ core.config
  ├─▶ core.crawler
  │    └─▶ utils.http_client
  │    └─▶ utils.parser
  ├─▶ core.ultimate_xss_detector
  │    ├─▶ utils.http_client
  │    ├─▶ utils.parser
  │    ├─▶ core.payload_generator
  │    ├─▶ core.source_analyzer
  │    ├─▶ core.verifier
  │    ├─▶ core.dom_xss_detector
  │    └─▶ core.blind_xss_detector
  │         └─▶ core.callback_manager
  ├─▶ core.reporter
  ├─▶ utils.banner
  ├─▶ utils.logger
  └─▶ utils.ui (Rich library)

External Dependencies:
  ├─▶ requests (HTTP & Callback verification)
  ├─▶ beautifulsoup4 (HTML parsing)
  ├─▶ lxml (XML/HTML processing)
  ├─▶ selenium (Browser automation)
  ├─▶ colorama (Terminal colors)
  ├─▶ rich (Beautiful terminal UI)
  └─▶ urllib3 (URL handling)
```

## Threading Model

```
┌────────────────────────────────────────────────────────────┐
│                    Main Thread                             │
│  • CLI parsing                                             │
│  • Component initialization                                │
│  • Result collection                                       │
└────────────────┬───────────────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────────────┐
│              ThreadPoolExecutor                            │
│              (max_workers = config.threads)                │
└────────────────┬───────────────────────────────────────────┘
                 │
     ┌───────────┼───────────┬───────────┐
     ▼           ▼           ▼           ▼
┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│Worker 1 │ │Worker 2 │ │Worker 3 │ │Worker N │
│         │ │         │ │         │ │         │
│ Scan    │ │ Scan    │ │ Scan    │ │ Scan    │
│ URL 1   │ │ URL 2   │ │ URL 3   │ │ URL N   │
└─────────┘ └─────────┘ └─────────┘ └─────────┘
     │           │           │           │
     └───────────┴───────────┴───────────┘
                 │
                 ▼
         Results Collection
```

## Context Detection Flow

```
Input Reflected in Response
         │
         ▼
    Find Marker
         │
    ┌────┴────┐
    │         │
    ▼         ▼
In Text?   In Attribute?
    │         │
    ▼         ▼
Inside    Which Attr?
<script>?     │
    │     ┌───┴───┐
    ▼     ▼       ▼
   JS   href/src  on*
Context    │      │
           ▼      ▼
          URL    JS
        Context Context
```

## Payload Selection Logic

```
Context Detected
       │
   ┌───┴───┬───────┬───────┐
   ▼       ▼       ▼       ▼
 HTML   Attribute  JS    URL
   │       │       │       │
   ▼       ▼       ▼       ▼
<script> " on*=  '; //  javascript:
<img>    '><     "; //  data:
<svg>    "><      -      
```

## Security Headers Analysis

```
HTTP Response
      │
      ▼
Extract Headers
      │
  ┌───┴───┬──────────┬────────────┐
  ▼       ▼          ▼            ▼
 CSP   X-XSS-   X-Content-   X-Frame-
       Protection  Type       Options
  │       │          │            │
  ▼       ▼          ▼            ▼
Parse  Check     Check        Check
Policy  Mode    nosniff      DENY
  │       │          │            │
  └───────┴──────────┴────────────┘
              │
              ▼
      Security Assessment
```

## Error Handling Strategy

```
┌────────────────────────────────────────────┐
│         Try-Catch Hierarchy                │
└────────────────────────────────────────────┘

Level 1: Main Entry Point (bugme.py)
  ├─▶ Catch KeyboardInterrupt (Ctrl+C)
  ├─▶ Catch general Exception
  └─▶ Exit with appropriate code

Level 2: Component Level
  ├─▶ Crawler: Handle network errors
  ├─▶ Detector: Handle injection errors
  ├─▶ Verifier: Handle browser errors
  └─▶ Reporter: Handle file I/O errors

Level 3: Utility Level
  ├─▶ HTTP Client: Retry on failure
  ├─▶ Parser: Handle malformed HTML
  └─▶ Logger: Never fail

Strategy:
  • Fail gracefully
  • Log errors if verbose
  • Continue with remaining work
  • Report partial results
```

## Performance Optimization

```
┌────────────────────────────────────────────┐
│         Optimization Techniques            │
└────────────────────────────────────────────┘

1. Connection Pooling
   • Reuse HTTP connections
   • Reduce handshake overhead

2. Multi-threading
   • Parallel URL scanning
   • Configurable worker count

3. Smart Crawling
   • Deduplication
   • Scope filtering
   • Depth limiting

4. Conditional Verification
   • Only verify promising findings
   • Optional browser automation

5. Efficient Parsing
   • lxml for speed
   • Lazy evaluation
   • Stream processing where possible

6. Memory Management
   • Limit stored URLs
   • Clear processed data
   • Generator patterns
```

## Extension Points

```
┌────────────────────────────────────────────┐
│         How to Extend BugMe                │
└────────────────────────────────────────────┘

1. Add New Payload Types
   └─▶ Edit: core/payload_generator.py
       • Add new context methods
       • Update get_payloads()

2. Add New Detection Methods
   └─▶ Edit: core/xss_detector.py
       • Add detection logic
       • Update scan_url()

3. Add New Report Formats
   └─▶ Edit: core/reporter.py
       • Add save_* method
       • Update CLI options

4. Add New Verification Methods
   └─▶ Edit: core/verifier.py
       • Add verification logic
       • Update verify()

5. Add New Analysis Features
   └─▶ Edit: core/source_analyzer.py
       • Add analysis methods
       • Update analyze()
```

---

## Key Design Principles

1. **Modularity**: Each component has single responsibility
2. **Extensibility**: Easy to add new features
3. **Robustness**: Comprehensive error handling
4. **Performance**: Multi-threaded, optimized
5. **Usability**: Clean CLI, colored output
6. **Maintainability**: Well-documented, clear structure
7. **Security**: Ethical design, safe defaults

---

## Blind XSS & Callback Manager (v3.0)

```
┌────────────────────────────────────────────┐
│         Callback Manager Flow              │
└────────────────────────────────────────────┘

1. INITIALIZATION
   Callback Manager
      ├─▶ Check provider (interactsh/burp/xsshunter/custom)
      ├─▶ Register with provider (if Interactsh)
      ├─▶ Obtain callback domain
      └─▶ Display configuration

2. PAYLOAD GENERATION
   Blind XSS Detector
      ├─▶ Generate unique identifier (MD5 hash)
      ├─▶ Create callback URL
      │   └─▶ Format: https://identifier.domain.com
      ├─▶ Generate callback payloads
      │   ├─▶ Image-based callbacks
      │   ├─▶ Script-based callbacks
      │   ├─▶ Cookie exfiltration
      │   └─▶ DOM capture
      └─▶ Store payload tracking info

3. INJECTION
   XSS Detector
      ├─▶ Inject blind XSS payloads
      ├─▶ Send to all parameters
      └─▶ Track sent payloads

4. VERIFICATION (Post-Scan)
   Callback Manager
      ├─▶ Wait for callbacks (configurable)
      ├─▶ Query callback server API
      │   ├─▶ Interactsh: Poll endpoint
      │   ├─▶ Burp: Manual check
      │   ├─▶ XSS Hunter: Manual check
      │   └─▶ Custom: API query
      ├─▶ Match callbacks to identifiers
      └─▶ Return verified vulnerabilities

5. REPORTING
   Reporter
      ├─▶ Add blind XSS to results
      ├─▶ Display confirmation message
      ├─▶ Include in summary counts
      └─▶ Export to JSON/HTML

6. CLEANUP
   Callback Manager
      └─▶ Deregister from provider (if Interactsh)
```

### Callback Provider Architecture

```
┌──────────────────────────────────────────────────────┐
│              Callback Manager                        │
│  • Provider abstraction layer                        │
│  • Unified interface for all providers               │
└──────────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┬──────────────┐
        ▼               ▼               ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  Interactsh  │ │     Burp     │ │ XSS Hunter   │ │   Custom     │
│              │ │ Collaborator │ │              │ │   Server     │
├──────────────┤ ├──────────────┤ ├──────────────┤ ├──────────────┤
│• Auto-reg    │ │• Manual setup│ │• Manual setup│ │• API-based   │
│• API polling │ │• Manual check│ │• Dashboard   │ │• Token auth  │
│• Free        │ │• Burp Suite  │ │• Free/Paid   │ │• Custom impl │
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
```

---

This architecture enables BugMe to be:
- ✅ Fast (multi-threaded)
- ✅ Accurate (context-aware)
- ✅ Reliable (error handling)
- ✅ Extensible (modular design)
- ✅ User-friendly (clean interface)
- ✅ Complete (all 5 XSS types with callback support)
