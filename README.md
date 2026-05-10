# Gmail Risk Scanner

A Gmail Workspace Add-on that analyzes every email the user opens, produces an explainable maliciousness verdict, and auto-quarantines confirmed bad messages. 

# About the product
A hybrid five-layer email security engine combining authentication, identity, threat-intelligence, heuristic, and AI-based analysis through a weighted composite scoring system. The platform correlates real-time reputation data from VirusTotal, AbuseIPDB, Google Safe Browsing, and URLhaus, while Anthropic Claude performs contextual phishing and social-engineering reasoning on pre-processed evidence. The system classifies emails into Safe, Suspicious, or Malicious, with high-confidence override rules capable of bypassing composite scoring and enforcing immediate quarantine. It is designed with graceful degradation, allowing deterministic security layers to retain protection authority even if the AI layer becomes unavailable. The backend is fully stateless, privacy-aware, and processes an email end-to-end - including all external intelligence lookups - in approximately 3-6 seconds.


## High-Level Architecture 

the product includes :

Gmail Add-on frontend , 
Stateless FastAPI backend , 
Five-layer detection engine , 
Parallel reputation lookups , 
Claude contextual analysis , 
Risk scoring + quarantine malicious mails



The system is split across two cooperating components. A **Gmail Workspace Add-on** runs inside the user's Gmail session: it parses each opened email (headers, body, URLs, attachments), hashes attachments locally so file bytes never leave the user's machine, gathers sender-relationship context from the recipient's own mailbox, and sends a structured payload to the backend over HTTPS.

The **backend is a stateless FastAPI service** - no database, no email-body persistence - that orchestrates a **five-layer detection engine**: authentication, sender identity, threat intelligence, content, and an AI layer. Each layer emits an independent sub-score and a list of named signals.

Threat intelligence is gathered through **parallel reputation lookups** against four external services (VirusTotal, AbuseIPDB, Google Safe Browsing, URLhaus), fanned out concurrently with bounded total latency. The aggregated evidence is then passed to **Anthropic Claude for contextual analysis** of intent, social-engineering patterns, and anomalies relative to prior emails from the same sender. Claude operates on pre-gathered evidence rather than via agentic tool use, which keeps latency, cost, and reproducibility predictable.

A **weighted scoring + quarantine flow** combines the five layers into a single composite score, classifies the email as Safe, Suspicious, or Malicious, and decides on the quarantine action. High-confidence override rules can bypass the composite math entirely when industry-consensus indicators are present, ensuring that proven-malicious mail is removed regardless of how the rest of the verdict scores.


## Approch - Way of Thinking

My approach was to build a small version of a product that can provide meaningful protection against real-world phishing and malicious emails. Instead of relying entirely on AI or entirely on static rules, I designed a hybrid system that combines deterministic security signals, external threat intelligence, and contextual AI reasoning. The goal was to create a solution that is explainable, fast, privacy-aware, and resilient to failures. Every architectural decision was driven by three principles: defense in depth, high-confidence actions only, and honest acknowledgment of the system’s limitations and tradeoffs.

 
## Tradeoffs & Engineering Decisions

One of the main challenges in building the product was balancing detection quality, explainability, speed, and simplicity. I intentionally chose a hybrid architecture instead of relying entirely on AI, because deterministic security layers provide more predictable and auditable behavior. I also decided to keep the backend stateless and avoid persistent email storage in order to simplify privacy and security concerns. Features such as sandbox detonation or OCR-based phishing detection were intentionally deferred to keep the first version lightweight, fast, and realistically shippable. Another important tradeoff was prioritizing high-confidence quarantine actions over aggressive blocking in order to reduce false positives and preserve user trust. Overall, the project taught me that good security products are often the result of carefully chosen constraints rather than trying to solve everything at once.


## What I Learned Building This Product

Building this product was a deep learning experience both from a cybersecurity perspective and from a modern product-engineering perspective. On the security side, it taught me how real-world phishing defense is built through layered thinking, tradeoffs, and handling uncertainty rather than relying on a single “magic” detector. On the engineering side, it showed me how quickly meaningful products can now be developed by combining strong architectural thinking with modern AI-assisted development workflows. The most interesting part for me was not only building the system itself, but learning how to make complex security decisions explainable, practical, and resilient under real-world constraints. It made me increasingly curious about how modern security products are evolving at the intersection of AI, product design, and defensive engineering.


