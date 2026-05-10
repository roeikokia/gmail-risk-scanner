# Gmail add-on sequrity Product 

A Gmail Workspace Add-on that analyzes every email the user opens, produces an explainable maliciousness verdict, and auto-quarantines confirmed bad messages. 

# About the product
A hybrid five-layer email security engine combining authentication, identity, threat-intelligence, heuristic, and AI-based analysis through a weighted composite scoring system. The platform correlates real-time reputation data from VirusTotal, AbuseIPDB, Google Safe Browsing, and URLhaus, while Anthropic Claude performs contextual phishing and social-engineering reasoning on pre-processed evidence. The system classifies emails into Safe, Suspicious, or Malicious, with high-confidence override rules capable of bypassing composite scoring and enforcing immediate quarantine. It is designed with graceful degradation, allowing deterministic security layers to retain protection authority even if the AI layer becomes unavailable. The backend is fully stateless and processes an email end-to-end including all external intelligence lookups in seconds.


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


## Way of Thinking and approach

My approach was to build a small version of a product that can provide meaningful protection against real-world phishing and malicious emails. Instead of relying entirely on AI or entirely on static rules, I designed a hybrid system that combines deterministic security signals, external threat intelligence, and contextual AI reasoning. The goal was to create a solution that is explainable, fast, privacy-aware, and resilient to failures. Every architectural decision was driven by three principles: defense in depth, high-confidence actions only, and honest acknowledgment of the system’s limitations and tradeoffs.

When I received the assignment, my first goal was not to immediately start coding, but to deeply understand the problem space. Since the field of email security was relatively new to me, I began by studying the domain itself: phishing, business email compromise (BEC), malicious attachments, spoofing, and the real-world damage these attacks cause to enterprises. To accelerate my learning process and organize the knowledge I was gathering, I created a personal “Email Security Dictionary” containing the key terms, technologies, protocols, and attack methods used in the industry. This became a reference point throughout the project and helped me build a more structured understanding of the ecosystem.

After understanding the “problem world,” I shifted my focus to the “solution world.” I researched how modern email security products are built today, what differentiates strong products from weak ones, which detection approaches create real security value, and where existing solutions still struggle. I also spoke with people working in the cybersecurity industry in order to better understand how real security teams think about detection quality, false positives, explainability, and user trust.

Only after understanding both the problem and the existing solutions, I started thinking deeply about the users themselves. I asked questions such as: What information does a user actually want to see when opening a Gmail add-on? What creates trust in a security product? What makes users rely on alerts rather than ignore them? What creates real value instead of noise? This thinking heavily influenced the product’s architecture and UX decisions.

From there, I started designing the system itself. I intentionally chose a multi-layered protection approach because I understood that high-quality email security products cannot rely on a single detection methodology. I identified two core pillars that would determine the product’s value: the scoring engine and the contextual explanation engine. Providing a malicious rate (sequrity score) without clear context is difficult for users to trust, while contextual explanations without reliable scoring create inconsistent protection and might mislead users. My goal became building them together in a way that was explainable, practical, and resilient.

I then designed a hybrid architecture that combines deterministic security signals, external threat intelligence, and AI-based contextual reasoning. During the process, I deliberately treated AI as an enhancement layer rather than the sole decision-maker. I wanted the system to remain explainable, auditable, and functional even when external AI services are unavailable.

Before starting development, I created a backlog document containing the product features, detection ideas, architecture decisions, and future improvements I wanted the system to support. I began implementation from the backend because it represented the core logic and decision-making engine of the product, and only afterward moved to the frontend and Gmail Add-on experience. Once the core functionality was completed, I worked iteratively through testing, debugging, refining the scoring behavior, and improving the user-facing explanations and contextual alerts. 
finally, I created this readme file and submitted the project.

One of the most important lessons from this project was understanding that building a good security product is not only about detecting threats, it is about designing systems that users can trust, understand, and realistically rely on in high-risk situations.
 
## Some Engineering Decisions

One of the main challenges in building the product was balancing detection quality, explainability, speed, and simplicity. I intentionally chose a hybrid architecture instead of relying entirely on AI, because deterministic security indicators provide a strong and reliable foundation that can serve as concrete evidence of malicious behavior. At the same time, the AI layer adds contextual understanding by correlating multiple independent signals, identifying behavioral patterns, and building a broader understanding of the overall threat landscape and intent behind the email. I also decided to keep the backend stateless and avoid persistent email storage in order to simplify privacy and security concerns. Features such as sandbox detonation were intentionally deferred to keep the prodcut lightweight, fast, relevant for users. Another important tradeoff was prioritizing high-confidence quarantine actions over aggressive blocking in order to reduce false positives and preserve user trust. Overall, the project taught me that good security products are often the result of carefully chosen constraints rather than trying to solve everything at once.


## What I Learned Building This Product

Building this product was a deep learning experience both from a cybersecurity perspective and from a product-engineering perspective. On the security side, it taught me how real-world layers of defense is built through layered thinking, tradeoffs, and handling uncertainty rather than relying on a single indicator or a single detector. On the engineering side, it showed me how quickly meaningful products can now be developed by combining strong architectural thinking with modern AI-assisted development workflows. The most interesting part for me was not only building the system itself, but learning how to make complex security decisions explainable, practical, and resilient under real-world constraints. It made me increasingly curious about how modern security products are evolving at the intersection of AI, product design, and intelligent threat detection.


