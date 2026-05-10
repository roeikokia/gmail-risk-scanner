/**
 * Gmail Risk Scanner — Google Workspace Add-on
 *
 * Triggered when the user opens any message in Gmail. Parses the message,
 * computes attachment hashes, gathers sender-relationship history, sends
 * everything to the FastAPI backend for analysis, then renders a sidebar
 * card with the verdict and (when warranted) executes auto-quarantine plus
 * SOC and user notifications.
 *
 * Scopes used (declared in appsscript.json):
 *   - gmail.addons.current.message.readonly  — read the open message
 *   - gmail.modify                            — search history + quarantine
 *   - gmail.send                              — SOC alert + user notification
 *   - script.external_request                 — POST to backend
 *   - userinfo.email                          — sign notifications correctly
 */

// =================================================================
// Configuration
// =================================================================
const BACKEND_ANALYZE_URL = "https://unmovable-erupt-gravel.ngrok-free.dev/api/analyze-email";
const SOC_ALERT_EMAIL = "roeiko1soc@gmail.com";

// SHA-256 max attachment size to hash (10 MB). Larger files are skipped.
const MAX_ATTACHMENT_HASH_BYTES = 10 * 1024 * 1024;

// Sender history search caps
const SENDER_HISTORY_MAX_THREADS = 50;

// Anomaly-comparison recent emails caps
const RECENT_EMAILS_TO_FETCH = 5;
const RECENT_EMAIL_BODY_CHARS = 600;

// =================================================================
// Main contextual trigger
// =================================================================

/**
 * Triggered when the user opens any Gmail message.
 */
function buildRiskCard(e) {
  try {
    const messageId = e.gmail.messageId;
    const accessToken = e.gmail.accessToken;

    GmailApp.setCurrentMessageAccessToken(accessToken);

    const message = GmailApp.getMessageById(messageId);
    const thread = message.getThread();
    const alreadyQuarantined = thread.isInSpam() || thread.isInTrash();

    const parsedEmail = parseGmailAppMessage(message);
    const analysis = callBackend(parsedEmail);

    // Idempotency: only act if we haven't already quarantined this thread.
    if (!alreadyQuarantined && analysis && analysis.quarantine_action) {
      handleQuarantineAction_(thread, message, analysis, parsedEmail);
    }

    return buildAnalysisCard_(analysis, parsedEmail, alreadyQuarantined);
  } catch (err) {
    return buildErrorCard_(err);
  }
}

// =================================================================
// Email parsing
// =================================================================

function parseGmailAppMessage(message) {
  const rawContent = message.getRawContent();
  const plainBody = message.getPlainBody();
  const htmlBody = message.getBody();
  const subject = message.getSubject();
  const from = message.getFrom();
  const replyTo = message.getReplyTo();
  const attachments = message.getAttachments({
    includeInlineImages: false,
    includeAttachments: true
  });

  const fromDomain = extractDomainFromEmail_(from);
  const senderEmailAddress = extractEmailAddressFromHeader_(from);

  return {
    message_id: message.getId(),
    subject: subject,
    from_email: from,
    from_domain: fromDomain,
    reply_to_email: replyTo,
    reply_to_domain: extractDomainFromEmail_(replyTo),
    return_path: null,
    authentication_results: extractAuthenticationResults_(rawContent),
    body_text: plainBody,
    body_html: htmlBody,
    urls: extractUrls_(plainBody, htmlBody),
    attachments: attachments.map(parseAttachment_),
    sender_history: buildSenderHistory_(senderEmailAddress),
    recent_emails_from_sender: getSenderRecentEmails_(senderEmailAddress, message.getId())
  };
}

function parseAttachment_(att) {
  let sha256 = null;
  let size = null;

  try {
    const bytes = att.getBytes();
    size = bytes.length;
    if (size <= MAX_ATTACHMENT_HASH_BYTES) {
      sha256 = computeSha256Hex_(bytes);
    }
  } catch (e) {
    // best-effort — if we can't read bytes, just skip the hash
  }

  return {
    filename: att.getName(),
    mime_type: att.getContentType(),
    size: size,
    sha256: sha256
  };
}

function computeSha256Hex_(bytes) {
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  let hex = "";
  for (let i = 0; i < digest.length; i++) {
    let b = digest[i];
    if (b < 0) b += 256;
    const h = b.toString(16);
    hex += (h.length === 1 ? "0" : "") + h;
  }
  return hex;
}

// =================================================================
// Sender Relationship Analytics
// =================================================================

function buildSenderHistory_(senderEmail) {
  if (!senderEmail) {
    return {
      available: false,
      total_threads: 0,
      is_first_time_sender: false,
      has_user_replied: false,
      spam_count: 0,
      trash_count: 0
    };
  }

  try {
    // Total threads from this sender (excludes Spam/Trash by default)
    const threads = GmailApp.search('from:' + senderEmail, 0, SENDER_HISTORY_MAX_THREADS);
    const totalThreads = threads.length;

    let oldestDate = null;
    if (totalThreads > 0) {
      const lastThread = threads[threads.length - 1];
      try {
        oldestDate = lastThread.getLastMessageDate().toISOString();
      } catch (e) {
        oldestDate = null;
      }
    }

    // Sender's prior emails currently in Spam
    let spamCount = 0;
    try {
      const spamThreads = GmailApp.search(
        'from:' + senderEmail + ' in:spam', 0, SENDER_HISTORY_MAX_THREADS
      );
      spamCount = spamThreads.length;
    } catch (e) {
      // ignore — best effort
    }

    // Sender's prior emails currently in Trash
    let trashCount = 0;
    try {
      const trashThreads = GmailApp.search(
        'from:' + senderEmail + ' in:trash', 0, SENDER_HISTORY_MAX_THREADS
      );
      trashCount = trashThreads.length;
    } catch (e) {
      // ignore — best effort
    }

    // Has the user ever replied to this sender? Check the user's sent mail.
    let hasUserReplied = false;
    try {
      const myEmail = Session.getActiveUser().getEmail();
      if (myEmail) {
        const replies = GmailApp.search(
          'from:' + myEmail + ' to:' + senderEmail, 0, 5
        );
        hasUserReplied = replies.length > 0;
      }
    } catch (e) {
      // userinfo.email scope may be denied — silent fallback
    }

    return {
      available: true,
      total_threads: totalThreads,
      is_first_time_sender: totalThreads === 0,
      has_user_replied: hasUserReplied,
      spam_count: spamCount,
      trash_count: trashCount,
      oldest_thread_iso_date: oldestDate
    };
  } catch (err) {
    return {
      available: false,
      total_threads: 0,
      is_first_time_sender: false,
      has_user_replied: false,
      spam_count: 0,
      trash_count: 0
    };
  }
}

// =================================================================
// Sender's recent emails — for Claude's anomaly comparison
// =================================================================

/**
 * Returns up to RECENT_EMAILS_TO_FETCH most recent emails from this
 * sender, EXCLUDING the currently-open message. Bodies are truncated
 * client-side to RECENT_EMAIL_BODY_CHARS to keep the payload small.
 *
 * Returns an empty array on error / no history. The backend treats an
 * empty list as "no anomaly comparison possible".
 */
function getSenderRecentEmails_(senderEmail, currentMessageId) {
  if (!senderEmail) return [];

  try {
    const threads = GmailApp.search(
      'from:' + senderEmail, 0, RECENT_EMAILS_TO_FETCH + 1
    );
    if (!threads || threads.length === 0) return [];

    const results = [];

    for (let t = 0; t < threads.length && results.length < RECENT_EMAILS_TO_FETCH; t++) {
      const thread = threads[t];
      let messages;
      try {
        messages = thread.getMessages();
      } catch (e) {
        continue;
      }
      if (!messages || messages.length === 0) continue;

      // Pick the most recent message in the thread (last index in Gmail order)
      // that is NOT the currently-open message.
      let chosen = null;
      for (let m = messages.length - 1; m >= 0; m--) {
        const msg = messages[m];
        try {
          if (msg.getId() === currentMessageId) continue;
        } catch (e) {
          continue;
        }
        chosen = msg;
        break;
      }
      if (!chosen) continue;

      let body = "";
      try {
        body = chosen.getPlainBody() || "";
      } catch (e) {
        body = "";
      }
      if (body.length > RECENT_EMAIL_BODY_CHARS) {
        body = body.substring(0, RECENT_EMAIL_BODY_CHARS);
      }

      let receivedDate = null;
      try {
        receivedDate = chosen.getDate().toISOString();
      } catch (e) {
        receivedDate = null;
      }

      let attachmentsCount = 0;
      try {
        attachmentsCount = chosen.getAttachments({
          includeInlineImages: false,
          includeAttachments: true
        }).length;
      } catch (e) {
        attachmentsCount = 0;
      }

      let urlCount = 0;
      try {
        urlCount = (extractUrls_(body) || []).length;
      } catch (e) {
        urlCount = 0;
      }

      results.push({
        subject: chosen.getSubject ? chosen.getSubject() : null,
        body_snippet: body,
        received_iso_date: receivedDate,
        has_attachments: attachmentsCount > 0,
        url_count: urlCount
      });
    }

    return results;
  } catch (err) {
    return [];
  }
}

// =================================================================
// Backend call
// =================================================================

function callBackend(parsedEmail) {
  const response = UrlFetchApp.fetch(BACKEND_ANALYZE_URL, {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify({ email: parsedEmail }),
    muteHttpExceptions: true
  });

  const status = response.getResponseCode();
  const text = response.getContentText();

  if (status < 200 || status >= 300) {
    throw new Error("Backend returned HTTP " + status + ": " + text);
  }

  return JSON.parse(text);
}

// =================================================================
// Quarantine action + notifications
// =================================================================

/**
 * Risk-level driven actions:
 *   - Safe        → no action, no emails
 *   - Suspicious  → email stays in Inbox; SOC alert is sent
 *   - Malicious   → email moves to Trash; SOC alert + user notification sent
 */
function handleQuarantineAction_(thread, message, analysis, parsedEmail) {
  const level = analysis.risk_level || "Safe";

  // Safe: nothing to do.
  if (level === "Safe") return;

  // Suspicious: stay in Inbox, alert SOC only.
  if (level === "Suspicious") {
    try {
      sendSocAlert_(analysis, parsedEmail);
    } catch (err) {
      console.warn("SOC alert failed: " + err.message);
    }
    return;
  }

  // Malicious: move to Trash, then alert SOC and notify the user.
  try {
    thread.moveToTrash();
  } catch (err) {
    console.warn("Move to Trash failed: " + err.message);
    // Still send notifications so the SOC team can investigate.
  }

  try {
    sendSocAlert_(analysis, parsedEmail);
  } catch (err) {
    console.warn("SOC alert failed: " + err.message);
  }

  try {
    sendUserNotification_(parsedEmail, analysis);
  } catch (err) {
    console.warn("User notification failed: " + err.message);
  }
}

function sendSocAlert_(analysis, parsedEmail) {
  const level = analysis.risk_level || "UNKNOWN";
  const isMalicious = (level === "Malicious");
  const senderAddr = parsedEmail.from_email || "(unknown sender)";
  const threatCat = analysis.threat_category || "UNKNOWN";

  // Subject: severity emoji + level + threat-type + sender + score + action.
  // Example:
  //   [RISK SCANNER] 🔴 MALICIOUS [PHISHING] from noreply@gmail.com — 87/100 — Auto-quarantined to Trash
  //   [RISK SCANNER] 🟠 SUSPICIOUS [BEC] from someone@x.com — 53/100 — Flagged in Inbox
  const severityEmoji = isMalicious ? "🔴" : "🟠";
  const actionTag = isMalicious ? "Auto-quarantined to Trash" : "Flagged in Inbox";
  const subject = "[RISK SCANNER] " + severityEmoji + " " + level.toUpperCase()
    + " [" + threatCat + "] from " + senderAddr
    + " — " + analysis.score + "/100 — " + actionTag;

  const lines = [];
  lines.push("================================");
  lines.push("SECURITY INCIDENT NOTIFICATION");
  lines.push("================================");
  lines.push("");
  if (isMalicious) {
    lines.push("A MALICIOUS email was automatically detected and moved to the");
    lines.push("recipient's Trash folder.");
  } else {
    lines.push("A SUSPICIOUS email was flagged for review. The email REMAINS in the");
    lines.push("recipient's Inbox per policy — no automated movement was applied.");
  }
  lines.push("");

  // ---- INCIDENT METADATA ----
  lines.push("------ INCIDENT METADATA ------");
  lines.push("Detected at:        " + new Date().toISOString());
  lines.push("Recipient:          " + (Session.getActiveUser().getEmail() || "(unknown)"));
  lines.push("Malicious rate:     " + analysis.score + " / 100");
  lines.push("Risk Level:         " + level);
  lines.push("Threat Category:    " + threatCat);
  lines.push(
    "Action Taken:       " +
    (isMalicious
      ? "Auto-moved to Trash, recipient notified"
      : "Email left in Inbox; recipient sees a warning card and decides")
  );
  lines.push("");

  // ---- SENDER ----
  lines.push("------ SENDER ------");
  lines.push("From:               " + senderAddr);
  lines.push("Reply-To:           " + (parsedEmail.reply_to_email || "(none)"));
  lines.push("Sender domain:      " + (parsedEmail.from_domain || ""));
  if (analysis.threat_intel && analysis.threat_intel.sender_ip) {
    lines.push("Sender IP:          " + analysis.threat_intel.sender_ip);
  }
  lines.push("");

  // ---- AI ANALYSIS — moved to a prominent position so the SOC analyst
  //      gets immediate human-readable context BEFORE the raw technical data.
  //      Order per spec: Main findings FIRST, then Potential damage.
  if (analysis.claude_analysis && analysis.claude_analysis.available) {
    lines.push("------ AI ANALYSIS (Claude) ------");
    lines.push("Main findings:");
    (analysis.claude_analysis.main_findings || []).forEach(function(b) {
      lines.push("  - " + b);
    });
    lines.push("");
    if (analysis.claude_analysis.potential_damage) {
      lines.push("Potential damage:");
      lines.push("  " + analysis.claude_analysis.potential_damage);
      lines.push("");
    }
  } else {
    lines.push("------ AI ANALYSIS ------");
    lines.push("(Claude AI analysis was unavailable for this email; verdict is based");
    lines.push("on deterministic checks only.)");
    lines.push("");
  }

  // ---- EMAIL CONTENT ----
  lines.push("------ EMAIL CONTENT ------");
  lines.push("Subject:            " + (parsedEmail.subject || ""));
  const snippet = (parsedEmail.body_text || "").substring(0, 250);
  lines.push("Body snippet:");
  lines.push(snippet);
  lines.push("");

  // ---- THREAT INTELLIGENCE (raw technical findings) ----
  if (analysis.threat_intel) {
    lines.push("------ THREAT INTELLIGENCE ------");
    const ti = analysis.threat_intel;
    if (ti.url_results && ti.url_results.length > 0) {
      ti.url_results.forEach(function(r) {
        lines.push("URL: " + r.target);
        lines.push("  VirusTotal: " + r.malicious_count + "/" + r.total_engines + " engines");
        if (r.threat_names && r.threat_names.length) {
          lines.push("  VT threats: " + r.threat_names.join(", "));
        }
      });
    }
    if (ti.file_results && ti.file_results.length > 0) {
      ti.file_results.forEach(function(r) {
        lines.push("Attachment hash: " + r.target);
        lines.push("  VirusTotal: " + r.malicious_count + "/" + r.total_engines + " engines");
        if (r.type_description) lines.push("  Type: " + r.type_description);
      });
    }
    if (ti.abuseipdb_result) {
      const a = ti.abuseipdb_result;
      lines.push("AbuseIPDB:");
      lines.push("  Confidence: " + a.abuse_confidence + "%");
      lines.push("  Reports: " + a.total_reports + " (" + a.distinct_reporters + " reporters)");
      if (a.country_name) lines.push("  Country: " + a.country_name);
      if (a.isp) lines.push("  ISP: " + a.isp);
    }
    lines.push("");
  }

  // ---- DETECTED SIGNALS ----
  lines.push("------ SIGNALS FIRED ------");
  (analysis.signals || []).forEach(function(s) {
    lines.push("- " + s.title);
  });
  lines.push("");

  lines.push("------ END OF INCIDENT REPORT ------");
  lines.push("");
  lines.push("This is an automated alert from the Gmail Risk Scanner.");

  GmailApp.sendEmail(SOC_ALERT_EMAIL, subject, lines.join("\n"));
}

/**
 * Sent ONLY for Malicious emails (which are always auto-moved to Trash).
 * Suspicious and Safe emails do not trigger this notification.
 *
 * Body structure (in order):
 *   1. Opening alert line
 *   2. Action taken (moved to Trash)
 *   3. Why we flagged it (first Claude main finding)
 *   4. Potential damage (Claude's full potential_damage paragraph)
 *   5. Recommendation (do not recover)
 *   6. SOC notification confirmation
 *   7. Sign-off
 */
function sendUserNotification_(parsedEmail, analysis) {
  const myEmail = Session.getActiveUser().getEmail();
  if (!myEmail) return;

  const senderAddress = parsedEmail.from_email || "(unknown sender)";

  // Subject — informative + severity indicator + sender
  const subject = "🚨 Malicious email blocked — sender: " + senderAddress;

  // Reason: prefer Claude's first main finding for human-readable context
  let reason = "External threat intelligence and AI analysis identified this email as malicious.";
  if (analysis.claude_analysis && analysis.claude_analysis.available
      && analysis.claude_analysis.main_findings
      && analysis.claude_analysis.main_findings.length > 0) {
    reason = analysis.claude_analysis.main_findings[0];
  }

  // Potential damage from Claude (plain-language consequences for the user)
  let potentialDamage = "";
  if (analysis.claude_analysis && analysis.claude_analysis.available
      && analysis.claude_analysis.potential_damage) {
    potentialDamage = analysis.claude_analysis.potential_damage;
  }

  const lines = [];

  // 1. Opening alert
  lines.push("🚨 SECURITY ALERT 🚨");
  lines.push("");
  lines.push("Hi,");
  lines.push("");
  lines.push("Our security system has blocked a malicious email that was sent to you "
    + "from " + senderAddress + ".");
  lines.push("");

  // 2. Action taken
  lines.push("WHAT WE DID");
  lines.push("The email was identified as malicious and automatically moved to your "
    + "Trash folder. The full incident report has been forwarded to your SOC "
    + "teammate for further investigation.");
  lines.push("");

  // 3. Why we flagged it
  lines.push("WHY WE FLAGGED IT");
  lines.push(reason);
  lines.push("");

  // 4. Potential damage from Claude — this is the new prominent section
  if (potentialDamage) {
    lines.push("WHAT COULD HAVE HAPPENED");
    lines.push(potentialDamage);
    lines.push("");
  }

  // 5. Recommendation
  lines.push("WHAT YOU SHOULD DO");
  lines.push("• Do NOT attempt to recover this email from your Trash folder.");
  lines.push("• Do NOT click any link or open any attachment from this sender.");
  lines.push("• If you believe this was a mistake, contact your SOC team before taking any action.");
  lines.push("");
  lines.push("Your SOC team (" + SOC_ALERT_EMAIL + ") has been notified with full incident details.");
  lines.push("");
  lines.push("— Gmail Risk Scanner");

  GmailApp.sendEmail(myEmail, subject, lines.join("\n"));
}

// =================================================================
// Card UI
// =================================================================

function buildAnalysisCard_(analysis, parsedEmail, alreadyQuarantined) {
  const card = CardService.newCardBuilder();

  // Risk level comes from backend with one of three values:
  // "Safe" / "Suspicious" / "Malicious".
  const score = analysis.score;
  const level = analysis.risk_level || "Safe";
  const claude = analysis.claude_analysis || {};
  const claudeAvailable = !!claude.available;
  const levelColor = levelColor_(level);

  // ====================================================
  // SAFE EMAILS — MINIMAL CARD (no card header, big green check image)
  // ====================================================
  if (level === "Safe") {
    // Deliberately do NOT call card.setHeader() so the "Gmail Risk Scanner"
    // line doesn't render — the green check is the visual.

    // ---- Section 1: image only + 2 trailing spacer rows ----
    const imgSection = CardService.newCardSection();
    imgSection.addWidget(
      CardService.newImage()
        .setImageUrl(
          "https://www.gstatic.com/images/icons/material/system/2x/check_circle_googgreen_48dp.png"
        )
        .setAltText("Safe email")
    );
    // Two rows of empty space below the image.
    imgSection.addWidget(CardService.newTextParagraph().setText("&nbsp;"));
    imgSection.addWidget(CardService.newTextParagraph().setText("&nbsp;"));
    card.addSection(imgSection);

    // ---- Section 2: Risk level — rendered via CardSection.setHeader()
    // because section headers are the only CardService text element that
    // actually renders visibly larger than the default body text. ----
    const riskSection = CardService.newCardSection()
      .setHeader('<b>Risk level:</b> <font color="#1e8e3e">Safe</font>');
    // A section also needs at least one widget to render properly;
    // an empty TextParagraph keeps the section visible without adding noise.
    riskSection.addWidget(CardService.newTextParagraph().setText(""));
    card.addSection(riskSection);

    // ---- Section 3: Malicious rate — same pattern as Risk level. ----
    const rateSection = CardService.newCardSection()
      .setHeader('<b>Malicious rate:</b> <font color="#1e8e3e">'
        + score + '/100</font>');
    rateSection.addWidget(CardService.newTextParagraph().setText(""));
    card.addSection(rateSection);

    return card.build();
  }

  // ====================================================
  // SUSPICIOUS EMAILS — orange warning + custom section order
  // ====================================================
  if (level === "Suspicious") {
    // No card header — image carries the visual identity.

    // ---- Section 1: orange warning image + 2 spacers + risk level + rate ----
    const susSection = CardService.newCardSection();

    susSection.addWidget(
      CardService.newImage()
        .setImageUrl(
          "https://www.gstatic.com/images/icons/material/system/2x/warning_amber_48dp.png"
        )
        .setAltText("Suspicious email")
    );
    // One empty row below the image.
    susSection.addWidget(CardService.newTextParagraph().setText("&nbsp;"));

    // Risk level — label bold black, value "Suspicious" in bold orange.
    susSection.addWidget(
      CardService.newTextParagraph().setText(
        '<b>Risk level:</b> <font color="#f29900"><b>Suspicious</b></font>'
      )
    );
    // Malicious rate — label bold black, rate value in bold orange.
    susSection.addWidget(
      CardService.newTextParagraph().setText(
        '<b>Malicious rate:</b> <font color="#f29900"><b>' + score + '/100</b></font>'
      )
    );

    card.addSection(susSection);

    // ---- Section 2: POTENTIAL DAMAGE (visible, with ⚠ icon, black bold header) ----
    const damageSection = CardService.newCardSection()
      .setHeader('<b>⚠ Potential damage</b>');

    let potentialDamage = "";
    if (claudeAvailable && claude.potential_damage) {
      potentialDamage = claude.potential_damage;
    }

    if (potentialDamage) {
      damageSection.addWidget(
        CardService.newTextParagraph().setText(
          escape_(potentialDamage).replace(/\n/g, '<br>')
        )
      );
    } else {
      damageSection.addWidget(CardService.newTextParagraph().setText(
        '<font color="#5f6368">(no AI analysis available)</font>'
      ));
    }
    card.addSection(damageSection);

    // ---- Section 3: WHAT NOT TO DO (red header, red bullets) — visible ----
    let dontItems = [];
    if (claudeAvailable && claude.what_to_do && claude.what_to_do.do_not) {
      dontItems = claude.what_to_do.do_not.slice(0, 3);
    }

    const dontSection = CardService.newCardSection()
      .setHeader('<font color="#d93025"><b>What not to do</b></font>');

    if (dontItems.length === 0) {
      dontSection.addWidget(CardService.newTextParagraph().setText(
        '<font color="#5f6368">(no specific warnings)</font>'
      ));
    } else {
      dontItems.forEach(function(item) {
        dontSection.addWidget(
          CardService.newTextParagraph().setText(
            '<font color="#d93025">❌ ' + escape_(item) + '</font>'
          )
        );
      });
    }
    card.addSection(dontSection);

    // ---- Section 4: WHAT TO DO (green header, green bullets) — visible ----
    let doItems = [];
    if (claudeAvailable && claude.what_to_do && claude.what_to_do["do"]) {
      doItems = claude.what_to_do["do"].slice(0, 3);
    } else if (analysis.actions && analysis.actions.length) {
      doItems = analysis.actions.slice(0, 3);
    }

    const doSection = CardService.newCardSection()
      .setHeader('<font color="#1e8e3e"><b>What to do</b></font>');

    if (doItems.length === 0) {
      doSection.addWidget(CardService.newTextParagraph().setText(
        '<font color="#5f6368">(no specific recommendations)</font>'
      ));
    } else {
      doItems.forEach(function(item) {
        doSection.addWidget(
          CardService.newTextParagraph().setText(
            '<font color="#1e8e3e">✅ ' + escape_(item) + '</font>'
          )
        );
      });
    }
    card.addSection(doSection);

    // ---- Section 5: MAIN FINDINGS — COLLAPSIBLE (bold header) ----
    const findingsSection = CardService.newCardSection()
      .setHeader('<b>🔍 Main findings</b>')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);

    let findings = [];
    if (claudeAvailable && claude.main_findings && claude.main_findings.length > 0) {
      findings = claude.main_findings.slice(0, 5);
    } else if (analysis.signals && analysis.signals.length > 0) {
      // Fallback when Claude is unavailable: top deterministic signal titles
      const ordered = analysis.signals.slice().sort(function(a, b) {
        const sevRank = { high: 0, medium: 1, low: 2 };
        return (sevRank[a.severity] || 3) - (sevRank[b.severity] || 3);
      });
      findings = ordered.slice(0, 5).map(function(s) {
        return s.title + ' — ' + s.explanation;
      });
    }

    if (findings.length === 0) {
      findingsSection.addWidget(CardService.newTextParagraph().setText(
        '<font color="#5f6368">(no specific findings)</font>'
      ));
    } else {
      findings.forEach(function(f) {
        findingsSection.addWidget(
          CardService.newTextParagraph().setText('• ' + escape_(f))
        );
      });
    }
    card.addSection(findingsSection);

    return card.build();
  }

  // ====================================================
  // MALICIOUS EMAILS — same layout as Suspicious, with red image and red text
  // ====================================================
  if (level === "Malicious") {
    // No card header — image carries the visual identity.

    // ---- Section 1: red warning image + 1 spacer + risk level + rate ----
    const malSection = CardService.newCardSection();

    malSection.addWidget(
      CardService.newImage()
        .setImageUrl(
          "https://img.freepik.com/free-vector/red-exclamation-mark-symbol-attention-caution-sign-icon-alert-danger-problem_40876-3505.jpg?semt=ais_hybrid&w=740&q=80"
        )
        .setAltText("Malicious email")
    );
    // One empty row below the image.
    malSection.addWidget(CardService.newTextParagraph().setText("&nbsp;"));

    // Risk level — label bold black, "Malicious" in bold red.
    malSection.addWidget(
      CardService.newTextParagraph().setText(
        '<b>Risk level:</b> <font color="#d93025"><b>Malicious</b></font>'
      )
    );
    // Malicious rate — label bold black, rate value in bold red.
    malSection.addWidget(
      CardService.newTextParagraph().setText(
        '<b>Malicious rate:</b> <font color="#d93025"><b>' + score + '/100</b></font>'
      )
    );

    // Trash status banner — kept at the bottom of Section 1.
    if (alreadyQuarantined) {
      malSection.addWidget(CardService.newDivider());
      malSection.addWidget(
        CardService.newTextParagraph().setText(
          '<font color="#d93025"><b>⚠ Previously quarantined.</b></font><br>' +
          'This email is currently in your Trash folder.'
        )
      );
    } else if (analysis.quarantine_action
               && analysis.quarantine_action.action_taken === "MOVE_TO_TRASH") {
      malSection.addWidget(CardService.newDivider());
      malSection.addWidget(
        CardService.newTextParagraph().setText(
          '<font color="#d93025"><b>🗑 Moved to Trash.</b></font><br>' +
          escape_(analysis.quarantine_action.reason || '')
        )
      );
    }

    card.addSection(malSection);

    // ---- Section 2: POTENTIAL DAMAGE (visible, with ⚠ icon, RED bold header) ----
    const damageSection = CardService.newCardSection()
      .setHeader('<font color="#d93025"><b>⚠ Potential damage</b></font>');

    let potentialDamage = "";
    if (claudeAvailable && claude.potential_damage) {
      potentialDamage = claude.potential_damage;
    }

    if (potentialDamage) {
      damageSection.addWidget(
        CardService.newTextParagraph().setText(
          escape_(potentialDamage).replace(/\n/g, '<br>')
        )
      );
    } else {
      damageSection.addWidget(CardService.newTextParagraph().setText(
        '<font color="#5f6368">(no AI analysis available)</font>'
      ));
    }
    card.addSection(damageSection);

    // ---- Section 3: WHAT NOT TO DO (red header, red bullets) — visible ----
    let dontItems = [];
    if (claudeAvailable && claude.what_to_do && claude.what_to_do.do_not) {
      dontItems = claude.what_to_do.do_not.slice(0, 3);
    }

    const dontSection = CardService.newCardSection()
      .setHeader('<font color="#d93025"><b>What not to do</b></font>');

    if (dontItems.length === 0) {
      dontSection.addWidget(CardService.newTextParagraph().setText(
        '<font color="#5f6368">(no specific warnings)</font>'
      ));
    } else {
      dontItems.forEach(function(item) {
        dontSection.addWidget(
          CardService.newTextParagraph().setText(
            '<font color="#d93025">❌ ' + escape_(item) + '</font>'
          )
        );
      });
    }
    card.addSection(dontSection);

    // ---- Section 4: WHAT TO DO (green header, green bullets) — visible ----
    let doItems = [];
    if (claudeAvailable && claude.what_to_do && claude.what_to_do["do"]) {
      doItems = claude.what_to_do["do"].slice(0, 3);
    } else if (analysis.actions && analysis.actions.length) {
      doItems = analysis.actions.slice(0, 3);
    }

    const doSection = CardService.newCardSection()
      .setHeader('<font color="#1e8e3e"><b>What to do</b></font>');

    if (doItems.length === 0) {
      doSection.addWidget(CardService.newTextParagraph().setText(
        '<font color="#5f6368">(no specific recommendations)</font>'
      ));
    } else {
      doItems.forEach(function(item) {
        doSection.addWidget(
          CardService.newTextParagraph().setText(
            '<font color="#1e8e3e">✅ ' + escape_(item) + '</font>'
          )
        );
      });
    }
    card.addSection(doSection);

    // ---- Section 5: MAIN FINDINGS — COLLAPSIBLE (bold header) ----
    const findingsSection = CardService.newCardSection()
      .setHeader('<b>🔍 Main findings</b>')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);

    let findings = [];
    if (claudeAvailable && claude.main_findings && claude.main_findings.length > 0) {
      findings = claude.main_findings.slice(0, 5);
    } else if (analysis.signals && analysis.signals.length > 0) {
      const ordered = analysis.signals.slice().sort(function(a, b) {
        const sevRank = { high: 0, medium: 1, low: 2 };
        return (sevRank[a.severity] || 3) - (sevRank[b.severity] || 3);
      });
      findings = ordered.slice(0, 5).map(function(s) {
        return s.title + ' — ' + s.explanation;
      });
    }

    if (findings.length === 0) {
      findingsSection.addWidget(CardService.newTextParagraph().setText(
        '<font color="#5f6368">(no specific findings)</font>'
      ));
    } else {
      findings.forEach(function(f) {
        findingsSection.addWidget(
          CardService.newTextParagraph().setText('• ' + escape_(f))
        );
      });
    }
    card.addSection(findingsSection);

    return card.build();
  }

  // Defensive fallback (should not be reached)
  return card.build();
}

function buildErrorCard_(err) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Gmail Risk Scanner"))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText(
            '<font color="#d93025"><b>Error during analysis</b></font><br>' +
            escape_(err && err.message ? err.message : String(err))
          )
        )
    )
    .build();
}

// =================================================================
// UI helpers
// =================================================================

// Three risk levels only: Safe / Suspicious / Malicious.
// Backend sends them with that exact capitalization.
function levelColor_(level) {
  if (level === "Malicious") return "#d93025"; // red
  if (level === "Suspicious") return "#f29900"; // orange
  return "#1e8e3e"; // green (Safe)
}

// =================================================================
// Header / parsing helpers
// =================================================================

function extractUrls_(plainText, htmlText) {
  // Map keyed by URL → { url, domain, visible_text }
  const byUrl = {};

  // 1) Parse <a href="..."> ... </a> pairs out of the HTML body to capture
  //    visible anchor text — needed for link-text-vs-href phishing detection.
  if (htmlText) {
    const anchorRe = /<a\b[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = anchorRe.exec(htmlText)) !== null) {
      const href = m[1];
      if (!/^https?:\/\//i.test(href)) continue;
      const innerHtml = m[2] || "";
      // Strip nested tags, decode common entities, collapse whitespace.
      const visible = innerHtml
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/&quot;/gi, '"')
        .replace(/&#39;/gi, "'")
        .replace(/\s+/g, " ")
        .trim();
      if (!byUrl[href]) {
        byUrl[href] = {
          url: href,
          domain: extractDomainFromUrl_(href),
          visible_text: visible || null
        };
      }
    }
  }

  // 2) Plain-text URL fallback for URLs not wrapped in an anchor.
  const plainRe = /https?:\/\/[^\s"'<>]+/gi;
  const plainMatches = ((plainText || "") + " " + (htmlText || "")).match(plainRe) || [];
  plainMatches.forEach(function(url) {
    if (!byUrl[url]) {
      byUrl[url] = {
        url: url,
        domain: extractDomainFromUrl_(url),
        visible_text: null
      };
    }
  });

  return Object.keys(byUrl).map(function(k) { return byUrl[k]; });
}

function extractDomainFromUrl_(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch (e) {
    return null;
  }
}

function extractEmailAddressFromHeader_(value) {
  if (!value) return null;
  const match = value.match(/<([^>]+)>/);
  return match ? match[1].trim() : value.trim();
}

function extractDomainFromEmail_(value) {
  if (!value) return null;
  const email = extractEmailAddressFromHeader_(value);
  if (!email) return null;
  const at = email.indexOf("@");
  if (at === -1) return null;
  return email.substring(at + 1).trim().toLowerCase().replace(/[>"]/g, "");
}

function extractAuthenticationResults_(rawContent) {
  if (!rawContent) return null;
  const match = rawContent.match(/Authentication-Results:[\s\S]*?(?=\n[A-Za-z-]+:|\n\n)/i);
  return match ? match[0] : null;
}

function escape_(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
