# Demo script (about 10 minutes)

A walkthrough for a presentation or viva. It uses the built-in demo samples.

**Needs the network** (marked 🌐 below):
- the "safe page" check on a live website (§3 step 1);
- the RDAP domain-age, DNS and ASN lookups (§4 stage 5).

If you're offline, the live page won't load and those lookups show "lookup
failed". Everything else works offline: the URL model, the warning page
(the test URL is served by your own backend), email analysis, QR decoding,
the report, and the built-in summaries.

## Before you start (5 minutes, the day before)

1. Start the backend:
   ```bash
   cd PhishIntel/phishing-detector/backend
   ..\..\.venv\Scripts\activate
   uvicorn api:app --port 8000
   ```
2. Open http://localhost:8000/health. It should show
   `"model_loaded": true, "model_version": "2.0"`.
3. Load or reload the extension (`chrome://extensions` → Load unpacked →
   `phishing-detector/extension/`). Open its **Settings**, click **Test
   connection**, and check it says "Connected — model v2.0 loaded".
4. Optional: start Ollama for local AI summaries. Without it, the built-in
   summaries work offline.
5. Open the figures in `phishing-detector/reports/` in a second window.

## 1. The problem and the claim (1 min)

> "Phishing is fought in two places: in the browser, where a user is about to
> type a password, and in the security team, who must investigate a
> reported email. This project covers both, with one backend that needs no
> paid API."

Show the architecture diagram in the root `README.md`.

## 2. The model, and why the first version was wrong (2 min)

Open `docs/EVALUATION.md`.

- "The starter model reported **F1 0.995**. When I audited it, I found three
  problems: label leakage, a homepage shortcut, and a random split."
- "On URLs it had never seen, it **flagged 75% of legitimate pages**." Show
  the ROC/PR figure: the blue (v1) curve against the orange (v2) one.
- "I rebuilt the dataset with real deep links and hosting-platform pages,
  split by domain, and calibrated the threshold for at least 97% precision.
  v2 has **F1 0.955 and 3.6% false alarms** on domains it never saw."

## 3. Browser extension (2 min)

1. 🌐 Visit a harmless page such as `https://www.bbc.co.uk/news`. The badge
   stays clear, and the popup shows **Looks safe**. Offline? Skip this step;
   the next one doesn't need the network.
2. Visit the test URL below. It's served by your own backend (a 404 page),
   so it's harmless, but it looks like phishing:
   ```
   http://127.0.0.1:8000/paypal-account-verify/login.php?session=8f7a6d5c4b3a2918&next=http://evil.example
   ```
   You get the **full-page warning**, with the hostname highlighted and the
   reasons: *raw IP address · random-looking URL · long query string*.
3. Click **Proceed anyway**. A banner remains on the page. Open the popup to
   show the reasons and the **Report false alarm** and **Investigate in
   PhishIntel** buttons.
4. Click **Investigate in PhishIntel**. A case opens for that URL.

## 4. PhishIntel investigation (4 min)

Go to http://localhost:8000/app/.

1. **Stage 1:** click **QR-code phishing (quishing)**, then **Analyze
   email**.
2. **Stage 2 (headers):**
   - SPF, DKIM and DMARC all pass, "but authentication only proves the
     attacker owns *their* domain".
   - Point out **Display-name spoofing** and **Sender domain imitates a
     brand** (`m1crosoft`), with their ATT&CK chips (T1684.002, T1684.001).
3. **Stage 3 (URLs):**
   - There is no clickable link in the email. The URL was **decoded from the
     QR-code image**.
   - It gets an ML score of ~96%, with reasons such as "looks like a
     misspelt brand name".
4. Back in Stage 1, load **Voicemail HTML attachment** and analyse it. In
   Stage 3, the **HTML attachment** row shows a redirect and obfuscated
   script, found by reading the file as text without opening it.
5. 🌐 **Stage 5 (infrastructure):**
   - Domain age (RDAP), the network owner (ASN), and DNS records. These are
     live lookups.
   - Findings such as "Domain is not registered" feed into the score.
6. **Stage 6 (report):**
   - Open **How the risk score was calculated**: every point is
     traceable.
   - Show the **MITRE ATT&CK** table, with links to attack.mitre.org.
   - Click **Generate executive summary** with *Built-in (offline)*.
   - If Gemini is configured, switch the engine to show the **privacy
     preview**: exactly what would be sent, already redacted.
   - Export **Report (Markdown)**.

## 5. Close (1 min)

- **Keyless and private by default.** Cloud AI is opt-in and reviewed
  before sending, and URL logging is opt-in.
- **Honest limits.** Phishing hosted on legitimate services and URLs with
  random IDs are the main error sources (`docs/EVALUATION.md` §5–6).
- **Future work:**
  - Retraining from user feedback (`feedback.py export`).
  - Page-content features.
  - Certificate Transparency as a second domain-age signal.

## Likely questions

| Question | Short answer |
|---|---|
| Why not a deep model? | 33 interpretable lexical features with a Random Forest give F1 0.955 at about 10 ms per URL, with per-feature explanations. The remaining errors come from information that isn't in the URL, so a bigger URL model wouldn't fix them. |
| How do you know the score isn't inflated again? | Splits are by domain, with no leaked features. The test set is touched once, and the v1 comparison uses only URLs neither model trained on (EVALUATION §3). |
| What if the API is down? | The extension fails open, so browsing is never blocked by an outage. |
| Does it send my emails anywhere? | No. Parsing the email, the rules, QR decoding and URL scoring all run locally. The infrastructure lookups do contact external services: rdap.org and your DNS resolver see the domain names, and Team Cymru sees the IP addresses. They never see the email's content. Gemini is opt-in, never gets the body, redacts recipients, and shows a preview first. |
| Why rules on top of ML? | Lookalike domains are rare in the training data, so the model under-weights them. The rules encode that knowledge explicitly and show up as reasons, so nothing is hidden. |
