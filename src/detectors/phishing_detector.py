"""
Phishing Email Detector.

Analyzes emails for phishing indicators using a scoring system that
combines multiple signals:

1. URL analysis — suspicious links, IP-based URLs, mismatched display text
2. Language analysis — urgency, threats, rewards, impersonation phrases
3. Sender analysis — display name spoofing, freemail impersonation
4. Structure analysis — embedded forms, dangerous attachments
5. Combined scoring — weighted combination of all signals

Unlike the network detectors which use ML models, the phishing detector
uses a rule-based scoring system. This is intentional for v1 because:
- Phishing patterns are well-understood and codifiable
- Rule-based systems are transparent and explainable
- No training data needed to get started
- Easy to add new rules as new phishing techniques emerge

A future v2 could add an ML classifier trained on labeled phishing corpora
to catch novel patterns the rules miss.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity
from src.detectors.phishing_features import EmailFeatures, extract_email_features

logger = structlog.get_logger()


# Scoring weights for each feature category
SCORING_WEIGHTS = {
    "suspicious_urls": 3.0,
    "ip_based_urls": 4.0,
    "mismatched_urls": 5.0,
    "shortened_urls": 1.5,
    "suspicious_tlds": 2.0,
    "urgency": 2.0,
    "threats": 3.0,
    "rewards": 2.5,
    "impersonation": 2.0,
    "sender_mismatch": 4.0,
    "brand_impersonation": 5.0,
    "reply_to_mismatch": 3.0,
    "freemail_corporate": 2.0,
    "dangerous_attachment": 4.0,
    "embedded_form": 3.0,
    "password_field": 5.0,
    "high_link_ratio": 1.5,
}


class PhishingEmailDetector(BaseDetector):
    """
    Detects phishing emails using multi-signal scoring.

    Each email is scored across multiple phishing indicators. The scores
    are weighted and summed to produce a final phishing probability.
    Emails above the threshold are flagged as phishing.

    Usage:
        detector = PhishingEmailDetector(config, event_bus)
        await detector.start()
        results = await detector.analyze([
            {
                "subject": "Urgent: Verify your account",
                "body": "Click here to verify...",
                "sender_name": "PayPal Security",
                "sender_email": "security@paypa1.xyz",
            }
        ])
    """

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="phishing_email_detector", config=config, event_bus=event_bus)

        phishing_config = config.get("phishing_detector", {})
        self._score_threshold = phishing_config.get("score_threshold", 5.0)
        self._high_threshold = phishing_config.get("high_threshold", 15.0)
        self._medium_threshold = phishing_config.get("medium_threshold", 10.0)

    async def start(self) -> None:
        """Initialize the detector."""
        self._update_status(running=True)
        logger.info("phishing_detector_started")

    async def stop(self) -> None:
        """Shut down the detector."""
        self._update_status(running=False)
        logger.info("phishing_detector_stopped")

    async def analyze(self, data: Any) -> list[dict]:
        """
        Analyze a list of emails for phishing.

        Args:
            data: List of email dicts, each containing:
                - subject: str
                - body: str
                - sender_name: str
                - sender_email: str
                - reply_to: str (optional)
                - attachments: list[str] (optional)
                - urls: list[str] (optional)

        Returns:
            List of analysis results, one per email.
        """
        if not data:
            return []

        # Accept single email or list
        emails = data if isinstance(data, list) else [data]

        results = []
        phishing_count = 0

        for i, email in enumerate(emails):
            # Extract features
            features = extract_email_features(email)

            # Score the email
            score = self._compute_phishing_score(features)
            is_phishing = score >= self._score_threshold
            severity = self._score_to_severity(score)

            result = {
                "index": i,
                "is_phishing": is_phishing,
                "phishing_score": round(score, 2),
                "severity": severity.value if is_phishing else None,
                "confidence": min(1.0, round(score / 20.0, 3)),
                "features": features.to_dict(),
                "details": {
                    "subject": email.get("subject", ""),
                    "sender_name": email.get("sender_name", ""),
                    "sender_email": email.get("sender_email", ""),
                    "indicator_count": features.total_indicators,
                    "indicators": features.indicator_details,
                },
            }
            results.append(result)

            if is_phishing:
                phishing_count += 1
                await self.event_bus.publish(Event(
                    event_type=EventType.ANOMALY_DETECTED,
                    source=self.name,
                    severity=severity,
                    data={
                        "detector": self.name,
                        "attack_type": "phishing",
                        "phishing_score": round(score, 2),
                        "subject": email.get("subject", ""),
                        "sender": email.get("sender_email", ""),
                        "indicator_count": features.total_indicators,
                        "indicators": features.indicator_details[:5],
                    },
                ))

        self._update_status(
            events_processed=self._status.events_processed + len(emails),
            anomalies_detected=self._status.anomalies_detected + phishing_count,
        )

        logger.info(
            "phishing_analysis_complete",
            total_emails=len(emails),
            phishing_detected=phishing_count,
            phishing_rate=f"{phishing_count / len(emails) * 100:.1f}%",
        )

        return results

    def _compute_phishing_score(self, features: EmailFeatures) -> float:
        """
        Compute a weighted phishing score from extracted features.

        Higher score = more likely phishing.
        """
        score = 0.0

        # URL indicators
        score += features.suspicious_url_count * SCORING_WEIGHTS["suspicious_urls"]
        score += features.ip_based_url_count * SCORING_WEIGHTS["ip_based_urls"]
        score += features.mismatched_url_count * SCORING_WEIGHTS["mismatched_urls"]
        score += features.shortened_url_count * SCORING_WEIGHTS["shortened_urls"]
        score += features.suspicious_tld_count * SCORING_WEIGHTS["suspicious_tlds"]

        # Language indicators (scaled by match score)
        score += features.urgency_score * SCORING_WEIGHTS["urgency"]
        score += features.threat_score * SCORING_WEIGHTS["threats"]
        score += features.reward_score * SCORING_WEIGHTS["rewards"]
        score += features.impersonation_score * SCORING_WEIGHTS["impersonation"]

        # Sender indicators (binary)
        if features.sender_name_email_mismatch:
            score += SCORING_WEIGHTS["sender_mismatch"]
        if features.sender_domain_mismatch:
            score += SCORING_WEIGHTS["brand_impersonation"]
        if features.reply_to_mismatch:
            score += SCORING_WEIGHTS["reply_to_mismatch"]
        if features.freemail_sender and features.impersonation_score > 0:
            score += SCORING_WEIGHTS["freemail_corporate"]

        # Structure indicators
        if features.dangerous_attachment:
            score += SCORING_WEIGHTS["dangerous_attachment"]
        if features.has_form:
            score += SCORING_WEIGHTS["embedded_form"]
        if features.has_password_field:
            score += SCORING_WEIGHTS["password_field"]
        if features.link_to_text_ratio > 0.3:
            score += SCORING_WEIGHTS["high_link_ratio"]

        # Compound signals — combinations that are especially suspicious
        if features.urgency_score > 0.1 and features.suspicious_url_count > 0:
            score += 3.0  # Urgency + suspicious link = very likely phishing

        if features.sender_domain_mismatch and features.urgency_score > 0:
            score += 3.0  # Brand impersonation + urgency = very likely phishing

        return score

    def _score_to_severity(self, score: float) -> Severity:
        """Map phishing score to alert severity."""
        if score >= self._high_threshold:
            return Severity.HIGH
        elif score >= self._medium_threshold:
            return Severity.MEDIUM
        else:
            return Severity.LOW
