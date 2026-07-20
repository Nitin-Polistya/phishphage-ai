export const MAX_EMAIL_BYTES = 2_000_000;

export function validateRawEmail(value) {
  if (!value || !value.trim()) return 'Paste an email before starting analysis.';
  if (new TextEncoder().encode(value).length > MAX_EMAIL_BYTES) return 'This email exceeds the 2 MB processing limit.';
  return null;
}

export function displayRisk(score) {
  if (score >= 85) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 30) return 'Moderate';
  return 'Low';
}

export function displayPrediction(result) {
  if (result.prediction === 'phishing') return 'Phishing';
  return result.probability >= 0.35 ? 'Suspicious' : 'Low risk';
}

export function uniqueSignalValues(values) {
  return [...new Set(values)];
}
