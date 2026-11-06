'use strict';

// Turns the scores into a verdict. A text is flagged when its score reaches the threshold.
function decide(scores, threshold) {
  const flagged = Object.entries(scores)
    .filter(([, score]) => score >= threshold)
    .map(([name]) => name);
  return { verdict: flagged.length > 0 ? 'flagged' : 'clean', flagged };
}

// Scores as shown to people: four decimals, rounded down so that a score below the threshold
// never shows as the threshold itself.
function formatScore(score) {
  return (Math.floor(score * 10_000) / 10_000).toFixed(4);
}

module.exports = { decide, formatScore };
