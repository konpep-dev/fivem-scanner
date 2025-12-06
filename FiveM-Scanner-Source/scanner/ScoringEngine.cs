using System;
using System.Collections.Generic;
using System.Linq;

namespace FiveMScanner
{
    public class ScoringResult
    {
        public string Name { get; set; } = string.Empty;
        public int Score { get; set; }
        public List<string> Contributors { get; set; } = new List<string>();
    }

    public static class ScoringEngine
    {
        // Minimum confidence threshold - findings below this are filtered out
        private const int MIN_CONFIDENCE_THRESHOLD = 30; // Only report findings with 30+ confidence
        
        // Compute a simple normalized score (0-100) for a signature based on matches.
        // matchedKeys: identifiers of which fields matched (e.g. "md5", "string:Susano", "process:Tomato.exe")
        public static ScoringResult ComputeScore(CheatSignature sig, IEnumerable<string> matchedKeys)
        {
            var matched = (matchedKeys ?? Enumerable.Empty<string>()).ToList();

            // Determine number of 'possible' matching dimensions for this signature
            int possible = 0;
            if (sig.FileNames?.Any() == true) possible++;
            if (sig.FileSizes?.Any() == true) possible++;
            if (sig.MD5Hashes?.Any() == true) possible++;
            if (sig.SHA1Hashes?.Any() == true) possible++;
            if (sig.SHA256Hashes?.Any() == true) possible++;
            if (sig.Strings?.Any() == true) possible++;
            if (sig.ProcessNames?.Any() == true) possible++;
            if (sig.DNS?.Any() == true) possible++;
            if (sig.FilePatterns?.Any() == true) possible++;

            if (possible == 0) possible = 1; // avoid division by zero

            int matches = matched.Count;

            double baseWeight = Math.Clamp(sig.Weight, 0, 100);
            double confidence = Math.Clamp(sig.Confidence, 0, 100) / 100.0;

            // Enhanced scoring: Multi-factor bonus
            // Hash matches are most reliable (100% confidence)
            // Multiple matches increase confidence
            double matchRatio = (double)matches / possible;
            double multiFactorBonus = matches > 1 ? Math.Min(1.2, 1.0 + (matches - 1) * 0.1) : 1.0;
            
            // Hash matches get maximum confidence boost
            bool hasHashMatch = matched.Any(m => m.Contains("hash") || m.Contains("md5") || m.Contains("sha"));
            if (hasHashMatch) multiFactorBonus = Math.Max(multiFactorBonus, 1.3);

            // raw score: weight * (matches / possible) * confidence * multiFactorBonus
            double raw = baseWeight * matchRatio * confidence * multiFactorBonus;

            int score = (int)Math.Round(Math.Min(100.0, raw));

            return new ScoringResult
            {
                Name = sig.Name,
                Score = score,
                Contributors = matched
            };
        }
        
        // Check if a finding should be reported based on confidence threshold
        public static bool ShouldReportFinding(ScoringResult result, int matchCount, bool hasHashMatch)
        {
            // Hash matches are always reported (highest confidence)
            if (hasHashMatch) return true;
            
            // Require minimum score threshold
            if (result.Score < MIN_CONFIDENCE_THRESHOLD) return false;
            
            // Require at least 2 matching factors for keyword-only matches (reduces false positives)
            if (!hasHashMatch && matchCount < 2 && result.Score < 50) return false;
            
            return true;
        }
    }
}
