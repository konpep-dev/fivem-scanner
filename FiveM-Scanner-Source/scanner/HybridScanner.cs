using System;
using System.Collections.Generic;
using System.Linq;

namespace FiveMScanner
{
    // Hybrid scanning helper: fast exact checks + simple fuzzy string matching
    public class HybridScanner
    {
        // Quick exact check helper
        public bool IsExactHashMatch(HashSet<string> knownHashes, string hash)
        {
            if (knownHashes == null || string.IsNullOrWhiteSpace(hash)) return false;
            return knownHashes.Contains(hash, StringComparer.OrdinalIgnoreCase);
        }

        // Simple fuzzy search: returns matched pattern and distance if within threshold, otherwise null.
        public (string Pattern, int Distance)? FuzzyMatchString(string input, IEnumerable<string> patterns, int maxDistance = 3)
        {
            if (string.IsNullOrWhiteSpace(input) || patterns == null) return null;

            string best = string.Empty;
            int bestDist = int.MaxValue;

            foreach (var p in patterns)
            {
                if (string.IsNullOrWhiteSpace(p)) continue;
                int d = LevenshteinDistanceLimited(input, p, maxDistance);
                if (d >= 0 && d < bestDist)
                {
                    bestDist = d;
                    best = p;
                }
            }

            if (string.IsNullOrEmpty(best)) return null;
            return (best, bestDist);
        }

        // Levenshtein distance with early exit if distance exceeds limit. Returns -1 if over limit.
        private int LevenshteinDistanceLimited(string a, string b, int limit)
        {
            if (a == null) a = string.Empty;
            if (b == null) b = string.Empty;

            int n = a.Length;
            int m = b.Length;

            if (Math.Abs(n - m) > limit) return -1;

            var prev = new int[m + 1];
            var curr = new int[m + 1];

            for (int j = 0; j <= m; j++) prev[j] = j;

            for (int i = 1; i <= n; i++)
            {
                curr[0] = i;
                int minRow = curr[0];
                for (int j = 1; j <= m; j++)
                {
                    int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
                    curr[j] = Math.Min(Math.Min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
                    if (curr[j] < minRow) minRow = curr[j];
                }

                if (minRow > limit) return -1; // early exit
                var tmp = prev; prev = curr; curr = tmp;
            }

            return prev[m] <= limit ? prev[m] : -1;
        }
    }
}
