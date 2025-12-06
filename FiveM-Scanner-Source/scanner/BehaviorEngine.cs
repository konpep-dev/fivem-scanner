using System;
using System.Collections.Generic;
using System.Linq;

namespace FiveMScanner
{
    // Lightweight behavior event recorder and correlator
    public class BehaviorEngine
    {
        private readonly Dictionary<string, List<(string Event, DateTime Time)>> _events = new Dictionary<string, List<(string, DateTime)>>();

        // Simple default weights for suspicious API events
        private readonly Dictionary<string, int> _eventWeights = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            { "CreateRemoteThread", 30 },
            { "WriteProcessMemory", 25 },
            { "VirtualProtectEx", 20 },
            { "LoadLibrary", 10 },
            { "OpenProcess", 8 },
            { "NtProtectVirtualMemory", 20 }
        };

        public void RecordEvent(string processName, string eventName)
        {
            if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(eventName))
                return;

            lock (_events)
            {
                if (!_events.ContainsKey(processName))
                    _events[processName] = new List<(string, DateTime)>();

                _events[processName].Add((eventName, DateTime.UtcNow));

                // Keep history bounded (last 500 events)
                if (_events[processName].Count > 500)
                    _events[processName].RemoveRange(0, _events[processName].Count - 500);
            }
        }

        // Compute a suspicion score for a process (0-100) by summing recent event weights
        public int ComputeSuspicionScore(string processName, TimeSpan lookback)
        {
            if (string.IsNullOrWhiteSpace(processName)) return 0;

            List<(string Event, DateTime Time)> listSnapshot;
            lock (_events)
            {
                if (!_events.TryGetValue(processName, out var tempList) || tempList == null || tempList.Count == 0) return 0;
                // work on a snapshot
                listSnapshot = tempList.ToList();
            }

            var cutoff = DateTime.UtcNow - lookback;
            int score = 0;

            foreach (var ev in listSnapshot.Where(e => e.Time >= cutoff))
            {
                if (_eventWeights.TryGetValue(ev.Event, out int w)) score += w;
                else score += 5; // small default weight
            }

            // Simple normalization
            return Math.Clamp(score, 0, 100);
        }

        public IEnumerable<string> GetRecentEvents(string processName, TimeSpan lookback)
        {
            if (string.IsNullOrWhiteSpace(processName)) return Enumerable.Empty<string>();

            lock (_events)
            {
                if (!_events.TryGetValue(processName, out var list) || list.Count == 0) return Enumerable.Empty<string>();
                var cutoff = DateTime.UtcNow - lookback;
                return list.Where(e => e.Time >= cutoff).Select(e => e.Event).ToList();
            }
        }
    }
}
