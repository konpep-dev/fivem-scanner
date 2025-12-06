using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace FiveMScanner
{
    // Simple local telemetry client (privacy-aware)
    public class TelemetryClient
    {
        private readonly string _cachePath;
        public bool OptIn { get; set; } = false;

        public TelemetryClient(string cachePath = null)
        {
            _cachePath = cachePath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "telemetry_cache.json");
        }

        public void SaveLocalReport(object report)
        {
            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                var json = JsonSerializer.Serialize(report, options);
                File.WriteAllText(_cachePath, json);
            }
            catch
            {
                // Don't throw; telemetry must not break scan
            }
        }

        public T? LoadLocalCache<T>() where T : class
        {
            try
            {
                if (!File.Exists(_cachePath)) return null;
                var json = File.ReadAllText(_cachePath);
                return JsonSerializer.Deserialize<T>(json);
            }
            catch
            {
                return null;
            }
        }

        // Upload report to server (if OptIn). Safe no-throw variant.
        public async Task<bool> UploadReportAsync(string serverBaseUrl, object report)
        {
            if (!OptIn || string.IsNullOrWhiteSpace(serverBaseUrl) || report == null) return false;

            try
            {
                using var client = new HttpClient();
                client.Timeout = TimeSpan.FromSeconds(30);
                var json = JsonSerializer.Serialize(report);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var url = serverBaseUrl.TrimEnd('/') + "/api/telemetry";
                var resp = await client.PostAsync(url, content);
                return resp.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        // Fetch available rulepacks from server (returns raw JSON or null)
        public async Task<string?> FetchRulePacksAsync(string serverBaseUrl)
        {
            if (string.IsNullOrWhiteSpace(serverBaseUrl)) return null;

            try
            {
                using var client = new HttpClient();
                client.Timeout = TimeSpan.FromSeconds(20);
                var url = serverBaseUrl.TrimEnd('/') + "/api/rulepacks";
                var resp = await client.GetAsync(url);
                if (!resp.IsSuccessStatusCode) return null;
                return await resp.Content.ReadAsStringAsync();
            }
            catch
            {
                return null;
            }
        }
    }
}
