using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using Newtonsoft.Json;

namespace FiveMScanner
{
    public class ApiClient
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;
        private readonly string _pin;

        public ApiClient(string baseUrl, string pin)
        {
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromMinutes(5);
            _baseUrl = baseUrl.TrimEnd('/');
            _pin = pin;
        }

        public async Task<string> DownloadCustomRules()
        {
            try
            {
                var url = $"{_baseUrl}/api/custom-rules/download/{_pin}";
                Console.WriteLine($"Downloading custom rules from: {url}");
                
                var response = await _httpClient.GetAsync(url);
                
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"✅ Custom rules downloaded successfully!");
                    return json;
                }
                else
                {
                    Console.WriteLine($"⚠️  No custom rules found or error: {response.StatusCode}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Error downloading custom rules: {ex.Message}");
                return null;
            }
        }

        public async Task<bool> SubmitScanResults(object scanData)
        {
            try
            {
                var json = JsonConvert.SerializeObject(scanData, Formatting.Indented);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                
                var url = $"{_baseUrl}/api/submit/{_pin}";
                Console.WriteLine($"Submitting scan results to: {url}");
                Console.WriteLine($"Payload size: {json.Length} bytes");
                
                // Log findings count for debugging using reflection
                try
                {
                    var resultsProperty = scanData.GetType().GetProperty("results");
                    if (resultsProperty != null)
                    {
                        var resultsValue = resultsProperty.GetValue(scanData);
                        if (resultsValue is System.Collections.IList resultsList)
                        {
                            Console.WriteLine($"Findings count: {resultsList.Count}");
                        }
                    }
                }
                catch
                {
                    // Ignore reflection errors
                }
                
                var response = await _httpClient.PostAsync(url, content);
                
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"✅ Scan results submitted successfully!");
                    Console.WriteLine($"Response: {responseContent}");
                    return true;
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"❌ Failed to submit scan results. Status: {response.StatusCode}");
                    Console.WriteLine($"Error: {errorContent}");
                    Console.WriteLine($"Request URL: {url}");
                    Console.WriteLine($"Request payload preview (first 500 chars): {json.Substring(0, Math.Min(500, json.Length))}...");
                    return false;
                }
            }
            catch (HttpRequestException httpEx)
            {
                Console.WriteLine($"❌ HTTP Error submitting scan results: {httpEx.Message}");
                Console.WriteLine($"Inner exception: {httpEx.InnerException?.Message ?? "None"}");
                return false;
            }
            catch (TaskCanceledException timeoutEx)
            {
                Console.WriteLine($"❌ Timeout submitting scan results (exceeded 5 minutes): {timeoutEx.Message}");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error submitting scan results: {ex.Message}");
                Console.WriteLine($"Exception type: {ex.GetType().Name}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
                return false;
            }
        }
    }
}
