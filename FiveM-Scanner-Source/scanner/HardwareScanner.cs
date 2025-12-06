using System;
using System.Management;
using System.Collections.Generic;

namespace FiveMScanner
{
    public class HardwareInfo
    {
        public string Name { get; set; }
        public Dictionary<string, string> Details { get; set; }
    }

    public class HardwareScanner
    {
        public static List<HardwareInfo> GetHardwareInfo()
        {
            var hardwareInfo = new List<HardwareInfo>();

            try
            {
                // CPU Information
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (var cpu in searcher.Get())
                    {
                        try
                        {
                            var info = new HardwareInfo
                            {
                                Name = cpu["Name"]?.ToString() ?? "Unknown CPU",
                                Details = new Dictionary<string, string>
                                {
                                    { "Type", "CPU" },
                                    { "Manufacturer", cpu["Manufacturer"]?.ToString() ?? "N/A" },
                                    { "Cores", cpu["NumberOfCores"]?.ToString() ?? "N/A" },
                                    { "Threads", cpu["NumberOfLogicalProcessors"]?.ToString() ?? "N/A" },
                                    { "Clock Speed", $"{cpu["MaxClockSpeed"]} MHz" }
                                }
                            };
                            hardwareInfo.Add(info);
                        }
                        catch { }
                    }
                }

                // GPU Information
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController"))
                {
                    foreach (var gpu in searcher.Get())
                    {
                        try
                        {
                            var info = new HardwareInfo
                            {
                                Name = gpu["Name"]?.ToString() ?? "Unknown GPU",
                                Details = new Dictionary<string, string>
                                {
                                    { "Type", "GPU" },
                                    { "Processor", gpu["VideoProcessor"]?.ToString() ?? "N/A" },
                                    { "Memory", ConvertBytesToReadable(gpu["AdapterRAM"]?.ToString()) },
                                    { "Driver Version", gpu["DriverVersion"]?.ToString() ?? "N/A" }
                                }
                            };
                            hardwareInfo.Add(info);
                        }
                        catch { }
                    }
                }

                // RAM Information
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMemory"))
                {
                    foreach (var ram in searcher.Get())
                    {
                        try
                        {
                            var info = new HardwareInfo
                            {
                                Name = $"{ConvertBytesToReadable(ram["Capacity"]?.ToString())} {ram["Manufacturer"]?.ToString() ?? "Unknown"} RAM",
                                Details = new Dictionary<string, string>
                                {
                                    { "Type", "RAM" },
                                    { "Manufacturer", ram["Manufacturer"]?.ToString() ?? "N/A" },
                                    { "Capacity", ConvertBytesToReadable(ram["Capacity"]?.ToString()) },
                                    { "Speed", $"{ram["Speed"]} MHz" }
                                }
                            };
                            hardwareInfo.Add(info);
                        }
                        catch { }
                    }
                }

                // Network Adapters
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True"))
                {
                    foreach (var adapter in searcher.Get())
                    {
                        try
                        {
                            var info = new HardwareInfo
                            {
                                Name = adapter["Name"]?.ToString() ?? "Unknown Network Adapter",
                                Details = new Dictionary<string, string>
                                {
                                    { "Type", "Network Adapter" },
                                    { "Manufacturer", adapter["Manufacturer"]?.ToString() ?? "N/A" },
                                    { "MAC Address", adapter["MACAddress"]?.ToString() ?? "N/A" }
                                }
                            };
                            hardwareInfo.Add(info);
                        }
                        catch { }
                    }
                }

                // Storage Devices
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (var disk in searcher.Get())
                    {
                        try
                        {
                            var info = new HardwareInfo
                            {
                                Name = disk["Model"]?.ToString() ?? "Unknown Disk",
                                Details = new Dictionary<string, string>
                                {
                                    { "Type", "Storage" },
                                    { "Size", ConvertBytesToReadable(disk["Size"]?.ToString()) },
                                    { "Interface", disk["InterfaceType"]?.ToString() ?? "N/A" }
                                }
                            };
                            hardwareInfo.Add(info);
                        }
                        catch { }
                    }
                }

                // Motherboard Information
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard"))
                {
                    foreach (var board in searcher.Get())
                    {
                        try
                        {
                            var info = new HardwareInfo
                            {
                                Name = board["Product"]?.ToString() ?? "Unknown Motherboard",
                                Details = new Dictionary<string, string>
                                {
                                    { "Type", "Motherboard" },
                                    { "Manufacturer", board["Manufacturer"]?.ToString() ?? "N/A" },
                                    { "Serial Number", board["SerialNumber"]?.ToString() ?? "N/A" }
                                }
                            };
                            hardwareInfo.Add(info);
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error collecting hardware info: {ex.Message}");
            }

            return hardwareInfo;
        }

        private static string ConvertBytesToReadable(string bytes)
        {
            if (string.IsNullOrEmpty(bytes) || !long.TryParse(bytes, out long size))
                return "N/A";

            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double len = size;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }
    }
}