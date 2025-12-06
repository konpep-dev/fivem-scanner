using System;
using System.Windows;

namespace FiveMScanner
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            try
            {
                // Initialize anti-tamper protection
                AntiTamper.Initialize();

                // Verify assembly integrity
                if (!AntiTamper.VerifyIntegrity())
                {
                    MessageBox.Show("Application integrity check failed. The application may have been modified.", 
                                    "Security Error", 
                                    MessageBoxButton.OK, 
                                    MessageBoxImage.Error);
                    Shutdown();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Security initialization failed: {ex.Message}", 
                                "Security Error", 
                                MessageBoxButton.OK, 
                                MessageBoxImage.Error);
                Shutdown();
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            AntiTamper.StopMonitoring();
            base.OnExit(e);
        }
    }
}
