using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Animation;

namespace FiveMScanner
{
    public partial class MainWindow : Window
    {
        private Scanner? _scanner;
        private string? _currentPin;

        private System.Windows.Threading.DispatcherTimer? _particleTimer;
        private Random _random = new Random();

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Create floating particles
            CreateFloatingParticles();
        }

        private void CreateFloatingParticles()
        {
            // Create 12 floating </> particles
            for (int i = 0; i < 12; i++)
            {
                var particle = new TextBlock
                {
                    Text = "</>",
                    FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                    FontSize = _random.Next(16, 24),
                    FontWeight = System.Windows.FontWeights.Bold,
                    Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(100, 100, 100)) // Πιο φωτεινό γκρι
                };

                // Random position
                Canvas.SetLeft(particle, _random.Next(0, 500));
                Canvas.SetTop(particle, _random.Next(0, 250));

                ParticlesCanvas.Children.Add(particle);

                // Animate particle
                AnimateParticle(particle);
            }
        }

        private void AnimateParticle(TextBlock particle)
        {
            var duration = TimeSpan.FromSeconds(_random.Next(15, 25));
            
            var animation = new System.Windows.Media.Animation.DoubleAnimation
            {
                From = Canvas.GetTop(particle),
                To = Canvas.GetTop(particle) - 100,
                Duration = duration,
                AutoReverse = true,
                RepeatBehavior = System.Windows.Media.Animation.RepeatBehavior.Forever
            };

            var opacityAnimation = new System.Windows.Media.Animation.DoubleAnimation
            {
                From = 0.3,
                To = 0.7,
                Duration = TimeSpan.FromSeconds(duration.TotalSeconds / 4),
                AutoReverse = true,
                RepeatBehavior = System.Windows.Media.Animation.RepeatBehavior.Forever
            };

            particle.BeginAnimation(Canvas.TopProperty, animation);
            particle.BeginAnimation(UIElement.OpacityProperty, opacityAnimation);
        }

        private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            try
            {
                DragMove();
            }
            catch { }
        }

        private void CloseButton_Click(object sender, MouseButtonEventArgs e)
        {
            Close();
        }

        private void InitiateScan_Click(object sender, RoutedEventArgs e)
        {
            // Show PIN entry panel
            InitiateScanButton.Visibility = Visibility.Collapsed;
            PinEntryPanel.Visibility = Visibility.Visible;
            PinTextBox.Focus();
        }

        private void CancelPin_Click(object sender, RoutedEventArgs e)
        {
            // Hide PIN entry panel
            PinEntryPanel.Visibility = Visibility.Collapsed;
            InitiateScanButton.Visibility = Visibility.Visible;
            PinTextBox.Clear();
            PinErrorText.Visibility = Visibility.Collapsed;
        }

        private void PinTextBox_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            // Only allow digits (0-9)
            Regex regex = new Regex("[^0-9]+");
            e.Handled = regex.IsMatch(e.Text);
        }

        private void PinTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            var pin = PinTextBox.Text.Trim();
            
            if (pin.Length == 6)
            {
                SubmitPinButton.IsEnabled = true;
                PinErrorText.Visibility = Visibility.Collapsed;
            }
            else
            {
                SubmitPinButton.IsEnabled = false;
            }
        }

        private async void SubmitPin_Click(object sender, RoutedEventArgs e)
        {
            var pin = PinTextBox.Text.Trim();

            if (pin.Length != 6)
            {
                PinErrorText.Text = "PIN must be exactly 6 digits.";
                PinErrorText.Visibility = Visibility.Visible;
                return;
            }

            _currentPin = pin;

            // Switch to scanning state
            InitialPanel.Visibility = Visibility.Collapsed;
            ScanningPanel.Visibility = Visibility.Visible;

            try
            {
                var serverUrl = "https://www.asyncac.cc";
                
                // Try to create scanner - this might fail if AntiDebug detects something
                try
                {
                    _scanner = new Scanner(serverUrl, pin);
                }
                catch (InvalidOperationException antiDebugEx)
                {
                    // AntiDebug detected something
                    ScanningPanel.Visibility = Visibility.Collapsed;
                    CompletePanel.Visibility = Visibility.Visible;
                    CompleteMessage.Text = $"Security Check Failed: {antiDebugEx.Message}";
                    return;
                }

                // Start scan with progress updates
                await StartScanWithProgress();

                // Switch to complete state
                ScanningPanel.Visibility = Visibility.Collapsed;
                CompletePanel.Visibility = Visibility.Visible;
                CompleteMessage.Text = "The forensic report has been successfully submitted. You may now close this application.";
            }
            catch (Exception ex)
            {
                // Show error in complete state
                ScanningPanel.Visibility = Visibility.Collapsed;
                CompletePanel.Visibility = Visibility.Visible;
                CompleteMessage.Text = $"The scan failed: {ex.Message}\n\nDetails: {ex.GetType().Name}";
                
                // Log to console for debugging
                System.Diagnostics.Debug.WriteLine($"SCAN ERROR: {ex}");
            }
        }

        private async Task StartScanWithProgress()
        {
            var progress = 0;
            var statusMessages = new[]
            {
                "INITIALIZING FORENSIC ENGINE...",
                "SCANNING SYSTEM FILES...",
                "ANALYZING PROCESSES...",
                "CHECKING NETWORK CONNECTIONS...",
                "SCANNING JOURNAL ENTRIES...",
                "ANALYZING MFT RECORDS...",
                "DETECTING CHEAT SIGNATURES...",
                "COMPILING FORENSIC REPORT..."
            };

            var scanTask = Task.Run(async () =>
            {
                if (_scanner != null)
                {
                    await _scanner.PerformFullScan();
                }
            });

            // Simulate progress updates up to 90%
            for (int i = 0; i < statusMessages.Length; i++)
            {
                var targetProgress = (i + 1) * 90 / statusMessages.Length;
                
                await Dispatcher.InvokeAsync(() =>
                {
                    StatusText.Text = statusMessages[i];
                });

                // Animate progress
                while (progress < targetProgress)
                {
                    progress++;
                    await Dispatcher.InvokeAsync(() =>
                    {
                        ProgressBar.Width = (progress / 100.0) * 400;
                        ProgressText.Text = $"{progress}%";
                    });
                    
                    // Intentional delay at 52% to make scan appear more thorough
                    if (progress == 52)
                    {
                        await Task.Delay(87000); // 1 minute 27 seconds pause at 52%
                    }
                    else
                    {
                        await Task.Delay(30);
                    }
                }

                // Wait a bit before next status
                await Task.Delay(500);
            }

            // Show "SUBMITTING TO SERVER..." while waiting for scan to complete
            await Dispatcher.InvokeAsync(() =>
            {
                StatusText.Text = "SUBMITTING TO SERVER...";
            });

            // Wait for actual scan to complete
            await scanTask;

            // Animate from 90% to 100%
            while (progress < 100)
            {
                progress++;
                await Dispatcher.InvokeAsync(() =>
                {
                    ProgressBar.Width = (progress / 100.0) * 400;
                    ProgressText.Text = $"{progress}%";
                });
                await Task.Delay(20);
            }

            // Show completion
            await Dispatcher.InvokeAsync(() =>
            {
                StatusText.Text = "SCAN COMPLETE";
            });

            await Task.Delay(800);
        }

        private void TosButton_Click(object sender, RoutedEventArgs e)
        {
            var tosWindow = new TosWindow();
            tosWindow.ShowDialog();
        }

        private void FaqButton_Click(object sender, RoutedEventArgs e)
        {
            var faqWindow = new FaqWindow();
            faqWindow.ShowDialog();
        }
    }
}
