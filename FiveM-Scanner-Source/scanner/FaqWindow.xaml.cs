using System;
using System.Speech.Synthesis;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace FiveMScanner
{
    public partial class FaqWindow : Window
    {
        private Random _random = new Random();
        private SpeechSynthesizer? _synthesizer;
        private bool _isReading = false;

        private const string FaqText = @"</async> FREQUENTLY ASKED QUESTIONS

Q: What is </async> Scanner?
A: </async> is a real-time security and anti-cheat tool designed for game server communities like FiveM, DayZ, and Minecraft. It performs deep system analysis on a player's PC to detect cheats, injectors, and other malicious software, helping server owners maintain a fair and secure gaming environment.

Q: How does a scan work?
A: 1. An admin initiates a scan from the web dashboard, which generates a unique 6-digit PIN.
   2. The admin gives this PIN to the player who needs to be scanned.
   3. The player downloads and runs the scanner client, enters the PIN, and starts the scan.
   4. The scanner analyzes the system and securely sends the results back to the web dashboard.
   5. The admin can then review the detailed report to check for any threats.

Q: What data does the scanner collect?
A: The scanner collects data strictly for security analysis. This includes running processes, system information (OS, hardware ID), file signatures in common cheating locations, network activity, and recent command history. All collected data is handled confidentially as per our Terms of Service.

Q: Is the scanner safe for my computer?
A: Yes. The scanner is a ""read-only"" analysis tool. It does not modify, delete, or quarantine any files on your system. Its sole purpose is to gather information and generate a report. It is designed to be non-intrusive and safe to run.

Q: I lost my license or access, what should I do?
A: If you have lost access to your account or your license is not working, please open a support ticket in our official Discord server. You will need to provide proof of ownership (like a purchase receipt) for our support team to assist you with license recovery.

Q: The Terms of Service say not to scan myself. Why?
A: The tool is designed for authorized investigation of other players within a community. Scanning yourself is prohibited because it can be used by cheat developers to test their software against our scanner, which undermines its purpose. Violating this rule can result in a license termination.";

        public FaqWindow()
        {
            InitializeComponent();
            FaqTextBlock.Text = FaqText;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            CreateFloatingParticles();
        }

        private void CreateFloatingParticles()
        {
            // Create 20 floating </> particles
            for (int i = 0; i < 20; i++)
            {
                var particle = new TextBlock
                {
                    Text = "</>",
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = _random.Next(14, 28),
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(80, 80, 80))
                };

                Canvas.SetLeft(particle, _random.Next(0, 650));
                Canvas.SetTop(particle, _random.Next(0, 550));

                ParticlesCanvas.Children.Add(particle);
                AnimateParticle(particle);
            }
        }

        private void AnimateParticle(TextBlock particle)
        {
            var duration = TimeSpan.FromSeconds(_random.Next(20, 30));
            
            var animation = new System.Windows.Media.Animation.DoubleAnimation
            {
                From = Canvas.GetTop(particle),
                To = Canvas.GetTop(particle) - 120,
                Duration = duration,
                AutoReverse = true,
                RepeatBehavior = System.Windows.Media.Animation.RepeatBehavior.Forever
            };

            var opacityAnimation = new System.Windows.Media.Animation.DoubleAnimation
            {
                From = 0.2,
                To = 0.6,
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
            StopReading();
            Close();
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            StopReading();
            Close();
        }

        private void ReadAloud_Click(object sender, RoutedEventArgs e)
        {
            if (_isReading)
            {
                StopReading();
                ((Button)sender).Content = "🔊 READ ALOUD";
            }
            else
            {
                StartReading();
                ((Button)sender).Content = "⏸ STOP READING";
            }
        }

        private void StartReading()
        {
            try
            {
                _synthesizer = new SpeechSynthesizer();
                _synthesizer.SetOutputToDefaultAudioDevice();
                _synthesizer.Rate = 0;
                _synthesizer.Volume = 100;
                
                _synthesizer.SpeakCompleted += (s, e) =>
                {
                    _isReading = false;
                    Dispatcher.Invoke(() =>
                    {
                        var button = FindName("ReadAloudButton") as Button;
                        if (button != null)
                        {
                            button.Content = "🔊 READ ALOUD";
                        }
                    });
                };

                _isReading = true;
                _synthesizer.SpeakAsync(FaqText);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Text-to-speech is not available: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void StopReading()
        {
            if (_synthesizer != null && _isReading)
            {
                _synthesizer.SpeakAsyncCancelAll();
                _synthesizer.Dispose();
                _synthesizer = null;
                _isReading = false;
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            StopReading();
            base.OnClosed(e);
        }
    }
}
