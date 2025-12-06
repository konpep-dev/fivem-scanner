using System;
using System.Speech.Synthesis;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace FiveMScanner
{
    public partial class TosWindow : Window
    {
        private Random _random = new Random();
        private SpeechSynthesizer? _synthesizer;
        private bool _isReading = false;

        private const string TosText = @"</async> TERMS OF SERVICE
Effective Date: November 5, 2025

1. Your License to Use </async>
We grant you a personal, limited license to use our software for its intended security purpose. You cannot sell, share, or use it for commercial business.

2. What Data We Collect
This is a security tool. By running a scan, you agree that we can collect system data (like files, user info, and threat details). This report is securely sent to our team on Discord for review.

3. Our Responsibility (or Lack Thereof)
The software is provided ""as-is."" We are not responsible for any damage it might cause. We only offer refunds if the software itself is verifiably broken, not if an issue is caused by your computer or other software.

4. Rules of Conduct: What Not To Do
• Don't Reverse Engineer: Do not try to hack, decompile, or reverse-engineer our software.
• Don't Help Cheaters: If you are involved in making or using cheats/tools to bypass our scanner, your license will be terminated instantly. Using our software to help cheat developers will also result in a ban.
• Don't Scan Yourself: This tool is for authorized investigation of others. Scanning your own system is a violation of this agreement.
• Keep Reports Confidential: Scan results are private. Leaking or publicly sharing reports will result in an immediate license termination.
• No Scan Spamming: Do not scan the same user more than twice within a one-hour period.
• No Ban Evasion: Using alternate accounts to get around a ban will result in all your associated accounts being banned permanently.
• Severe Violations: If you break any of these rules, we reserve the right to ban you from our Discord server permanently, with no chance for appeal.

5. Account & License Issues
• Account Recovery: If you lose access to your account, contact us. You must provide valid proof of ownership (like a receipt) to recover your license.
• Bans & Refunds: If you break any of these rules, we can revoke your license immediately with no refund.

6. Getting Help & Final Terms
• Support: Have questions? Open a support ticket in our Discord. Please be respectful.
• Changes to Terms: We can change these terms at any time. By continuing to use the software, you agree to the updated terms.";

        public TosWindow()
        {
            InitializeComponent();
            TosTextBlock.Text = TosText;
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
                _synthesizer.Rate = 0; // Normal speed
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
                _synthesizer.SpeakAsync(TosText);
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
