using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using MaterialDesignThemes.Wpf;
using Microsoft.Win32;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using System.Text.Json;
// Alias MailKit's client to avoid System.Net.Mail collisions
using MKSmtpClient = MailKit.Net.Smtp.SmtpClient;

namespace SmtpTesterWpf
{
    public partial class MainWindow : Window
    {
        private readonly PaletteHelper _paletteHelper = new PaletteHelper();
        private readonly ISnackbarMessageQueue _snackbar = new SnackbarMessageQueue(TimeSpan.FromSeconds(3));

        // Simple options bag (could be turned into a ViewModel later)
        class Options
        {
            public string Host = "";
            public int Port = 587;
            public string TlsMode = "starttls"; // none|starttls|ssl
            public string Username = "";
            public string Password = "";
            public string From = "";
            public string To = "";
            public string Subject = "SMTP tester";
            public string Body = "This is a test message.";
            public bool SendMessage = false;
            public bool SkipCertVerify = false;
            public int TimeoutMs = 20000;
            public bool LogToFile = false;
            public string LogFilePath = "smtp-protocol.log";
            public List<string> Attachments = new List<string>();
            public Options Clone()
            {
                return new Options
                {
                    Host = Host,
                    Port = Port,
                    TlsMode = TlsMode,
                    Username = Username,
                    Password = Password,
                    From = From,
                    To = To,
                    Subject = Subject,
                    Body = Body,
                    SendMessage = SendMessage,
                    SkipCertVerify = SkipCertVerify,
                    TimeoutMs = TimeoutMs,
                    LogToFile = LogToFile,
                    LogFilePath = LogFilePath,
                    Attachments = new List<string>(Attachments)
                };
            }
        }

        private readonly Options _opt = new Options();

        // NEW: cancellation & autoscroll
        private CancellationTokenSource _cts;
        private bool _autoScroll = true; // toggle via a checkbox if you want

        public MainWindow()
        {

            InitializeComponent();
            MainSnackbar.MessageQueue = (SnackbarMessageQueue)_snackbar;

            // optional: start with Light or remember the last choice
            DarkToggle.IsChecked = false;   // Light by default
            ApplyBaseTheme(isDark: false);
            TlsBox.SelectedIndex = 1; // starttls

            _settings = LoadSettings();

            // Decide initial theme:
            // - "dark"/"light" => use saved preference
            // - "system" (default) => follow Windows setting
            bool initialIsDark = _settings.Theme?.ToLowerInvariant() switch
            {
                "dark" => true,
                "light" => false,
                _ => IsSystemDark()
            };

            // set the toggle without firing handlers
            _suppressThemeToggleEvent = true;
            DarkToggle.IsChecked = initialIsDark;
            _suppressThemeToggleEvent = false;

            // apply theme
            ApplyBaseTheme(initialIsDark);
            SetLogVisible(false);
            ShowLogToggle.IsChecked = false;
        }

        // === UI events ===
        private async void Probe_Click(object sender, RoutedEventArgs e) => await RunOnceAsync(forceSend: false);
        private async void Send_Click(object sender, RoutedEventArgs e) => await RunOnceAsync(forceSend: true);
        private void TestSnack_Click(object sender, RoutedEventArgs e)
        {
            SnackInfo("Hello from Snackbar!", "Undo", () => SnackInfo("Undone"));
        }

        private static MailboxAddress GetEnvelopeSender(MimeMessage msg)
        {
            // Prefer explicit Sender, else the single From mailbox
            if (msg.Sender is MailboxAddress s) return s;

            var from = msg.From?.Mailboxes?.FirstOrDefault();
            if (from == null)
                throw new ArgumentException("Message must have a Sender or a single From mailbox.", nameof(msg));
            return from;
        }

        private static IList<MailboxAddress> GetAllRecipients(MimeMessage msg)
        {
            var list = new List<MailboxAddress>();
            if (msg.To != null) foreach (var m in msg.To.Mailboxes) list.Add(m);
            if (msg.Cc != null) foreach (var m in msg.Cc.Mailboxes) list.Add(m);
            if (msg.Bcc != null) foreach (var m in msg.Bcc.Mailboxes) list.Add(m);
            return list;
        }

        // Persisted settings (extend later if you want)
        private sealed class AppSettings
        {
            // "system" | "dark" | "light"
            public string Theme { get; set; } = "system";
        }

        private AppSettings _settings;
        private bool _suppressThemeToggleEvent;  // prevents re-entrancy when we set the toggle programmatically
        private static string SettingsFilePath =>
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                 "SmtpTesterWpf", "settings.json");

        private AppSettings LoadSettings()
        {
            try
            {
                var path = SettingsFilePath;
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }
            }
            catch { /* ignore, fall back to defaults */ }
            return new AppSettings();
        }

        private void SaveSettings()
        {
            try
            {
                var dir = Path.GetDirectoryName(SettingsFilePath);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir!);
                var json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(SettingsFilePath, json);
            }
            catch { /* ignore write failures */ }
        }

        // Windows “AppsUseLightTheme” registry value: 0 = dark, 1 = light
        private static bool IsSystemDark()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
                var v = key?.GetValue("AppsUseLightTheme");
                if (v is int i) return i == 0;
                if (v is long l) return l == 0L;
            }
            catch { }
            return false;
        }


        private async void TestAll_Click(object sender, RoutedEventArgs e)
        {
            var modes = new[] { "none", "starttls", "ssl" };
            foreach (var m in modes)
            {
                AppendInfo($"\n=== Testing TLS mode: {m.ToUpperInvariant()} ===");
                var snapshot = ReadOptionsFromUI().Clone();
                snapshot.TlsMode = m;
                await RunOnceAsync(forceSend: false, snapshot);
            }
        }
        private void ApplyBaseTheme(bool isDark)
        {
            var theme = _paletteHelper.GetTheme();
            theme.SetBaseTheme(isDark ? BaseTheme.Dark : BaseTheme.Light);
            _paletteHelper.SetTheme(theme);
        }

        private void DarkToggle_Checked(object sender, RoutedEventArgs e)
        {
            if (_suppressThemeToggleEvent) return;
            ApplyBaseTheme(true);
            (_settings ??= new AppSettings()).Theme = "dark";
            SaveSettings();
        }

        private void DarkToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            if (_suppressThemeToggleEvent) return;
            ApplyBaseTheme(false);
            (_settings ??= new AppSettings()).Theme = "light";
            SaveSettings();
        }
        private void SetLogVisible(bool visible)
        {
            if (visible)
            {
                LogRow.Height = new GridLength(1, GridUnitType.Star);
                LogCard.Visibility = Visibility.Visible;
            }
            else
            {
                LogRow.Height = new GridLength(0);
                LogCard.Visibility = Visibility.Collapsed;
            }
        }

        private void ShowLogToggle_Checked(object sender, RoutedEventArgs e) => SetLogVisible(true);
        private void ShowLogToggle_Unchecked(object sender, RoutedEventArgs e) => SetLogVisible(false);


        private void SnackInfo(string message, string actionContent = null, Action action = null)
        {
            if (actionContent == null && action == null)
                Dispatcher.BeginInvoke(() => _snackbar.Enqueue(message));
            else
                Dispatcher.BeginInvoke(() => _snackbar.Enqueue(message, actionContent, action));
        }

        private void SnackError(string message)
            => Dispatcher.BeginInvoke(() => _snackbar.Enqueue("❌ " + message));

        // NEW: cancel button handler (add a button in XAML and hook Click=Cancel_Click)
        private void Cancel_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();

        // (optional) hook these to a checkbox if you add one
        private void AutoScroll_On(object sender, RoutedEventArgs e) => _autoScroll = true;
        private void AutoScroll_Off(object sender, RoutedEventArgs e) => _autoScroll = false;

        private void AddAttachment_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog { Multiselect = true, Title = "Select attachment(s)" };
            if (dlg.ShowDialog() == true)
            {
                foreach (var f in dlg.FileNames)
                    AttachList.Items.Add(f);
            }
        }

        private void RemoveAttachment_Click(object sender, RoutedEventArgs e)
        {
            var sel = AttachList.SelectedItem as string;
            if (sel != null) AttachList.Items.Remove(sel);
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e) => LogBox.Clear();

        // (optional) add a “Copy log” button and wire this
        private void CopyLog_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(LogBox.Text ?? "");
            AppendOk("Log copied to clipboard.");
        }

        private void SaveProfile_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog { Filter = "Profile (*.ini)|*.ini", FileName = "profile.ini" };
            if (dlg.ShowDialog() == true)
            {
                SaveProfile(dlg.FileName, ReadOptionsFromUI());
                AppendOk($"Saved profile: {dlg.FileName}");
                SnackInfo("Saved profile", "Open", () =>
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true }));
            }
        }

        private void LoadProfile_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog { Filter = "Profile (*.ini)|*.ini" };
            if (dlg.ShowDialog() == true)
            {
                var loaded = LoadProfile(dlg.FileName);
                if (loaded != null)
                {
                    WriteOptionsToUI(loaded);
                    AppendOk($"Loaded profile: {dlg.FileName}");
                    SnackInfo("Profile loaded");
                }
                else
                {
                    AppendWarn("Could not load profile.");
                }
            }
        }

        // === Core run ===
        private async Task<int> RunOnceAsync(bool forceSend, Options snapshot = null)
        {
            var opt = snapshot ?? ReadOptionsFromUI();

            if (string.IsNullOrWhiteSpace(opt.Host)) { AppendWarn("Host is required."); return 1; }
            if (opt.Port <= 0 || opt.Port > 65535) { AppendWarn("Port is invalid."); return 1; }
            if (string.IsNullOrWhiteSpace(opt.From)) { AppendWarn("'From' is required."); return 1; }
            if (string.IsNullOrWhiteSpace(opt.To)) { AppendWarn("'To' is required."); return 1; }

            AppendRule();
            AppendInfo("--- Settings ---");
            AppendInfo($"Host: {opt.Host}");
            AppendInfo($"Port: {opt.Port}");
            AppendInfo($"TLS : {opt.TlsMode}");
            AppendInfo($"User: {(string.IsNullOrWhiteSpace(opt.Username) ? "(none)" : opt.Username)}");
            AppendInfo($"From: {opt.From}");
            AppendInfo($"To  : {opt.To}");
            AppendInfo($"Timeout: {opt.TimeoutMs} ms");
            if (opt.SkipCertVerify) AppendWarn("Skipping certificate validation (testing only).");
            if (opt.LogToFile) AppendInfo("Protocol will also be logged to file: " + opt.LogFilePath);

            var total = Stopwatch.StartNew();

            FileStream fs = null;
            try
            {
                if (opt.LogToFile)
                    fs = new FileStream(opt.LogFilePath, FileMode.Create, FileAccess.Write, FileShare.Read);

                using (var proto = new MailKit.ProtocolLogger(fs == null ? (Stream)new ProtocolLogStream(AppendLog)
                                                                          : (Stream)new ProtocolLogStream(AppendLog, fs)))
                using (var client = new MKSmtpClient(proto))
                {
                    _cts?.Dispose();
                    _cts = new CancellationTokenSource();
                    var token = _cts.Token;

                    client.Timeout = opt.TimeoutMs;

                    // Stronger TLS
                    client.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;

                    // (Optional) EHLO override if you add x:Name="EhloBox" TextBox in XAML
                    var ehlo = TryGetEhloOverride();
                    if (!string.IsNullOrWhiteSpace(ehlo))
                        client.LocalDomain = ehlo;

                    // Always log certificate details; only approve if valid or SkipCertVerify checked
                    client.ServerCertificateValidationCallback = (s, cert, chain, errors) =>
                    {
                        try
                        {
                            var c2 = cert as X509Certificate2 ?? new X509Certificate2(cert);
                            AppendInfo("Certificate:");
                            AppendInfo("  Subject   : " + c2.Subject);
                            AppendInfo("  Issuer    : " + c2.Issuer);
                            AppendInfo("  NotBefore : " + c2.NotBefore.ToUniversalTime().ToString("u"));
                            AppendInfo("  NotAfter  : " + c2.NotAfter.ToUniversalTime().ToString("u"));
                            AppendInfo("  Thumbprint: " + c2.Thumbprint);

                            foreach (var ext in c2.Extensions)
                            {
                                if (ext.Oid != null && ext.Oid.Value == "2.5.29.17") // SANs
                                {
                                    var san = ext.Format(true).Replace("\r", "").Replace("\n", " ").Trim();
                                    if (!string.IsNullOrWhiteSpace(san))
                                        AppendInfo("  SANs     : " + san);
                                }
                            }

                            if (chain != null)
                            {
                                AppendInfo("  Chain errors: " + errors);
                                foreach (var st in chain.ChainStatus)
                                    AppendWarn("   - " + st.Status + " " + (st.StatusInformation ?? "").Trim());
                            }
                        }
                        catch { /* ignore */ }

                        return (errors == SslPolicyErrors.None) || opt.SkipCertVerify;
                    };

                    try
                    {
                        var secure = ToSecureSocketOptions(opt.TlsMode);

                        var swConnect = Stopwatch.StartNew();
                        await client.ConnectAsync(opt.Host, opt.Port, secure, token); // STARTTLS handled here if selected
                        swConnect.Stop();
                        AppendOk($"Connected in {swConnect.ElapsedMilliseconds} ms");
                        SnackInfo($"Connected to {opt.Host}:{opt.Port}");

                        PrintCapabilities(client);

                        if (client.IsSecure)
                        {
                            try { AppendInfo($"TLS active — Protocol: {client.SslProtocol}, Cipher: {client.SslCipherAlgorithm} ({client.SslCipherStrength} bits)"); }
                            catch { }
                        }

                        if (!string.IsNullOrWhiteSpace(opt.Username))
                        {
                            var swAuth = Stopwatch.StartNew();
                            await client.AuthenticateAsync(opt.Username, opt.Password ?? "", token);
                            swAuth.Stop();
                            AppendOk($"Authenticated as '{opt.Username}' in {swAuth.ElapsedMilliseconds} ms");
                            SnackInfo($"Authenticated as {opt.Username}");
                        }
                        else
                        {
                            AppendWarn("No credentials; skipping AUTH.");
                        }

                        var doSend = forceSend || opt.SendMessage;
                        if (doSend)
                        {
                            var msg = BuildMessage(opt);
                            var swSend = Stopwatch.StartNew();

                            await client.SendAsync(msg, token);

                            swSend.Stop();
                            AppendOk($"Message accepted by server in {swSend.ElapsedMilliseconds} ms");
                            AppendInfo("Message-Id: " + msg.MessageId);
                            SnackInfo("Message accepted by server");

                        }
                        else
                        {
                            AppendInfo("Probe only (not sending).");
                        }

                        var swQuit = Stopwatch.StartNew();
                        await client.DisconnectAsync(true, token);
                        swQuit.Stop();

                        total.Stop();
                        AppendInfo($"Disconnected cleanly in {swQuit.ElapsedMilliseconds} ms");
                        AppendInfo($"Total elapsed: {total.ElapsedMilliseconds} ms");
                        return 0;
                    }
                    catch (OperationCanceledException)
                    {
                        AppendWarn("Operation canceled.");
                        try { if (client.IsConnected) await client.DisconnectAsync(true); } catch { }
                        return 2;
                    }
                    catch (MailKit.Security.AuthenticationException ex) { return Fail("Authentication failed: " + ex.Message); }
                    catch (ServiceNotAuthenticatedException ex) { return Fail("Server requires authentication: " + ex.Message); }
                    catch (ServiceNotConnectedException ex) { return Fail("Not connected: " + ex.Message); }
                    catch (TimeoutException ex) { return Fail("Timed out: " + ex.Message); }
                    catch (Exception ex) { return Fail(ex.GetType().Name + ": " + ex.Message); }
                }
            }
            finally
            {
                fs?.Dispose();
            }
        }

        private void PrintCapabilities(MKSmtpClient client)
        {
            AppendInfo("Capabilities:");
            // Works with both old/new API shapes (0 == unknown/unspecified on many relays)
            AppendInfo("  Size Limit : " + (client.MaxSize > 0 ? client.MaxSize.ToString() : "unknown"));
            AppendInfo("  8BITMIME  : " + client.Capabilities.HasFlag(SmtpCapabilities.EightBitMime));
            AppendInfo("  STARTTLS  : " + client.Capabilities.HasFlag(SmtpCapabilities.StartTLS));
            AppendInfo("  DSN       : " + client.Capabilities.HasFlag(SmtpCapabilities.Dsn));
            AppendInfo("  PIPELINING: " + client.Capabilities.HasFlag(SmtpCapabilities.Pipelining));
            AppendInfo("  AUTH      : " + string.Join(",", client.AuthenticationMechanisms));
        }

        private MimeMessage BuildMessage(Options opt)
        {
            var msg = new MimeMessage();
            msg.From.Add(MailboxAddress.Parse(opt.From));
            foreach (var r in SplitRecipients(opt.To))
                msg.To.Add(MailboxAddress.Parse(r));
            msg.Subject = opt.Subject;

            var builder = new BodyBuilder { TextBody = opt.Body };
            foreach (var path in opt.Attachments)
                try { builder.Attachments.Add(path); } catch { }
            msg.Body = builder.ToMessageBody();
            return msg;
        }

        private static IEnumerable<string> SplitRecipients(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) yield break;
            var parts = s.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var p in parts)
            {
                var t = p.Trim();
                if (t.Length > 0) yield return t;
            }
        }

        private SecureSocketOptions ToSecureSocketOptions(string mode)
        {
            var m = (mode ?? "").Trim().ToLowerInvariant();
            if (m == "none") return SecureSocketOptions.None;
            if (m == "ssl") return SecureSocketOptions.SslOnConnect;
            return SecureSocketOptions.StartTls;
        }

        private Options ReadOptionsFromUI()
        {
            _opt.Host = HostBox.Text?.Trim() ?? "";
            int port; _opt.Port = int.TryParse(PortBox.Text, out port) ? port : 587;
            _opt.TlsMode = ((System.Windows.Controls.ComboBoxItem)TlsBox.SelectedItem).Content.ToString();
            _opt.Username = UserBox.Text?.Trim() ?? "";
            _opt.Password = PassBox.Password ?? "";
            _opt.From = FromBox.Text?.Trim() ?? "";
            _opt.To = ToBox.Text?.Trim() ?? "";
            _opt.Subject = SubjectBox.Text ?? "SMTP tester";
            _opt.Body = BodyBox.Text ?? "This is a test message.";
            int t; _opt.TimeoutMs = int.TryParse(TimeoutBox.Text, out t) ? t : 20000;
            _opt.SkipCertVerify = SkipCertCheck.IsChecked == true;
            _opt.SendMessage = SendByDefault.IsChecked == true;
            _opt.LogToFile = LogToFileCheck.IsChecked == true;
            _opt.LogFilePath = LogPathBox.Text?.Trim() ?? "smtp-protocol.log";
            _opt.Attachments.Clear();
            foreach (var item in AttachList.Items)
                _opt.Attachments.Add(item as string);
            return _opt;
        }

        private void WriteOptionsToUI(Options o)
        {
            HostBox.Text = o.Host;
            PortBox.Text = o.Port.ToString();
            foreach (var item in TlsBox.Items)
                if (((System.Windows.Controls.ComboBoxItem)item).Content.ToString().Equals(o.TlsMode, StringComparison.OrdinalIgnoreCase))
                    TlsBox.SelectedItem = item;
            UserBox.Text = o.Username;
            PassBox.Password = o.Password;
            FromBox.Text = o.From;
            ToBox.Text = o.To;
            SubjectBox.Text = o.Subject;
            BodyBox.Text = o.Body;
            TimeoutBox.Text = o.TimeoutMs.ToString();
            SkipCertCheck.IsChecked = o.SkipCertVerify;
            SendByDefault.IsChecked = o.SendMessage;
            LogToFileCheck.IsChecked = o.LogToFile;
            LogPathBox.Text = o.LogFilePath;
            AttachList.Items.Clear();
            foreach (var a in o.Attachments) AttachList.Items.Add(a);
        }

        // === Profiles (simple INI) ===
        private void SaveProfile(string path, Options o)
        {
            var sb = new StringBuilder();
            sb.AppendLine("host=" + o.Host);
            sb.AppendLine("port=" + o.Port);
            sb.AppendLine("tls=" + o.TlsMode);
            sb.AppendLine("username=" + o.Username);
            sb.AppendLine("password=" + o.Password); // local dev convenience; secure as needed
            sb.AppendLine("from=" + o.From);
            sb.AppendLine("to=" + o.To);
            sb.AppendLine("subject=" + o.Subject.Replace(Environment.NewLine, "\\n"));
            sb.AppendLine("body=" + o.Body.Replace(Environment.NewLine, "\\n"));
            sb.AppendLine("send=" + o.SendMessage);
            sb.AppendLine("skipcert=" + o.SkipCertVerify);
            sb.AppendLine("timeoutms=" + o.TimeoutMs);
            sb.AppendLine("logtofile=" + o.LogToFile);
            sb.AppendLine("logpath=" + o.LogFilePath);
            sb.AppendLine("attachments=" + string.Join(";", o.Attachments.ToArray()));
            File.WriteAllText(path, sb.ToString());
        }

        private Options LoadProfile(string path)
        {
            var o = new Options();
            var lines = File.ReadAllLines(path);
            foreach (var raw in lines)
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                var idx = line.IndexOf('=');
                if (idx <= 0) continue;
                var key = line.Substring(0, idx).Trim().ToLowerInvariant();
                var val = line.Substring(idx + 1);

                switch (key)
                {
                    case "host": o.Host = val; break;
                    case "port": int p; if (int.TryParse(val, out p)) o.Port = p; break;
                    case "tls": o.TlsMode = val; break;
                    case "username": o.Username = val; break;
                    case "password": o.Password = val; break;
                    case "from": o.From = val; break;
                    case "to": o.To = val; break;
                    case "subject": o.Subject = val.Replace("\\n", Environment.NewLine); break;
                    case "body": o.Body = val.Replace("\\n", Environment.NewLine); break;
                    case "send": bool b; if (bool.TryParse(val, out b)) o.SendMessage = b; break;
                    case "skipcert": if (bool.TryParse(val, out b)) o.SkipCertVerify = b; break;
                    case "timeoutms": int t; if (int.TryParse(val, out t)) o.TimeoutMs = t; break;
                    case "logtofile": bool lf; if (bool.TryParse(val, out lf)) o.LogToFile = lf; break;
                    case "logpath": o.LogFilePath = val; break;
                    case "attachments":
                        o.Attachments = new List<string>((val ?? "").Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries));
                        break;
                }
            }
            return o;
        }

        // === Logging helpers ===
        private void AppendRule() => AppendLog(new string('-', 60));
        private void AppendOk(string message) => AppendLog("[OK] " + message);
        private void AppendWarn(string message) => AppendLog("[WARN] " + message);
        private void AppendInfo(string message) => AppendLog(message);

        private void AppendLog(string line)
        {
            // ensure UI thread
            Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
            {
                LogBox.AppendText(line + Environment.NewLine);
                if (_autoScroll) LogBox.ScrollToEnd();

                // crude log length control (avoid unbounded growth)
                if (LogBox.LineCount > 8000)
                    LogBox.Text = LogBox.Text.Substring(Math.Max(0, LogBox.Text.Length - 20000));
            }));
        }

        private int Fail(string message)
        {
            AppendLog("[ERROR] " + message);
            SnackError(message);
            return 1;
        }

        // Try to read an optional EHLO domain from a TextBox named "EhloBox" (if you add one)
        private string TryGetEhloOverride()
        {
            try
            {
                var o = this.FindName("EhloBox") as System.Windows.Controls.TextBox;
                return o == null ? null : (o.Text?.Trim() ?? null);
            }
            catch { return null; }
        }
    }

    /// <summary>
    /// Stream for MailKit ProtocolLogger: mirrors SMTP dialogue to UI (and optional file).
    /// </summary>
    sealed class ProtocolLogStream : Stream
    {
        private readonly Action<string> _sink;
        private readonly Stream _file;
        private readonly object _lock = new object();

        public ProtocolLogStream(Action<string> sink, Stream file = null)
        {
            _sink = sink ?? (_ => { });
            _file = file;
        }

        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { _file?.Flush(); }
        public override int Read(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _file?.Write(buffer, offset, count);

            var s = Encoding.UTF8.GetString(buffer, offset, count).Replace("\r", "");
            lock (_lock)
            {
                var lines = s.Split('\n');
                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    if (line.Length == 0) continue;

                    if (line.StartsWith("C:"))
                        _sink("[CLIENT] " + line.Substring(2).TrimStart());
                    else if (line.StartsWith("S:"))
                        _sink("[SERVER] " + line.Substring(2).TrimStart());
                    else
                        _sink("[LOG] " + line);
                }
            }
        }
    }
}
