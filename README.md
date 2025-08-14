# SMTP Tester

A fast, modern SMTP **probe & test** tool for Windows using **MailKit**.  
Connect to an SMTP/MX server, negotiate TLS (STARTTLS/SSL), optionally authenticate, and send a test message with attachments. The app shows a live transcript and timings, and can save the full protocol log to a file.

> ![App screenshot](docs/screenshot.png)

---

## ✨ Features

- Material-styled WPF UI (clean cards, keyboard friendly)
- TLS modes: **None · STARTTLS · SSL-on-connect** (TLS 1.2/1.3)
- Certificate insight: **Subject, Issuer, SANs, validity, chain errors**
- **Probe** (no send) or **Send Test** (with body/attachments)
- **DSN** requests (Failure/Delay) when the server supports it
- Live **SMTP transcript** (client/server lines), optional **log file**
- **Cancel** long operations, **Auto-scroll** toggle, **Copy log**
- **Profiles**: save/load settings as simple `.ini` files
- Optional **EHLO domain override**

---

## 📦 Requirements

- Windows 10/11  
- .NET 8.0 (or 6.0+ with small tweaks)  
- Visual Studio 2022 (or `dotnet` CLI)

**NuGet packages**

- `MailKit` 4.13.0  
- `MaterialDesignThemes` 5.x  
- `MaterialDesignColors` 5.x

`SmtpTesterWpf.csproj` should include:

```xml
<PropertyGroup>
  <TargetFramework>net8.0-windows</TargetFramework>
  <UseWPF>true</UseWPF>
</PropertyGroup>
<ItemGroup>
  <PackageReference Include="MailKit" Version="4.13.0" />
  <PackageReference Include="MaterialDesignThemes" Version="5.1.0" />
  <PackageReference Include="MaterialDesignColors" Version="5.1.0" />
</ItemGroup>
```

---

## 🚀 Quick Start

```bash
git clone https://github.com/Antinon/SMTPTester.git
cd SMTPTester

# open in Visual Studio and Run (F5)
# or build/run with the CLI:
dotnet build
dotnet run
```
---

## 🧭 Using the App

### Connection
- **Host / Port** – target SMTP or MX host (e.g., `smtp.office365.com`, `25/587/465`)
- **TLS Mode** – `none`, `starttls`, or `ssl`
- **Timeout (ms)** – connect/read timeout
- **EHLO domain (optional)** – overrides the domain sent in EHLO/HELO
- **Skip certificate validation** – for testing only (logs issues but continues)
- **Log to file** – saves the raw transcript to `smtp-protocol.log` (or your path)

### Authentication
- Leave **Username/Password** empty to skip AUTH.  
- If provided, AUTH runs after EHLO/TLS.

### Message
- **From / To** (comma **or** semicolon separated)  
- **Subject / Body**  
- **Attachments** – add/remove files

### Actions
- **Probe** – connect, EHLO, (STARTTLS if selected), (AUTH if provided), then QUIT  
- **Send Test** – same as probe, plus send the message  
- **Test All TLS** – tries `none`, `starttls`, `ssl`  
- **Save / Load Profile** – store/load all fields to/from an `.ini`  
- **Clear Log** – clear transcript  
- **Cancel** – abort the current connect/auth/send  
- **Auto-scroll** – keep the log pinned to bottom  
- **Copy log** – copy transcript to clipboard

---

## 🔐 TLS Modes

| Mode       | What it does                                                                    | Typical Port |
|------------|----------------------------------------------------------------------------------|--------------|
| `none`     | Plain TCP (no TLS). Useful for banner checks or legacy relays.                  | 25           |
| `starttls` | Connect plain, then upgrade to TLS via **STARTTLS** (recommended).              | 25 / 587     |
| `ssl`      | TLS from the first byte (a.k.a. SMTPS).                                         | 465          |

The app enforces **TLS 1.2/1.3** and logs the negotiated protocol and cipher.

---

## 🧾 Profiles

Profiles are simple `.ini` files; easy to version and share.

```ini
host=smtp.office365.com
port=587
tls=starttls
username=sender@contoso.com
password=********
from=sender@contoso.com
to=recipient@contoso.com
subject=SMTP tester
body=This is a test message.
send=False
skipcert=False
timeoutms=20000
logtofile=True
logpath=smtp-protocol.log
attachments=C:\temp\readme.txt;C:\temp\image.png
```

> ⚠️ If you commit profiles, consider **omitting passwords** or using local-only files.

---

## 🧪 Transcript & Certificates

- `[CLIENT]` lines are what the app sends.  
- `[SERVER]` lines are replies from the server.  
- `[LOG]` lines contain timings and notes.  
- On TLS, the app prints certificate **Subject**, **Issuer**, **Validity**, **Thumbprint**, **SANs**, and any **chain errors**.  
- The **Skip certificate validation** toggle decides whether to continue despite errors.

---

## ☁️ Notes for Common Providers

- `*.mail.protection.outlook.com:25` is **inbound MX** (does **not** allow AUTH).  
  Use this for MX reachability/TLS tests.
- For **Microsoft 365 submission** (from a mailbox): `smtp.office365.com:587` + `starttls` + user/pass (or OAuth).
- Gmail may require an **app password** or OAuth; basic user/pass can be blocked.

---

## 🛠 Troubleshooting

- **“Cannot locate resource ‘…MaterialDesignTheme.Defaults.xaml’”**  
  In MaterialDesign v5 use `MaterialDesign3.Defaults.xaml` (or `MaterialDesign2.Defaults.xaml`) in `App.xaml`.

- **`PackIcon` not found**  
  Use `<materialDesign:PackIcon …/>` from the `themes` namespace.

- **Ambiguous `SmtpClient`**  
  Alias MailKit’s type:  
  `using MKSmtpClient = MailKit.Net.Smtp.SmtpClient;`

- **Auth fails on port 25**  
  Many MX servers don’t allow AUTH. Use submission endpoints (e.g., `smtp.office365.com:587`).

- **Stuck connect**  
  Click **Cancel**. Check firewalls/proxies and that the port is open.

---

## 🧭 Roadmap

- Dark/Light theme toggle  
- Snackbar toasts for success/error  
- Force specific AUTH mechanisms (LOGIN/PLAIN/NTLM)  
- SMTPUTF8 test (i18n addresses/body)  
- SIZE/large-attachment limit test  
- Throughput run (N messages, timings & percentiles)  
- Export **HTML report** (capabilities + timings + transcript)  
- OAuth2 helpers (O365/Gmail)  
- MVVM refactor + unit tests

---

## 🤝 Contributing

Issues and PRs are welcome!  
If you add a feature, please include a brief demo and update this README.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

## 🙏 Acknowledgements

- [MailKit](https://github.com/jstedfast/MailKit)  
- [MaterialDesignInXamlToolkit](https://github.com/MaterialDesignInXAML/MaterialDesignInXamlToolkit)
