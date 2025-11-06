# BYE BAC CLI - Installation Guide

## 🎯 Goal

Run `byebac /help` from **any directory** instead of `python byebac.py /help`

---

## ⚡ Quick Setup (Recommended)

### Option A: Load for Current Session Only

**Fastest way** - Just run this once in PowerShell:

```powershell
cd ai_agent_starter
. .\QUICK_SETUP.ps1
```

✅ Now you can use: `byebac /help`, `byebac /status`, etc.

❌ Drawback: Only works in current PowerShell window. Closes when you exit.

---

### Option B: Permanent Setup (Add to PATH)

**Best for daily use** - Run setup script once:

```powershell
cd ai_agent_starter
.\SETUP_CLI.ps1
```

Follow the prompts to:

1. ✅ Add to User PATH (works in cmd, PowerShell, any terminal)
2. ✅ Add PowerShell alias (works in PowerShell only)
3. ✅ Add to PowerShell profile (loads automatically)

After setup, **restart your terminal**, then:

```powershell
byebac /help          # Works from anywhere!
byebac /check
byebac /runagent
```

---

## 🔧 Manual Setup Options

### For PowerShell (Current Session)

```powershell
Set-Alias byebac "C:\Users\carol\ai_agent_starter\ai_agent_starter\byebac.ps1"
```

### For PowerShell (Permanent)

Add this to your PowerShell profile (`notepad $PROFILE`):

```powershell
Set-Alias byebac "C:\Users\carol\ai_agent_starter\ai_agent_starter\byebac.ps1"
```

Then reload: `. $PROFILE`

### For CMD (Windows Command Prompt)

Add `C:\Users\carol\ai_agent_starter\ai_agent_starter` to your User PATH:

1. Windows Key → Search "Environment Variables"
2. Edit User PATH
3. Add: `C:\Users\carol\ai_agent_starter\ai_agent_starter`
4. Restart terminal

Then use: `byebac.bat /help`

---

## 🐧 Linux/Mac Setup

Make the script executable:

```bash
chmod +x ai_agent_starter/byebac.sh
```

Add alias to `~/.bashrc` or `~/.zshrc`:

```bash
alias byebac='/path/to/ai_agent_starter/byebac.sh'
```

Reload: `source ~/.bashrc`

---

## ✅ Verify Setup

After setup, test from **any directory**:

```powershell
byebac /help
```

Should show the BYE BAC banner and menu! 🎉

---

## 🆘 Troubleshooting

### "byebac is not recognized"

- **If you used PATH**: Restart terminal after setup
- **If you used alias**: Run `. $PROFILE` or `. .\QUICK_SETUP.ps1` first
- **Still not working**: Use full path: `python C:\Users\carol\ai_agent_starter\ai_agent_starter\byebac.py /help`

### PowerShell execution policy error

Run this first:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Python not found

Make sure Python is installed and in PATH:

```powershell
python --version
```

---

## 📚 Available Commands

Once setup is complete, you can use:

```
byebac /help          - Show all commands
byebac /information   - Interactive guide (with back button!)
byebac /check         - Verify setup
byebac /runagent      - Run security tests
byebac /status        - View latest results
byebac /report        - Open test reports
byebac /config        - Show configuration
byebac /specification - Technical details
```

---

**Made with ❤️ for Secure APIs**
