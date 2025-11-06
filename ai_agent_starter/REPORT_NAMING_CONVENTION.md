# 📝 Report Naming Convention

## Overview

BYE BAC Agent menggunakan **descriptive naming convention** untuk report files agar mudah diidentifikasi dan dipahami, terutama untuk keperluan akademik dan presentasi.

---

## Format Baru (v1.1.0+)

### **JSON Report**
```
BAC_Security_Test_Report-YYYY-MM-DD_HH-MM-SS.json
```

### **Markdown Report**
```
BAC_Security_Test_Report-YYYY-MM-DD_HH-MM-SS.md
```

### **Contoh:**
```
BAC_Security_Test_Report-2025-11-04_16-30-45.json
BAC_Security_Test_Report-2025-11-04_16-30-45.md
```

---

## Keuntungan Format Baru

### ✅ **1. Self-Descriptive**
File name langsung menjelaskan isinya:
- `BAC_Security_Test_Report` → Jelas bahwa ini laporan security testing untuk Broken Access Control
- Tidak perlu buka file untuk tahu isinya

### ✅ **2. Academic-Friendly**
Cocok untuk:
- 📚 Thesis/skripsi appendix
- 📊 Presentasi dengan dosen
- 📁 Portfolio akademik
- 📋 Dokumentasi formal

### ✅ **3. Sortable by Date**
Format `YYYY-MM-DD_HH-MM-SS` memastikan:
- Chronological sorting di file explorer
- Easy to find latest report
- Clear time-based organization

### ✅ **4. Professional**
Mengikuti **industry best practices**:
- Descriptive naming
- ISO 8601 date format
- Underscore separation for readability

---

## Backward Compatibility

CLI tool **mendukung kedua format** (old & new):

### **Old Format** (v1.0.0)
```
report-20251104-163045.json
report-20251104-163045.md
```

### **Commands yang Support Both:**
```bash
# Show status - finds latest from both formats
byebac /status

# Open report - searches both formats
byebac /report

# Clean artifacts - deletes both formats
byebac /clean
```

---

## Migration Guide

### **Tidak Perlu Action!**

✅ Old reports tetap bisa diakses
✅ New reports akan otomatis gunakan format baru
✅ CLI commands work with both formats

### **Optional: Rename Old Reports**

Jika ingin consistency, bisa rename manual:

**Windows PowerShell:**
```powershell
cd ai_agent\runs
Get-ChildItem -Filter "report-*.json" | ForEach-Object {
    # Extract timestamp from old format (20251104-163045)
    if ($_.Name -match "report-(\d{8})-(\d{6})\.json") {
        $date = $matches[1]
        $time = $matches[2]
        
        # Convert to new format (2025-11-04_16-30-45)
        $year = $date.Substring(0,4)
        $month = $date.Substring(4,2)
        $day = $date.Substring(6,2)
        $hour = $time.Substring(0,2)
        $min = $time.Substring(2,2)
        $sec = $time.Substring(4,2)
        
        $newName = "BAC_Security_Test_Report-$year-$month-${day}_$hour-$min-$sec.json"
        Rename-Item $_.FullName -NewName $newName
    }
}
```

**Linux/Mac:**
```bash
cd ai_agent/runs
for file in report-*.json; do
    # Extract old format: report-20251104-163045.json
    timestamp=$(echo $file | sed 's/report-\([0-9]*\)-\([0-9]*\)\.json/\1-\2/')
    
    # Convert: 20251104-163045 → 2025-11-04_16-30-45
    year=${timestamp:0:4}
    month=${timestamp:4:2}
    day=${timestamp:6:2}
    hour=${timestamp:9:2}
    min=${timestamp:11:2}
    sec=${timestamp:13:2}
    
    new_name="BAC_Security_Test_Report-${year}-${month}-${day}_${hour}-${min}-${sec}.json"
    mv "$file" "$new_name"
done
```

---

## File Structure Example

```
ai_agent/runs/
├── BAC_Security_Test_Report-2025-11-04_16-30-45.json
├── BAC_Security_Test_Report-2025-11-04_16-30-45.md
├── BAC_Security_Test_Report-2025-11-03_14-15-20.json
├── BAC_Security_Test_Report-2025-11-03_14-15-20.md
├── BAC_Security_Test_Report-2025-11-02_10-05-30.json
├── BAC_Security_Test_Report-2025-11-02_10-05-30.md
├── artifacts/
│   ├── admin_hc/
│   │   ├── BASELINE/
│   │   ├── BOLA/
│   │   └── IDOR/
│   └── employee/
│       ├── BASELINE/
│       ├── BOLA/
│       └── IDOR/
└── logs/
```

---

## Naming Components Breakdown

### **BAC_Security_Test_Report**
- `BAC` → Broken Access Control
- `Security_Test` → Security testing context
- `Report` → Document type

### **2025-11-04_16-30-45**
- `2025` → Year
- `11` → Month (November)
- `04` → Day
- `16` → Hour (24-hour format)
- `30` → Minute
- `45` → Second

### **Extensions**
- `.json` → Machine-readable, structured data
- `.md` → Human-readable, formatted summary

---

## Benefits for Academic Use

### **📚 For Thesis/Skripsi:**
```
Appendix A: Security Test Reports
- BAC_Security_Test_Report-2025-11-04_16-30-45.md
  (96 tests, 88.9% accuracy, 6 vulnerabilities found)

Appendix B: Test Artifacts
- artifacts/admin_hc/BOLA/...
- artifacts/employee/IDOR/...
```

### **📊 For Presentations:**
```
"Seperti yang terlihat di BAC Security Test Report tertanggal 
4 November 2025 pukul 16:30, sistem berhasil mendeteksi 6 
vulnerabilities dengan accuracy 88.9%..."
```

### **📁 For Portfolio:**
Clear, professional naming → easy to explain to reviewers:
- "This is a Broken Access Control security test report..."
- vs. "This is report-20251104-163045.json..." ❌

---

## Code Changes

### **orchestrator.py** (Line 1563-1566)
```python
# OLD:
ts = time.strftime("%Y%m%d-%H%M%S")
report_path = os.path.join(self.runs_dir, f"report-{ts}.json")

# NEW:
timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
report_name = f"BAC_Security_Test_Report-{timestamp}.json"
report_path = os.path.join(self.runs_dir, report_name)
```

### **byebac.py** - Updated Functions:
- ✅ `show_status()` - finds both formats
- ✅ `open_report()` - searches both formats
- ✅ `clean_artifacts()` - deletes both formats

---

## FAQ

### **Q: Apakah old reports masih bisa dibaca?**
A: Ya! CLI tool support backward compatibility penuh.

### **Q: Perlu rename manual old reports?**
A: Tidak wajib. Tapi bisa untuk consistency (lihat Migration Guide).

### **Q: Format mana yang lebih baik untuk academic submission?**
A: **New format** (`BAC_Security_Test_Report-...`) karena self-explanatory.

### **Q: Apakah bisa customize prefix?**
A: Bisa! Edit `orchestrator.py` line 1565:
```python
report_name = f"YOUR_PREFIX-{timestamp}.json"
```

---

**Version:** 1.1.0  
**Date:** November 4, 2025  
**Status:** ✅ Implemented & Tested
