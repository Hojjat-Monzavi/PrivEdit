// privedit_gui.cpp -- Windows Notepad-style GUI for PrivEdit.
//
// Crypto: Argon2id + XChaCha20-Poly1305 (PENC v3) via libsodium.
//
// Preserved features:
//   * Self-contained .exe notes (the executable IS the document)
//   * Cover / decoy on-screen text, REVEAL toggle (Ctrl+R)
//   * COVER-mode blind typing: keystrokes go to the hidden real note,
//     the visible decoy streams out one character per keystroke
//   * zlib payload compression
//   * Password retry (up to 3 attempts)
//   * Night theme
//
// Target: Windows 7 SP1 through Windows 11, x86_64, static MinGW.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0601
#define WINVER       0x0601

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <richedit.h>
#include <shellapi.h>
#include <shlwapi.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>

#include "privedit_crypto.h"
#include "resource.h"

using priv::crypto::Bytes;
using priv::crypto::DerivedKeys;

// ===========================================================================
//  Theme
// ===========================================================================
enum class Theme { Light, Dark };

namespace colors {
    constexpr COLORREF LightBg    = RGB(255, 255, 255);
    constexpr COLORREF LightFg    = RGB(  0,   0,   0);
    constexpr COLORREF LightCtlBg = RGB(255, 255, 255);
    constexpr COLORREF LightCtlFg = RGB(  0,   0,   0);

    constexpr COLORREF DarkBg     = RGB( 30,  30,  32);
    constexpr COLORREF DarkFg     = RGB(212, 212, 216);
    constexpr COLORREF DarkCtlBg  = RGB( 45,  45,  48);
    constexpr COLORREF DarkCtlFg  = RGB(230, 230, 235);
    constexpr COLORREF DarkBarBg  = RGB( 37,  37,  38);
} // namespace colors

// ===========================================================================
//  UTF-8 <-> UTF-16 helpers
// ===========================================================================
static std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out((size_t)n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], n);
    return out;
}
static std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        &out[0], n, nullptr, nullptr);
    return out;
}
static std::wstring lfToCrW(const std::wstring& s) {
    std::wstring w = s;
    for (auto& c : w) if (c == L'\n') c = L'\r';
    return w;
}
static std::wstring crToLfW(const std::wstring& w) {
    std::wstring out;
    out.reserve(w.size());
    for (size_t i = 0; i < w.size(); ++i) {
        wchar_t c = w[i];
        if (c == L'\r') {
            out += L'\n';
            if (i + 1 < w.size() && w[i + 1] == L'\n') ++i;
        } else out += c;
    }
    return out;
}

// ===========================================================================
//  Path / file helpers
// ===========================================================================
static std::wstring expandTildeW(const std::wstring& p) {
    if (p.empty() || p[0] != L'~') return p;
    wchar_t home[MAX_PATH] = {0};
    if (p.size() == 1 || p[1] == L'/' || p[1] == L'\\') {
        if (GetEnvironmentVariableW(L"USERPROFILE", home, MAX_PATH) ||
            GetEnvironmentVariableW(L"HOME", home, MAX_PATH)) {
            return (p.size() == 1) ? std::wstring(home)
                                   : std::wstring(home) + p.substr(1);
        }
    }
    return p;
}
static std::wstring canonicalPath(const std::wstring& p) {
    wchar_t buf[MAX_PATH * 2] = {0};
    DWORD n = GetFullPathNameW(p.c_str(), _countof(buf), buf, nullptr);
    if (n == 0 || n >= _countof(buf)) return p;
    return std::wstring(buf, (size_t)n);
}
static bool readFileBytes(const std::wstring& path, std::vector<uint8_t>& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0) { CloseHandle(h); return false; }
    out.resize((size_t)sz.QuadPart);
    size_t off = 0;
    while (off < out.size()) {
        DWORD want = (DWORD)std::min<size_t>(out.size() - off, (size_t)1 << 30);
        DWORD got = 0;
        if (!ReadFile(h, out.data() + off, want, &got, nullptr)) {
            CloseHandle(h); return false;
        }
        if (got == 0) break;
        off += got;
    }
    CloseHandle(h);
    return off == out.size();
}
static bool writeFileAtomic(const std::wstring& path,
                            const std::vector<uint8_t>& data) {
    std::wstring tmp = path + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    size_t off = 0;
    while (off < data.size()) {
        DWORD want = (DWORD)std::min<size_t>(data.size() - off, (size_t)1 << 30);
        DWORD wrote = 0;
        if (!WriteFile(h, data.data() + off, want, &wrote, nullptr)) {
            CloseHandle(h); DeleteFileW(tmp.c_str()); return false;
        }
        off += wrote;
    }
    FlushFileBuffers(h);
    CloseHandle(h);
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    return true;
}
static std::wstring getModulePathW() {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        DWORD n = GetModuleFileNameW(nullptr, &buf[0], (DWORD)buf.size());
        if (n == 0) return {};
        if (n < buf.size()) { buf.resize(n); return buf; }
        buf.resize(buf.size() * 2);
    }
}

// ===========================================================================
//  Application state
// ===========================================================================
struct App {
    HINSTANCE hInst      = nullptr;
    HWND      hwndMain   = nullptr;
    HWND      hwndEdit   = nullptr;
    HWND      hwndStatus = nullptr;
    HMENU     hMenu      = nullptr;
    HFONT     hFont      = nullptr;
    HACCEL    hAccel     = nullptr;
    HMODULE   hRich      = nullptr;
    int       dpi        = 96;

    Theme     theme = Theme::Light;

    std::wstring filepath;
    bool         isNote    = false;
    std::string  password;
    DerivedKeys  keys;

    std::wstring realText;
    std::wstring coverText;
    size_t       realCursor  = 0;
    size_t       coverCursor = 0;

    std::wstring selfPath;
    std::vector<uint8_t> selfData;
    size_t   selfMO = 0;
    uint64_t selfPL = 0;
    bool     selfIsNote = false;
    std::vector<uint8_t> stub;

    bool revealed  = true;
    bool wordWrap  = false;
    bool statusBar = true;

    bool         swapHelperSpawned = false;
    std::wstring lastSearch;

    bool editModified() const {
        return SendMessageW(hwndEdit, EM_GETMODIFY, 0, 0) != 0;
    }
    void setEditModified(bool m) const {
        SendMessageW(hwndEdit, EM_SETMODIFY, m ? TRUE : FALSE, 0);
    }
    void getSel(DWORD& start, DWORD& end) const {
        CHARRANGE cr{};
        SendMessageW(hwndEdit, EM_EXGETSEL, 0, (LPARAM)&cr);
        start = (DWORD)cr.cpMin;
        end   = (DWORD)cr.cpMax;
    }
    void wipeSecrets() {
        priv::crypto::cleanse(password);
        keys.wipe();
    }
};

static App g;

// ---------------------------------------------------------------------------
//  Forward declarations
// ---------------------------------------------------------------------------
static void updateTitle();
static void updateStatus();
static void setEditTextFromState();
static void setRevealed(bool on);
static void applyEditorTheme();
static void applyTheme();
static void refreshCoverDisplay();

typedef HRESULT (WINAPI *PFN_SetWindowTheme)(HWND, LPCWSTR, LPCWSTR);
static PFN_SetWindowTheme pSetWindowTheme = nullptr;

static void safeSetWindowTheme(HWND h, LPCWSTR sub, LPCWSTR sub2) {
    if (pSetWindowTheme) pSetWindowTheme(h, sub, sub2);
}

// ===========================================================================
//  Theme brushes
// ===========================================================================
static HBRUSH g_brDarkBg  = nullptr;
static HBRUSH g_brDarkCtl = nullptr;

static HBRUSH brushDarkBg() {
    if (!g_brDarkBg) g_brDarkBg = CreateSolidBrush(colors::DarkBg);
    return g_brDarkBg;
}
static HBRUSH brushDarkCtl() {
    if (!g_brDarkCtl) g_brDarkCtl = CreateSolidBrush(colors::DarkCtlBg);
    return g_brDarkCtl;
}

static INT_PTR handleDialogCtlColor(UINT msg, WPARAM wp) {
    if (g.theme != Theme::Dark) return 0;
    HDC hdc = (HDC)wp;
    switch (msg) {
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
        SetTextColor(hdc, colors::DarkFg);
        SetBkColor  (hdc, colors::DarkBg);
        return (INT_PTR)brushDarkBg();
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
        SetTextColor(hdc, colors::DarkCtlFg);
        SetBkColor  (hdc, colors::DarkCtlBg);
        return (INT_PTR)brushDarkCtl();
    }
    return 0;
}

// ===========================================================================
//  Font
// ===========================================================================
static HFONT makeEditorFont(int dpi, const std::wstring& face, int pt) {
    int height = -MulDiv(pt, dpi, 72);
    return CreateFontW(height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN,
                       face.empty() ? L"Consolas" : face.c_str());
}

// ===========================================================================
//  Editor theme
// ===========================================================================
static void applyEditorTheme() {
    if (!g.hwndEdit) return;

    BOOL wasModified = (BOOL)SendMessageW(g.hwndEdit, EM_GETMODIFY, 0, 0);

    COLORREF bg = (g.theme == Theme::Dark) ? colors::DarkBg : colors::LightBg;
    COLORREF fg = (g.theme == Theme::Dark) ? colors::DarkFg : colors::LightFg;

    SendMessageW(g.hwndEdit, EM_SETBKGNDCOLOR, 0, (LPARAM)bg);

    CHARFORMAT2W cf = {};
    cf.cbSize      = sizeof(cf);
    cf.dwMask      = CFM_COLOR;
    cf.crTextColor = fg;

    SendMessageW(g.hwndEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

    CHARRANGE saved{};
    SendMessageW(g.hwndEdit, EM_EXGETSEL, 0, (LPARAM)&saved);
    CHARRANGE atZero{0, 0};
    SendMessageW(g.hwndEdit, EM_EXSETSEL, 0, (LPARAM)&atZero);
    SendMessageW(g.hwndEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(g.hwndEdit, EM_EXSETSEL, 0, (LPARAM)&saved);

    safeSetWindowTheme(g.hwndEdit,
        (g.theme == Theme::Dark) ? L"DarkMode_Explorer" : L"Explorer",
        nullptr);

    SendMessageW(g.hwndEdit, EM_SETMODIFY, wasModified, 0);
    InvalidateRect(g.hwndEdit, nullptr, TRUE);
}

static void applyTheme() {
    applyEditorTheme();

    if (g.hwndStatus) {
        if (g.theme == Theme::Dark) {
            safeSetWindowTheme(g.hwndStatus, L"DarkMode_Explorer", nullptr);
            SendMessageW(g.hwndStatus, SB_SETBKCOLOR, 0,
                         (LPARAM)colors::DarkBarBg);
        } else {
            safeSetWindowTheme(g.hwndStatus, L"Explorer", nullptr);
            SendMessageW(g.hwndStatus, SB_SETBKCOLOR, 0, (LPARAM)CLR_DEFAULT);
        }
        InvalidateRect(g.hwndStatus, nullptr, TRUE);
    }

    CheckMenuItem(g.hMenu, ID_VIEW_NIGHTTHEME,
        MF_BYCOMMAND | (g.theme == Theme::Dark ? MF_CHECKED : MF_UNCHECKED));

    updateStatus();
}

// ===========================================================================
//  Title / status
// ===========================================================================
static void updateTitle() {
    std::wstring name = g.filepath.empty() ? L"Untitled" : g.filepath;
    const wchar_t* mode = g.revealed ? L"" : L" [COVER]";
    std::wstring t = L"PrivEdit - ";
    t += name;
    t += mode;
    if (g.editModified()) t += L" *";
    SetWindowTextW(g.hwndMain, t.c_str());
}

static void updateStatus() {
    if (!g.statusBar || !g.hwndStatus || !g.hwndEdit) return;
    DWORD selStart = 0, selEnd = 0;
    g.getSel(selStart, selEnd);
    int caret = (int)selStart;
    int line  = (int)SendMessageW(g.hwndEdit, EM_LINEFROMCHAR, caret, 0);
    int lineStart = (int)SendMessageW(g.hwndEdit, EM_LINEINDEX, line, 0);
    int col = caret - lineStart;
    wchar_t buf[256];
    if (g.revealed) {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                     L"  Ln %d, Col %d    REVEAL    %s",
                     line + 1, col + 1,
                     g.isNote ? L"self-note" : L"file");
    } else {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                     L"  COVER (keystrokes go to hidden note)    "
                     L"real: %zu chars    decoy: %zu/%zu",
                     g.realText.size(),
                     std::min(g.coverCursor, g.coverText.size()),
                     g.coverText.size());
    }
    SendMessageW(g.hwndStatus, SB_SETTEXTW, 0, (LPARAM)buf);
}

// ===========================================================================
//  Edit <-> state
// ===========================================================================
static void pullTextFromEdit() {
    int n = GetWindowTextLengthW(g.hwndEdit);
    std::wstring w;
    w.resize((size_t)n + 1);
    if (n > 0) GetWindowTextW(g.hwndEdit, &w[0], n + 1);
    w.resize((size_t)n);
    g.realText = crToLfW(w);
}

static void setEditTextFromState() {
    std::wstring display;
    size_t caret = 0;

    if (g.revealed) {
        display = lfToCrW(g.realText);
        caret   = g.realCursor;
        if (caret > display.size()) caret = display.size();
    } else {
        size_t n = std::min(g.coverCursor, g.coverText.size());
        std::wstring vis = g.coverText.substr(0, n);
        display = lfToCrW(vis);
        caret   = display.size();
    }

    BOOL wasModified = (BOOL)SendMessageW(g.hwndEdit, EM_GETMODIFY, 0, 0);

    SendMessageW(g.hwndEdit, WM_SETREDRAW, FALSE, 0);
    SetWindowTextW(g.hwndEdit, display.c_str());
    applyEditorTheme();
    SendMessageW(g.hwndEdit, EM_SETSEL, (WPARAM)caret, (LPARAM)caret);
    SendMessageW(g.hwndEdit, EM_SCROLLCARET, 0, 0);
    SendMessageW(g.hwndEdit, EM_SETMODIFY, wasModified, 0);
    SendMessageW(g.hwndEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g.hwndEdit, nullptr, TRUE);
}

static void refreshCoverDisplay() {
    if (g.revealed) return;

    size_t n = std::min(g.coverCursor, g.coverText.size());
    std::wstring display = lfToCrW(g.coverText.substr(0, n));

    SendMessageW(g.hwndEdit, WM_SETREDRAW, FALSE, 0);
    SetWindowTextW(g.hwndEdit, display.c_str());
    applyEditorTheme();
    size_t caret = display.size();
    SendMessageW(g.hwndEdit, EM_SETSEL, (WPARAM)caret, (LPARAM)caret);
    SendMessageW(g.hwndEdit, EM_SCROLLCARET, 0, 0);
    SendMessageW(g.hwndEdit, EM_SETMODIFY, TRUE, 0);
    SendMessageW(g.hwndEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g.hwndEdit, nullptr, TRUE);
}

static void setRevealed(bool on) {
    if (g.revealed == on) return;
    if (!on && g.revealed) {
        pullTextFromEdit();
        DWORD s = 0, e = 0;
        g.getSel(s, e);
        g.realCursor = (size_t)s;
        if (g.realCursor > g.realText.size())
            g.realCursor = g.realText.size();
        g.coverCursor = std::min<size_t>(g.realCursor, g.coverText.size());
    }
    g.revealed = on;
    setEditTextFromState();
    SendMessageW(g.hwndEdit, EM_SETREADONLY, on ? FALSE : TRUE, 0);
    updateTitle();
    updateStatus();
}

// ===========================================================================
//  COVER-mode editing primitives
// ===========================================================================
static void coverAdvanceDecoy() {
    if (g.coverCursor >= g.coverText.size()) return;
    wchar_t c = g.coverText[g.coverCursor++];
    if (c >= 0xD800 && c <= 0xDBFF && g.coverCursor < g.coverText.size()) {
        wchar_t d = g.coverText[g.coverCursor];
        if (d >= 0xDC00 && d <= 0xDFFF) g.coverCursor++;
    }
}

static void coverRetreatDecoy() {
    if (g.coverCursor == 0) return;
    g.coverCursor--;
    if (g.coverCursor > 0) {
        wchar_t c = g.coverText[g.coverCursor];
        if (c >= 0xDC00 && c <= 0xDFFF) {
            wchar_t d = g.coverText[g.coverCursor - 1];
            if (d >= 0xD800 && d <= 0xDBFF) g.coverCursor--;
        }
    }
}

static void coverInsert(wchar_t c) {
    if (g.realCursor > g.realText.size())
        g.realCursor = g.realText.size();
    g.realText.insert(g.realText.begin() + g.realCursor, c);
    g.realCursor++;
    coverAdvanceDecoy();
    refreshCoverDisplay();
    updateTitle();
    updateStatus();
}

static void coverBackspace() {
    if (g.realCursor > 0) {
        g.realText.erase(g.realCursor - 1, 1);
        g.realCursor--;
    }
    coverRetreatDecoy();
    refreshCoverDisplay();
    updateTitle();
    updateStatus();
}

// ===========================================================================
//  Password / input dialogs
// ===========================================================================
struct PwParams {
    const wchar_t* prompt = L"";
    const wchar_t* title  = L"PrivEdit";
    bool confirm = false;
    std::wstring result;
    bool ok = false;
};

static INT_PTR CALLBACK PwDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    PwParams* pp = (PwParams*)GetWindowLongPtrW(hDlg, DWLP_USER);
    switch (msg) {
    case WM_INITDIALOG: {
        pp = (PwParams*)lp;
        SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)pp);
        SetWindowTextW(hDlg, pp->title);
        SetDlgItemTextW(hDlg, IDC_PROMPT, pp->prompt);
        if (!pp->confirm) {
            ShowWindow(GetDlgItem(hDlg, IDC_CONFIRM_LABEL), SW_HIDE);
            ShowWindow(GetDlgItem(hDlg, IDC_CONFIRM),       SW_HIDE);
        }
        SetFocus(GetDlgItem(hDlg, IDC_PASSWORD));
        return FALSE;
    }
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        INT_PTR r = handleDialogCtlColor(msg, wp);
        if (r) return r;
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDOK: {
            wchar_t a[512] = {0}, b[512] = {0};
            GetDlgItemTextW(hDlg, IDC_PASSWORD, a, 511);
            if (pp->confirm) GetDlgItemTextW(hDlg, IDC_CONFIRM, b, 511);
            if (!a[0]) {
                MessageBoxW(hDlg, L"Password cannot be empty.", L"PrivEdit",
                            MB_ICONWARNING);
                return TRUE;
            }
            if (pp->confirm && wcscmp(a, b) != 0) {
                MessageBoxW(hDlg, L"Passwords do not match.", L"PrivEdit",
                            MB_ICONWARNING);
                SecureZeroMemory(a, sizeof(a));
                SecureZeroMemory(b, sizeof(b));
                return TRUE;
            }
            pp->result = a;
            SecureZeroMemory(a, sizeof(a));
            SecureZeroMemory(b, sizeof(b));
            pp->ok = true;
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

static bool askPassword(const wchar_t* title, const wchar_t* prompt,
                        bool confirm, std::wstring& out) {
    PwParams pp;
    pp.title   = title;
    pp.prompt  = prompt;
    pp.confirm = confirm;
    INT_PTR r = DialogBoxParamW(g.hInst, MAKEINTRESOURCEW(IDD_PASSWORD),
                                g.hwndMain, PwDlgProc, (LPARAM)&pp);
    if (r == IDOK && pp.ok) { out = pp.result; return true; }
    return false;
}

struct InParams {
    const wchar_t* prompt = L"";
    std::wstring result;
    bool ok = false;
};

static INT_PTR CALLBACK InDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    InParams* pp = (InParams*)GetWindowLongPtrW(hDlg, DWLP_USER);
    switch (msg) {
    case WM_INITDIALOG:
        pp = (InParams*)lp;
        SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)pp);
        SetDlgItemTextW(hDlg, IDC_PROMPT, pp->prompt);
        SetFocus(GetDlgItem(hDlg, IDC_INPUT_TEXT));
        return FALSE;
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        INT_PTR r = handleDialogCtlColor(msg, wp);
        if (r) return r;
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            wchar_t buf[512] = {0};
            GetDlgItemTextW(hDlg, IDC_INPUT_TEXT, buf, 511);
            pp->result = buf;
            pp->ok = true;
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}
static bool askInput(const wchar_t* prompt, std::wstring& out) {
    InParams pp;
    pp.prompt = prompt;
    INT_PTR r = DialogBoxParamW(g.hInst, MAKEINTRESOURCEW(IDD_INPUT),
                                g.hwndMain, InDlgProc, (LPARAM)&pp);
    if (r == IDOK && pp.ok) { out = pp.result; return true; }
    return false;
}

// ===========================================================================
//  File dialogs
// ===========================================================================
static bool showOpenDialog(std::wstring& path) {
    wchar_t buf[MAX_PATH * 2] = {0};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g.hwndMain;
    ofn.lpstrFilter =
        L"PrivEdit documents (*.enc;*.exe;*.bin;*.run)\0*.enc;*.exe;*.bin;*.run\0"
        L"Encrypted documents (*.enc)\0*.enc\0"
        L"Self-contained notes (*.exe;*.bin;*.run)\0*.exe;*.bin;*.run\0"
        L"All files (*.*)\0*.*\0";
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = _countof(buf);
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_EXPLORER;
    ofn.lpstrDefExt = L"enc";
    if (GetOpenFileNameW(&ofn)) { path = buf; return true; }
    return false;
}

static bool showSaveDialog(std::wstring& path) {
    wchar_t buf[MAX_PATH * 2] = {0};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g.hwndMain;
    ofn.lpstrFilter =
        L"Encrypted documents (*.enc)\0*.enc\0"
        L"Self-contained notes (*.exe)\0*.exe\0"
        L"All files (*.*)\0*.*\0";
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = _countof(buf);
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_EXPLORER;
    ofn.lpstrDefExt = L"enc";
    if (GetSaveFileNameW(&ofn)) { path = buf; return true; }
    return false;
}

static bool looksLikeNoteExt(const std::wstring& path) {
    auto ends = [&](const wchar_t* ext) {
        size_t el = wcslen(ext);
        if (path.size() < el) return false;
        std::wstring tail = path.substr(path.size() - el);
        for (auto& c : tail) c = towlower(c);
        return tail == ext;
    };
    return ends(L".exe") || ends(L".bin") || ends(L".run");
}

// ===========================================================================
//  Open / New / Save
// ===========================================================================
static bool openDocument(const std::wstring& path) {
    std::vector<uint8_t> data;
    if (!readFileBytes(path, data)) {
        MessageBoxW(g.hwndMain, L"Cannot read file.", L"PrivEdit", MB_ICONERROR);
        return false;
    }

    size_t mo = 0; uint64_t pl = 0;
    bool isNote = priv::findPrivexeMarker(data, mo, pl);

    const int maxAttempts = 3;
    DerivedKeys keys;
    std::string cover, content;
    std::wstring pw;
    std::string  pwUtf8;
    bool success = false;

    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        wchar_t prompt[128];
        if (attempt == 1)
            _snwprintf_s(prompt, _countof(prompt), _TRUNCATE,
                         L"Document password:");
        else
            _snwprintf_s(prompt, _countof(prompt), _TRUNCATE,
                         L"Document password (attempt %d of %d):",
                         attempt, maxAttempts);

        if (!askPassword(L"PrivEdit", prompt, false, pw))
            return false;

        pwUtf8 = wideToUtf8(pw);
        SecureZeroMemory(&pw[0], pw.size() * sizeof(wchar_t));

        SetCursor(LoadCursorW(nullptr, IDC_WAIT));

        std::string plain;
        bool pwOk = false;
        std::string pwErr;
        try {
            if (isNote) {
                Bytes blob(data.begin() + mo + sizeof(priv::PRIVEXE_MAGIC) + 8,
                           data.begin() + mo + sizeof(priv::PRIVEXE_MAGIC) + 8 + pl);
                plain = priv::crypto::unseal(blob, pwUtf8, &keys);
            } else {
                plain = priv::crypto::unseal(data, pwUtf8, &keys);
            }
            pwOk = true;
        } catch (const std::exception& e) {
            pwErr = e.what();
        }
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));

        if (!pwOk) {
            priv::crypto::cleanse(pwUtf8);
            keys.wipe();
            if (attempt < maxAttempts) {
                std::wstring m = L"Incorrect password:\n\n";
                m += utf8ToWide(pwErr);
                m += L"\n\nPlease try again.";
                MessageBoxW(g.hwndMain, m.c_str(), L"PrivEdit", MB_ICONWARNING);
                continue;
            }
            std::wstring m = L"Too many failed attempts.\n\nLast error:\n";
            m += utf8ToWide(pwErr);
            MessageBoxW(g.hwndMain, m.c_str(), L"PrivEdit", MB_ICONERROR);
            return false;
        }

        try {
            if (isNote) {
                if (!priv::unpackPayload(plain, cover, content))
                    throw std::runtime_error("corrupt payload structure");
                priv::crypto::cleanse(plain);
            } else {
                content = std::move(plain);
            }
        } catch (const std::exception& e) {
            priv::crypto::cleanse(pwUtf8);
            keys.wipe();
            std::wstring m = L"File is corrupted:\n\n";
            m += utf8ToWide(e.what());
            MessageBoxW(g.hwndMain, m.c_str(), L"PrivEdit", MB_ICONERROR);
            return false;
        }
        success = true;
        break;
    }

    if (!success) return false;

    g.wipeSecrets();
    g.filepath  = path;
    g.isNote    = isNote;
    g.password  = std::move(pwUtf8);
    g.keys      = std::move(keys);
    g.realText  = utf8ToWide(content);
    g.coverText = utf8ToWide(cover);
    g.realCursor  = g.realText.size();
    g.coverCursor = std::min(g.realCursor, g.coverText.size());

    if (!g.password.empty())
        VirtualLock(&g.password[0], g.password.size());
    if (!g.keys.key.empty())
        VirtualLock(g.keys.key.data(), g.keys.key.size());

    g.revealed = g.coverText.empty();
    setEditTextFromState();
    SendMessageW(g.hwndEdit, EM_SETREADONLY, g.revealed ? FALSE : TRUE, 0);
    updateTitle();
    updateStatus();
    return true;
}

static void newDocument() {
    std::wstring path;
    if (!showSaveDialog(path)) return;
    path = expandTildeW(path);

    std::wstring pw;
    if (!askPassword(L"New document", L"New password:", true, pw)) return;
    std::string pwUtf8 = wideToUtf8(pw);
    SecureZeroMemory(&pw[0], pw.size() * sizeof(wchar_t));

    SetCursor(LoadCursorW(nullptr, IDC_WAIT));

    DerivedKeys keys;
    std::vector<uint8_t> out;
    bool ok = false;
    try {
        Bytes salt = priv::crypto::randomSalt();
        keys = priv::crypto::deriveKeysArgon2id(pwUtf8, salt);
        std::string realUtf8  = wideToUtf8(g.realText);
        std::string coverUtf8 = wideToUtf8(g.coverText);
        if (looksLikeNoteExt(path)) {
            out = priv::buildSelfContained(g.stub, coverUtf8, realUtf8, keys);
        } else {
            out = priv::crypto::sealWithKeys(realUtf8, keys);
        }
        ok = writeFileAtomic(path, out);
    } catch (const std::exception& e) {
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
        priv::crypto::cleanse(pwUtf8);
        MessageBoxA(g.hwndMain, e.what(), "PrivEdit", MB_ICONERROR);
        return;
    }
    SetCursor(LoadCursorW(nullptr, IDC_ARROW));

    if (!ok) {
        priv::crypto::cleanse(pwUtf8);
        MessageBoxW(g.hwndMain, L"Cannot write file.", L"PrivEdit", MB_ICONERROR);
        return;
    }

    g.wipeSecrets();
    g.filepath   = path;
    g.isNote     = looksLikeNoteExt(path);
    g.password   = std::move(pwUtf8);
    g.keys       = std::move(keys);
    g.realText.clear();
    g.realCursor  = 0;
    g.coverCursor = 0;
    g.revealed = g.coverText.empty();

    if (!g.password.empty())
        VirtualLock(&g.password[0], g.password.size());
    if (!g.keys.key.empty())
        VirtualLock(g.keys.key.data(), g.keys.key.size());

    setEditTextFromState();
    SendMessageW(g.hwndEdit, EM_SETREADONLY, g.revealed ? FALSE : TRUE, 0);
    updateTitle();
    updateStatus();
}

// -- Windows self-swap helper ---------------------------------------------
static int runSwapHelper(int argc, wchar_t** argv) {
    if (argc < 5) return 2;
    std::wstring target = argv[2];
    std::wstring source = argv[3];
    DWORD pid = (DWORD)wcstoul(argv[4], nullptr, 10);

    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (h) { WaitForSingleObject(h, 120000); CloseHandle(h); }
    Sleep(300);

    std::wstring old = target + L".old";
    DeleteFileW(old.c_str());

    if (!MoveFileExW(target.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING))
        return 1;
    if (!MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        MoveFileExW(old.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING);
        return 1;
    }
    if (!DeleteFileW(old.c_str()))
        MoveFileExW(old.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);

    wchar_t me[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, me, MAX_PATH) > 0)
        MoveFileExW(me, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    return 0;
}

static bool spawnSwapHelper(const std::wstring& newFile) {
    wchar_t tmpDir[MAX_PATH] = {0};
    DWORD t = GetTempPathW(MAX_PATH, tmpDir);
    if (t == 0 || t >= MAX_PATH) return false;

    wchar_t helper[MAX_PATH];
    _snwprintf_s(helper, _countof(helper), _TRUNCATE,
                 L"%sprivedit_swap_%lu_%lu.exe",
                 tmpDir,
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long)GetTickCount());
    if (!writeFileAtomic(helper, g.stub)) return false;

    std::wstring cmd;
    cmd += L'"'; cmd += helper;               cmd += L"\" --swap-helper \"";
    cmd += g.selfPath;                        cmd += L"\" \"";
    cmd += newFile;                           cmd += L"\" ";
    cmd += std::to_wstring(GetCurrentProcessId());

    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(0);
    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                        DETACHED_PROCESS | CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

static bool saveDocument(bool saveAs) {
    if (g.revealed) pullTextFromEdit();

    if (saveAs || g.filepath.empty()) {
        std::wstring path = g.filepath;
        if (!showSaveDialog(path)) return false;
        path = expandTildeW(path);
        g.filepath = path;
        g.isNote = looksLikeNoteExt(path);
    }

    if (g.password.empty() || !g.keys.valid) {
        std::wstring pw;
        if (!askPassword(L"PrivEdit", L"Password:", false, pw)) return false;
        std::string pwUtf8 = wideToUtf8(pw);
        SecureZeroMemory(&pw[0], pw.size() * sizeof(wchar_t));
        try {
            Bytes salt = priv::crypto::randomSalt();
            DerivedKeys k = priv::crypto::deriveKeysArgon2id(pwUtf8, salt);
            g.password = std::move(pwUtf8);
            g.keys     = std::move(k);
        } catch (const std::exception& e) {
            priv::crypto::cleanse(pwUtf8);
            MessageBoxA(g.hwndMain, e.what(), "PrivEdit", MB_ICONERROR);
            return false;
        }
        if (!g.password.empty())
            VirtualLock(&g.password[0], g.password.size());
        if (!g.keys.key.empty())
            VirtualLock(g.keys.key.data(), g.keys.key.size());
    }

    SetCursor(LoadCursorW(nullptr, IDC_WAIT));

    std::vector<uint8_t> out;
    try {
        std::string realUtf8  = wideToUtf8(g.realText);
        std::string coverUtf8 = wideToUtf8(g.coverText);
        if (g.isNote) {
            out = priv::buildSelfContained(g.stub, coverUtf8, realUtf8, g.keys);
        } else {
            out = priv::crypto::sealWithKeys(realUtf8, g.keys);
        }
    } catch (const std::exception& e) {
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
        MessageBoxA(g.hwndMain, e.what(), "PrivEdit", MB_ICONERROR);
        return false;
    }

    bool isSelf = g.isNote &&
        _wcsicmp(canonicalPath(g.filepath).c_str(),
                 canonicalPath(g.selfPath).c_str()) == 0;

    if (isSelf) {
        std::wstring newFile = g.selfPath + L".new";
        if (!writeFileAtomic(newFile, out)) {
            SetCursor(LoadCursorW(nullptr, IDC_ARROW));
            MessageBoxW(g.hwndMain, L"Cannot write .new file.",
                        L"PrivEdit", MB_ICONERROR);
            return false;
        }
        if (!g.swapHelperSpawned) {
            if (!spawnSwapHelper(newFile)) {
                SetCursor(LoadCursorW(nullptr, IDC_ARROW));
                MessageBoxW(g.hwndMain, L"Could not spawn swap helper.",
                            L"PrivEdit", MB_ICONERROR);
                return false;
            }
            g.swapHelperSpawned = true;
        }
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
        g.setEditModified(false);
        updateTitle();
        MessageBoxW(g.hwndMain,
                    L"Saved. The running executable will be updated "
                    L"when you exit.",
                    L"PrivEdit", MB_ICONINFORMATION);
        return true;
    }

    if (!writeFileAtomic(g.filepath, out)) {
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
        MessageBoxW(g.hwndMain, L"Cannot write file.", L"PrivEdit", MB_ICONERROR);
        return false;
    }
    SetCursor(LoadCursorW(nullptr, IDC_ARROW));
    g.setEditModified(false);
    updateTitle();
    return true;
}

// ===========================================================================
//  Edit subclass
// ===========================================================================
static LRESULT CALLBACK EditSubclassProc(HWND hwnd, UINT msg, WPARAM wp,
                                         LPARAM lp, UINT_PTR /*id*/,
                                         DWORD_PTR /*ref*/) {
    if (!g.revealed) {
        switch (msg) {
        case WM_CHAR:
            if (wp == 8 || wp == 127) { coverBackspace();            return 0; }
            if (wp == 13 || wp == 10) { coverInsert(L'\n');          return 0; }
            if (wp == 9)              { for (int i = 0; i < 4; ++i)
                                          coverInsert(L' ');         return 0; }
            if (wp == 27)             { return 0; }
            if (wp >= 32)             { coverInsert((wchar_t)wp);    return 0; }
            return 0;
        case WM_KEYDOWN:
            switch (wp) {
            case VK_LEFT: case VK_RIGHT: case VK_UP: case VK_DOWN:
            case VK_HOME: case VK_END: case VK_PRIOR: case VK_NEXT:
            case VK_DELETE:
                return 0;
            }
            break;
        }
    }
    switch (msg) {
    case WM_KEYUP:
    case WM_LBUTTONUP:
    case WM_CHAR:
    case WM_LBUTTONDOWN:
        updateStatus();
        break;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

// ===========================================================================
//  Commands
// ===========================================================================
static void applyFontToEdit() {
    if (g.hFont) DeleteObject(g.hFont);
    g.hFont = makeEditorFont(g.dpi, L"Consolas", 10);
    SendMessageW(g.hwndEdit, WM_SETFONT, (WPARAM)g.hFont, TRUE);
    applyEditorTheme();
}

static void setWordWrap(bool on) {
    g.wordWrap = on;
    LONG style = GetWindowLongW(g.hwndEdit, GWL_STYLE);
    if (on) {
        style &= ~(LONG)WS_HSCROLL;
        SendMessageW(g.hwndEdit, EM_SETTARGETDEVICE, 0, 0);
    } else {
        style |= WS_HSCROLL;
        SendMessageW(g.hwndEdit, EM_SETTARGETDEVICE, 0, 1);
    }
    SetWindowLongW(g.hwndEdit, GWL_STYLE, style);
    CheckMenuItem(g.hMenu, ID_FORMAT_WORDWRAP,
                  MF_BYCOMMAND | (on ? MF_CHECKED : MF_UNCHECKED));
    InvalidateRect(g.hwndEdit, nullptr, TRUE);
}

static void setStatusBarVisible(bool on) {
    g.statusBar = on;
    ShowWindow(g.hwndStatus, on ? SW_SHOW : SW_HIDE);
    CheckMenuItem(g.hMenu, ID_VIEW_STATUSBAR,
                  MF_BYCOMMAND | (on ? MF_CHECKED : MF_UNCHECKED));
    RECT rc; GetClientRect(g.hwndMain, &rc);
    SendMessageW(g.hwndMain, WM_SIZE, 0,
                 MAKELPARAM(rc.right - rc.left, rc.bottom - rc.top));
}

static void doFind() {
    std::wstring q;
    if (!askInput(L"Find:", q)) return;
    if (q.empty()) return;
    g.lastSearch = q;

    DWORD s = 0, e = 0;
    g.getSel(s, e);

    FINDTEXTEXW ft = {};
    ft.chrg.cpMin = (LONG)e;
    ft.chrg.cpMax = -1;
    ft.lpstrText  = const_cast<wchar_t*>(g.lastSearch.c_str());
    LRESULT r = SendMessageW(g.hwndEdit, EM_FINDTEXTEXW, FR_DOWN, (LPARAM)&ft);
    if (r == -1) {
        ft.chrg.cpMin = 0; ft.chrg.cpMax = -1;
        r = SendMessageW(g.hwndEdit, EM_FINDTEXTEXW, FR_DOWN, (LPARAM)&ft);
    }
    if (r == -1) {
        MessageBoxW(g.hwndMain, L"Cannot find text.", L"PrivEdit",
                    MB_ICONINFORMATION);
        return;
    }
    SendMessageW(g.hwndEdit, EM_SETSEL, ft.chrgText.cpMin, ft.chrgText.cpMax);
    SendMessageW(g.hwndEdit, EM_SCROLLCARET, 0, 0);
}

static void doFindNext() {
    if (g.lastSearch.empty()) { doFind(); return; }
    DWORD s = 0, e = 0;
    g.getSel(s, e);
    FINDTEXTEXW ft = {};
    ft.chrg.cpMin = (LONG)e; ft.chrg.cpMax = -1;
    ft.lpstrText  = const_cast<wchar_t*>(g.lastSearch.c_str());
    LRESULT r = SendMessageW(g.hwndEdit, EM_FINDTEXTEXW, FR_DOWN, (LPARAM)&ft);
    if (r == -1) {
        ft.chrg.cpMin = 0; ft.chrg.cpMax = -1;
        r = SendMessageW(g.hwndEdit, EM_FINDTEXTEXW, FR_DOWN, (LPARAM)&ft);
    }
    if (r == -1) {
        MessageBoxW(g.hwndMain, L"Cannot find text.", L"PrivEdit",
                    MB_ICONINFORMATION);
        return;
    }
    SendMessageW(g.hwndEdit, EM_SETSEL, ft.chrgText.cpMin, ft.chrgText.cpMax);
    SendMessageW(g.hwndEdit, EM_SCROLLCARET, 0, 0);
}

static void doTimeDate() {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t buf[64];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                 L"%02d:%02d %04d-%02d-%02d",
                 st.wHour, st.wMinute,
                 st.wYear, st.wMonth, st.wDay);
    if (g.revealed) {
        SendMessageW(g.hwndEdit, EM_REPLACESEL, TRUE, (LPARAM)buf);
    } else {
        for (const wchar_t* p = buf; *p; ++p) coverInsert(*p);
    }
}

// -- Cover text dialog -----------------------------------------------------
struct CoverCtx {
    bool ok = false;
    std::wstring text;
};
static INT_PTR CALLBACK CoverDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    CoverCtx* c = (CoverCtx*)GetWindowLongPtrW(hDlg, DWLP_USER);
    switch (msg) {
    case WM_INITDIALOG:
        c = (CoverCtx*)lp;
        SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)c);
        SetDlgItemTextW(hDlg, IDC_COVER_TEXT, c->text.c_str());
        return TRUE;
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        INT_PTR r = handleDialogCtlColor(msg, wp);
        if (r) return r;
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            int n = GetWindowTextLengthW(GetDlgItem(hDlg, IDC_COVER_TEXT));
            std::wstring w; w.resize((size_t)n + 1);
            GetDlgItemTextW(hDlg, IDC_COVER_TEXT, &w[0], n + 1);
            w.resize((size_t)n);
            c->text = crToLfW(w);
            c->ok = true;
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}
static void doSetCover() {
    CoverCtx ctx;
    ctx.text = g.coverText;
    INT_PTR r = DialogBoxParamW(g.hInst, MAKEINTRESOURCEW(IDD_COVER),
                                g.hwndMain, CoverDlgProc, (LPARAM)&ctx);
    if (r != IDOK || !ctx.ok) return;
    g.coverText = std::move(ctx.text);
    if (g.coverCursor > g.coverText.size())
        g.coverCursor = g.coverText.size();
    if (!g.revealed) refreshCoverDisplay();
    SendMessageW(g.hwndEdit, EM_SETMODIFY, TRUE, 0);
    updateStatus();
}

static void doChangePassword() {
    std::wstring pw;
    if (!askPassword(L"PrivEdit", L"New password:", true, pw)) return;
    std::string pwUtf8 = wideToUtf8(pw);
    SecureZeroMemory(&pw[0], pw.size() * sizeof(wchar_t));

    SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    try {
        Bytes salt = priv::crypto::randomSalt();
        DerivedKeys newKeys = priv::crypto::deriveKeysArgon2id(pwUtf8, salt);
        g.keys.wipe();
        priv::crypto::cleanse(g.password);
        g.password = std::move(pwUtf8);
        g.keys     = std::move(newKeys);
        if (!g.password.empty())
            VirtualLock(&g.password[0], g.password.size());
        if (!g.keys.key.empty())
            VirtualLock(g.keys.key.data(), g.keys.key.size());
    } catch (const std::exception& e) {
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
        priv::crypto::cleanse(pwUtf8);
        MessageBoxA(g.hwndMain, e.what(), "PrivEdit", MB_ICONERROR);
        return;
    }
    SetCursor(LoadCursorW(nullptr, IDC_ARROW));
    MessageBoxW(g.hwndMain,
                L"Password changed. It will take effect on the next save.",
                L"PrivEdit", MB_ICONINFORMATION);
}

static void doLock() {
    g.keys.wipe();
    priv::crypto::cleanse(g.password);
    g.keys = DerivedKeys{};
    if (!g.coverText.empty()) {
        setRevealed(false);
    } else {
        MessageBoxW(g.hwndMain,
                    L"No cover text is set, so there is nothing to show. "
                    L"The password will be required on the next save.",
                    L"PrivEdit", MB_ICONINFORMATION);
    }
}

// -- About dialog ----------------------------------------------------------
static INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM) {
    switch (msg) {
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        INT_PTR r = handleDialogCtlColor(msg, wp);
        if (r) return r;
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        break;
    }
    return FALSE;
}
static void doAbout() {
    DialogBoxParamW(g.hInst, MAKEINTRESOURCEW(IDD_ABOUT), g.hwndMain,
                    AboutDlgProc, 0);
}

// -- Font dialog -----------------------------------------------------------
static void doFontPicker() {
    LOGFONTW lf = {};
    HFONT cur = (HFONT)SendMessageW(g.hwndEdit, WM_GETFONT, 0, 0);
    if (cur) GetObjectW(cur, sizeof(lf), &lf);
    CHOOSEFONTW cf = {}; cf.lStructSize = sizeof(cf);
    cf.hwndOwner = g.hwndMain;
    cf.lpLogFont = &lf;
    cf.Flags = CF_SCREENFONTS | CF_INITTOLOGFONTSTRUCT | CF_FIXEDPITCHONLY;
    if (ChooseFontW(&cf)) {
        if (g.hFont) DeleteObject(g.hFont);
        g.hFont = CreateFontIndirectW(&lf);
        SendMessageW(g.hwndEdit, WM_SETFONT, (WPARAM)g.hFont, TRUE);
        applyEditorTheme();
    }
}

static LRESULT doCommand(int id, int /*code*/) {
    switch (id) {
    case ID_FILE_NEW:
        if (g.editModified()) {
            int r = MessageBoxW(g.hwndMain,
                                L"Discard changes to the current document?",
                                L"PrivEdit",
                                MB_YESNOCANCEL | MB_ICONQUESTION);
            if (r != IDYES) return 0;
        }
        g.filepath.clear();
        newDocument();
        return 0;

    case ID_FILE_OPEN: {
        if (g.editModified()) {
            int r = MessageBoxW(g.hwndMain,
                                L"Discard changes to the current document?",
                                L"PrivEdit",
                                MB_YESNOCANCEL | MB_ICONQUESTION);
            if (r != IDYES) return 0;
        }
        std::wstring path;
        if (!showOpenDialog(path)) return 0;
        openDocument(expandTildeW(path));
        return 0;
    }

    case ID_FILE_SAVE:    saveDocument(false); return 0;
    case ID_FILE_SAVEAS:  saveDocument(true);  return 0;
    case ID_FILE_EXIT:    PostMessageW(g.hwndMain, WM_CLOSE, 0, 0); return 0;

    case ID_EDIT_UNDO:
        if (g.revealed) { SendMessageW(g.hwndEdit, EM_UNDO, 0, 0); updateStatus(); }
        return 0;
    case ID_EDIT_CUT:
        if (g.revealed) SendMessageW(g.hwndEdit, WM_CUT, 0, 0);
        return 0;
    case ID_EDIT_COPY:
        SendMessageW(g.hwndEdit, WM_COPY, 0, 0);
        return 0;
    case ID_EDIT_PASTE:
        if (g.revealed) SendMessageW(g.hwndEdit, WM_PASTE, 0, 0);
        return 0;
    case ID_EDIT_DELETE:
        if (g.revealed)
            SendMessageW(g.hwndEdit, EM_REPLACESEL, TRUE, (LPARAM)L"");
        return 0;
    case ID_EDIT_SELECTALL:
        SendMessageW(g.hwndEdit, EM_SETSEL, 0, -1);
        return 0;
    case ID_EDIT_TIMEDATE:  doTimeDate(); return 0;
    case ID_EDIT_FIND:      doFind();     return 0;
    case ID_EDIT_FINDNEXT:  doFindNext(); return 0;

    case ID_FORMAT_WORDWRAP: setWordWrap(!g.wordWrap); return 0;
    case ID_FORMAT_FONT:     doFontPicker();           return 0;

    case ID_VIEW_STATUSBAR:  setStatusBarVisible(!g.statusBar); return 0;
    case ID_VIEW_NIGHTTHEME:
        g.theme = (g.theme == Theme::Dark) ? Theme::Light : Theme::Dark;
        applyTheme();
        return 0;

    case ID_PRIV_REVEAL:   setRevealed(!g.revealed); return 0;
    case ID_PRIV_SETCOVER: doSetCover();             return 0;
    case ID_PRIV_CHANGEPW: doChangePassword();       return 0;
    case ID_PRIV_LOCK:     doLock();                 return 0;

    case ID_HELP_ABOUT:    doAbout(); return 0;
    }
    return 0;
}

// ===========================================================================
//  Main window procedure
// ===========================================================================
static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g.hwndMain = hwnd;
        g.hMenu    = GetMenu(hwnd);

        g.hwndEdit = CreateWindowExW(0, MSFTEDIT_CLASS, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_NOHIDESEL | ES_WANTRETURN,
            0, 0, 100, 100, hwnd, (HMENU)100, g.hInst, nullptr);
        if (!g.hwndEdit) return -1;

        SendMessageW(g.hwndEdit, EM_SETTEXTMODE,
                     TM_PLAINTEXT | TM_MULTICODEPAGE, 0);
        SendMessageW(g.hwndEdit, EM_SETLIMITTEXT, 0, 0);
        applyFontToEdit();
        SetWindowSubclass(g.hwndEdit, EditSubclassProc, 1, 0);

        g.hwndStatus = CreateWindowExW(0, STATUSCLASSNAMEW, L"",
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 100, 20, hwnd, (HMENU)200, g.hInst, nullptr);
        int parts[] = {-1};
        SendMessageW(g.hwndStatus, SB_SETPARTS, 1, (LPARAM)parts);

        CheckMenuItem(g.hMenu, ID_VIEW_STATUSBAR,  MF_BYCOMMAND | MF_CHECKED);
        CheckMenuItem(g.hMenu, ID_FORMAT_WORDWRAP, MF_BYCOMMAND | MF_UNCHECKED);
        CheckMenuItem(g.hMenu, ID_VIEW_NIGHTTHEME, MF_BYCOMMAND | MF_UNCHECKED);
        setWordWrap(false);
        return 0;
    }

    case WM_SIZE: {
        if (!g.hwndEdit) return 0;
        int w = LOWORD(lp), h = HIWORD(lp);
        int statusH = 0;
        if (g.statusBar && g.hwndStatus) {
            SendMessageW(g.hwndStatus, WM_SIZE, 0, 0);
            RECT rc; GetWindowRect(g.hwndStatus, &rc);
            statusH = rc.bottom - rc.top;
        }
        if (w < 0) w = 0;
        int editH = h - statusH; if (editH < 0) editH = 0;
        MoveWindow(g.hwndEdit, 0, 0, w, editH, TRUE);
        return 0;
    }

    case WM_SETFOCUS:
        if (g.hwndEdit) SetFocus(g.hwndEdit);
        return 0;

    case WM_COMMAND:
        return doCommand(LOWORD(wp), HIWORD(wp));

    case WM_CLOSE:
        if (g.editModified()) {
            int r = MessageBoxW(hwnd, L"Save changes before closing?",
                                L"PrivEdit",
                                MB_YESNOCANCEL | MB_ICONQUESTION);
            if (r == IDCANCEL) return 0;
            if (r == IDYES && !saveDocument(false)) return 0;
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_QUERYENDSESSION:
        return TRUE;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ===========================================================================
//  Entry point
// ===========================================================================
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);

    // --swap-helper dispatch (before anything else).
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv) {
            bool helper = (argc >= 2 && wcscmp(argv[1], L"--swap-helper") == 0);
            if (helper) {
                int rc = runSwapHelper(argc, argv);
                LocalFree(argv);
                return rc;
            }
            LocalFree(argv);
        }
    }

    g.hInst = hInst;

    // libsodium must be initialised before any crypto call.
    if (!priv::crypto::init()) {
        MessageBoxW(nullptr, L"Failed to initialise libsodium.",
                    L"PrivEdit", MB_ICONERROR);
        return 1;
    }

    // Resolve SetWindowTheme dynamically -- no uxtheme import.
    if (HMODULE hUx = LoadLibraryW(L"uxtheme.dll")) {
        FARPROC raw = GetProcAddress(hUx, "SetWindowTheme");
        void* p = nullptr;
        static_assert(sizeof(p) >= sizeof(raw),
                      "function pointer must fit in void*");
        std::memcpy(&p, &raw, sizeof(raw));
        pSetWindowTheme = reinterpret_cast<PFN_SetWindowTheme>(p);
        // Keep hUx loaded for the process lifetime on purpose.
    }

    g.hRich = LoadLibraryW(L"Msftedit.dll");
    if (!g.hRich) {
        MessageBoxW(nullptr,
                    L"Cannot load Msftedit.dll (required on Windows 7+).",
                    L"PrivEdit", MB_ICONERROR);
        return 1;
    }

    HDC hdc = GetDC(nullptr);
    g.dpi = GetDeviceCaps(hdc, LOGPIXELSY);
    ReleaseDC(nullptr, hdc);
    if (g.dpi < 72) g.dpi = 96;

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursorW(nullptr, IDC_IBEAM);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"PrivEdit.Main";
    wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);
    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Cannot register window class.",
                    L"PrivEdit", MB_ICONERROR);
        return 1;
    }

    g.selfPath = getModulePathW();
    readFileBytes(g.selfPath, g.selfData);
    g.selfIsNote = priv::findPrivexeMarker(g.selfData, g.selfMO, g.selfPL);
    if (g.selfIsNote)
        g.stub.assign(g.selfData.begin(), g.selfData.begin() + g.selfMO);
    else
        g.stub = g.selfData;

    HMENU menu = LoadMenuW(hInst, MAKEINTRESOURCEW(IDR_MAINMENU));
    g.hMenu = menu;
    g.hwndMain = CreateWindowExW(
        0, L"PrivEdit.Main", L"PrivEdit",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 820, 600,
        nullptr, menu, hInst, nullptr);
    if (!g.hwndMain) return 1;

    g.hAccel = LoadAcceleratorsW(hInst, MAKEINTRESOURCEW(IDR_MAINACCEL));
    ShowWindow(g.hwndMain, SW_SHOW);
    UpdateWindow(g.hwndMain);

    if (g.selfIsNote) {
        openDocument(g.selfPath);
    } else {
        SendMessageW(g.hwndEdit, EM_SETREADONLY, FALSE, 0);
        updateTitle();
        updateStatus();
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (g.hAccel && TranslateAcceleratorW(g.hwndMain, g.hAccel, &msg))
            continue;
        if (IsDialogMessageW(g.hwndMain, &msg))
            continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    g.wipeSecrets();
    if (g.hFont)      DeleteObject(g.hFont);
    if (g_brDarkBg)   DeleteObject(g_brDarkBg);
    if (g_brDarkCtl)  DeleteObject(g_brDarkCtl);
    if (g.hRich)      FreeLibrary(g.hRich);
    return (int)msg.wParam;
}