#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/dynldr'

module Metasm
module Gui
	class Win32Gui < DynLdr
		new_api_c <<EOS
typedef char CHAR;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int UINT;
typedef long LONG;
typedef unsigned long ULONG, DWORD;
typedef int BOOL;

typedef long LONG_PTR;
typedef unsigned long ULONG_PTR, DWORD_PTR;
typedef int INT_PTR;
typedef unsigned int UINT_PTR;
typedef LONG_PTR LPARAM;
typedef const CHAR *LPSTR, *LPCSTR;
typedef LONG_PTR LRESULT;
typedef UINT_PTR WPARAM;
typedef void VOID, *PVOID, *LPVOID;

typedef WORD ATOM;
typedef void *HANDLE;
typedef void *HBITMAP;
typedef void *HBRUSH;
typedef void *HCURSOR;
typedef void *HDC;
typedef void *HICON;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HMODULE;
typedef void *HWND;

#define DECLSPEC_IMPORT __declspec(dllimport)
#define WINUSERAPI DECLSPEC_IMPORT
#define WINAPI __stdcall
#define CALLBACK __stdcall
#define CONST const
#define __in __attribute__((in))
#define __out __attribute__((out))
#define __opt __attribute__((opt))
#define __inout __in __out
#define __in_opt __in __opt
#define __in_opt __in __opt
#define __out_opt __out __opt
#define __out_ecount(c) __out
#define __inout_ecount(c) __inout

#define CW_USEDEFAULT       ((int)0x80000000)

#define WS_OVERLAPPED       0x00000000L
#define WS_POPUP            0x80000000L
#define WS_CHILD            0x40000000L
#define WS_MINIMIZE         0x20000000L
#define WS_VISIBLE          0x10000000L
#define WS_DISABLED         0x08000000L
#define WS_CLIPSIBLINGS     0x04000000L
#define WS_CLIPCHILDREN     0x02000000L
#define WS_MAXIMIZE         0x01000000L
#define WS_CAPTION          0x00C00000L     /* WS_BORDER | WS_DLGFRAME  */
#define WS_BORDER           0x00800000L
#define WS_DLGFRAME         0x00400000L
#define WS_VSCROLL          0x00200000L
#define WS_HSCROLL          0x00100000L
#define WS_SYSMENU          0x00080000L
#define WS_THICKFRAME       0x00040000L
#define WS_GROUP            0x00020000L
#define WS_TABSTOP          0x00010000L
#define WS_MINIMIZEBOX      0x00020000L
#define WS_MAXIMIZEBOX      0x00010000L
#define WS_TILED            WS_OVERLAPPED
#define WS_ICONIC           WS_MINIMIZE
#define WS_SIZEBOX          WS_THICKFRAME
#define WS_TILEDWINDOW      WS_OVERLAPPEDWINDOW
#define WS_OVERLAPPEDWINDOW (WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX)
#define WS_POPUPWINDOW      (WS_POPUP |  WS_BORDER | WS_SYSMENU)
#define WS_CHILDWINDOW      (WS_CHILD)

#define WS_EX_DLGMODALFRAME     0x00000001L
#define WS_EX_NOPARENTNOTIFY    0x00000004L
#define WS_EX_TOPMOST           0x00000008L
#define WS_EX_ACCEPTFILES       0x00000010L
#define WS_EX_TRANSPARENT       0x00000020L
#define WS_EX_MDICHILD          0x00000040L
#define WS_EX_TOOLWINDOW        0x00000080L
#define WS_EX_WINDOWEDGE        0x00000100L
#define WS_EX_CLIENTEDGE        0x00000200L
#define WS_EX_CONTEXTHELP       0x00000400L
#define WS_EX_RIGHT             0x00001000L
#define WS_EX_LEFT              0x00000000L
#define WS_EX_RTLREADING        0x00002000L
#define WS_EX_LTRREADING        0x00000000L
#define WS_EX_LEFTSCROLLBAR     0x00004000L
#define WS_EX_RIGHTSCROLLBAR    0x00000000L
#define WS_EX_CONTROLPARENT     0x00010000L
#define WS_EX_STATICEDGE        0x00020000L
#define WS_EX_APPWINDOW         0x00040000L
#define WS_EX_OVERLAPPEDWINDOW  (WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE)
#define WS_EX_PALETTEWINDOW     (WS_EX_WINDOWEDGE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST)
#define WS_EX_LAYERED           0x00080000

#define WM_NULL                         0x0000
#define WM_CREATE                       0x0001
#define WM_DESTROY                      0x0002
#define WM_MOVE                         0x0003
#define WM_SIZE                         0x0005

#define WM_ACTIVATE                     0x0006
#define     WA_INACTIVE     0
#define     WA_ACTIVE       1
#define     WA_CLICKACTIVE  2

#define WM_SETFOCUS                     0x0007
#define WM_KILLFOCUS                    0x0008
#define WM_ENABLE                       0x000A
#define WM_SETREDRAW                    0x000B
#define WM_SETTEXT                      0x000C
#define WM_GETTEXT                      0x000D
#define WM_GETTEXTLENGTH                0x000E
#define WM_PAINT                        0x000F
#define WM_CLOSE                        0x0010
#define WM_QUERYENDSESSION              0x0011
#define WM_QUERYOPEN                    0x0013
#define WM_ENDSESSION                   0x0016
#define WM_QUIT                         0x0012
#define WM_ERASEBKGND                   0x0014
#define WM_SYSCOLORCHANGE               0x0015
#define WM_SHOWWINDOW                   0x0018
#define WM_WININICHANGE                 0x001A
#define WM_SETTINGCHANGE                WM_WININICHANGE
#define WM_DEVMODECHANGE                0x001B
#define WM_ACTIVATEAPP                  0x001C
#define WM_FONTCHANGE                   0x001D
#define WM_TIMECHANGE                   0x001E
#define WM_CANCELMODE                   0x001F
#define WM_SETCURSOR                    0x0020
#define WM_MOUSEACTIVATE                0x0021
#define WM_CHILDACTIVATE                0x0022
#define WM_QUEUESYNC                    0x0023
#define WM_GETMINMAXINFO                0x0024
typedef struct tagPOINT {
    LONG  x;
    LONG  y;
} POINT, *PPOINT, *LPPOINT;

typedef struct tagMINMAXINFO {
    POINT ptReserved;
    POINT ptMaxSize;
    POINT ptMaxPosition;
    POINT ptMinTrackSize;
    POINT ptMaxTrackSize;
} MINMAXINFO, *PMINMAXINFO, *LPMINMAXINFO;

#define WM_PAINTICON                    0x0026
#define WM_ICONERASEBKGND               0x0027
#define WM_NEXTDLGCTL                   0x0028
#define WM_SPOOLERSTATUS                0x002A
#define WM_DRAWITEM                     0x002B
#define WM_MEASUREITEM                  0x002C
#define WM_DELETEITEM                   0x002D
#define WM_VKEYTOITEM                   0x002E
#define WM_CHARTOITEM                   0x002F
#define WM_SETFONT                      0x0030
#define WM_GETFONT                      0x0031
#define WM_SETHOTKEY                    0x0032
#define WM_GETHOTKEY                    0x0033
#define WM_QUERYDRAGICON                0x0037
#define WM_COMPAREITEM                  0x0039
#define WM_GETOBJECT                    0x003D
#define WM_COMPACTING                   0x0041
#define WM_COMMNOTIFY                   0x0044
#define WM_WINDOWPOSCHANGING            0x0046
#define WM_WINDOWPOSCHANGED             0x0047
#define WM_POWER                        0x0048
#define PWR_OK              1
#define PWR_FAIL            (-1)
#define PWR_SUSPENDREQUEST  1
#define PWR_SUSPENDRESUME   2
#define PWR_CRITICALRESUME  3
#define WM_COPYDATA                     0x004A
typedef struct tagCOPYDATASTRUCT {
    ULONG_PTR dwData;
    DWORD cbData;
    PVOID lpData;
} COPYDATASTRUCT, *PCOPYDATASTRUCT;

#define WM_CANCELJOURNAL                0x004B

typedef struct tagMDINEXTMENU {
    HMENU   hmenuIn;
    HMENU   hmenuNext;
    HWND    hwndNext;
} MDINEXTMENU, *PMDINEXTMENU, *LPMDINEXTMENU;

#define WM_NOTIFY                       0x004E
#define WM_INPUTLANGCHANGEREQUEST       0x0050
#define WM_INPUTLANGCHANGE              0x0051
#define WM_TCARD                        0x0052
#define WM_HELP                         0x0053
#define WM_USERCHANGED                  0x0054
#define WM_NOTIFYFORMAT                 0x0055
#define NFR_ANSI                             1
#define NFR_UNICODE                          2
#define NF_QUERY                             3
#define NF_REQUERY                           4
#define WM_CONTEXTMENU                  0x007B
#define WM_STYLECHANGING                0x007C
#define WM_STYLECHANGED                 0x007D
#define WM_DISPLAYCHANGE                0x007E
#define WM_GETICON                      0x007F
#define WM_SETICON                      0x0080
#define WM_NCCREATE                     0x0081
#define WM_NCDESTROY                    0x0082
#define WM_NCCALCSIZE                   0x0083
#define WM_NCHITTEST                    0x0084
#define WM_NCPAINT                      0x0085
#define WM_NCACTIVATE                   0x0086
#define WM_GETDLGCODE                   0x0087
#define WM_SYNCPAINT                    0x0088
#define WM_NCMOUSEMOVE                  0x00A0
#define WM_NCLBUTTONDOWN                0x00A1
#define WM_NCLBUTTONUP                  0x00A2
#define WM_NCLBUTTONDBLCLK              0x00A3
#define WM_NCRBUTTONDOWN                0x00A4
#define WM_NCRBUTTONUP                  0x00A5
#define WM_NCRBUTTONDBLCLK              0x00A6
#define WM_NCMBUTTONDOWN                0x00A7
#define WM_NCMBUTTONUP                  0x00A8
#define WM_NCRBUTTONDBLCLK              0x00A6
#define WM_NCMBUTTONDOWN                0x00A7
#define WM_NCMBUTTONUP                  0x00A8
#define WM_NCMBUTTONDBLCLK              0x00A9
#define WM_NCXBUTTONDOWN                0x00AB
#define WM_NCXBUTTONUP                  0x00AC
#define WM_NCXBUTTONDBLCLK              0x00AD
#define WM_INPUT                        0x00FF
#define WM_KEYFIRST                     0x0100
#define WM_KEYDOWN                      0x0100
#define WM_KEYUP                        0x0101
#define WM_CHAR                         0x0102
#define WM_DEADCHAR                     0x0103
#define WM_SYSKEYDOWN                   0x0104
#define WM_SYSKEYUP                     0x0105
#define WM_SYSCHAR                      0x0106
#define WM_SYSDEADCHAR                  0x0107
#define WM_KEYLAST                      0x0108
#define WM_UNICHAR                      0x0109
#define WM_KEYLAST                      0x0109
#define UNICODE_NOCHAR                  0xFFFF
#define WM_IME_STARTCOMPOSITION         0x010D
#define WM_IME_ENDCOMPOSITION           0x010E
#define WM_IME_COMPOSITION              0x010F
#define WM_IME_KEYLAST                  0x010F

#define WM_INITDIALOG                   0x0110
#define WM_COMMAND                      0x0111
#define WM_SYSCOMMAND                   0x0112
#define WM_TIMER                        0x0113
#define WM_HSCROLL                      0x0114
#define WM_VSCROLL                      0x0115
#define WM_INITMENU                     0x0116
#define WM_INITMENUPOPUP                0x0117
#define WM_MENUSELECT                   0x011F
#define WM_MENUCHAR                     0x0120
#define WM_ENTERIDLE                    0x0121
#define WM_MENURBUTTONUP                0x0122
#define WM_MENUDRAG                     0x0123
#define WM_MENUGETOBJECT                0x0124
#define WM_UNINITMENUPOPUP              0x0125
#define WM_MENUCOMMAND                  0x0126
#define WM_CHANGEUISTATE                0x0127
#define WM_UPDATEUISTATE                0x0128
#define WM_QUERYUISTATE                 0x0129
#define UIS_SET                         1
#define UIS_CLEAR                       2
#define UIS_INITIALIZE                  3
#define UISF_HIDEFOCUS                  0x1
#define UISF_HIDEACCEL                  0x2
#define WM_CTLCOLORMSGBOX               0x0132
#define WM_CTLCOLOREDIT                 0x0133
#define WM_CTLCOLORLISTBOX              0x0134
#define WM_CTLCOLORBTN                  0x0135
#define WM_CTLCOLORDLG                  0x0136
#define WM_CTLCOLORSCROLLBAR            0x0137
#define WM_CTLCOLORSTATIC               0x0138
#define MN_GETHMENU                     0x01E1
#define WM_MOUSEFIRST                   0x0200
#define WM_MOUSEMOVE                    0x0200
#define WM_LBUTTONDOWN                  0x0201
#define WM_LBUTTONUP                    0x0202
#define WM_LBUTTONDBLCLK                0x0203
#define WM_RBUTTONDOWN                  0x0204
#define WM_RBUTTONUP                    0x0205
#define WM_RBUTTONDBLCLK                0x0206
#define WM_MBUTTONDOWN                  0x0207
#define WM_MBUTTONUP                    0x0208
#define WM_MBUTTONDBLCLK                0x0209
#define WM_MOUSEWHEEL                   0x020A
#define WM_XBUTTONDOWN                  0x020B
#define WM_XBUTTONUP                    0x020C
#define WM_XBUTTONDBLCLK                0x020D
#define WHEEL_DELTA                     120

#define WHEEL_PAGESCROLL                (UINT_MAX)
#define GET_WHEEL_DELTA_WPARAM(wParam)  ((short)HIWORD(wParam))
#define GET_KEYSTATE_WPARAM(wParam)     (LOWORD(wParam))
#define GET_NCHITTEST_WPARAM(wParam)    ((short)LOWORD(wParam))
#define GET_XBUTTON_WPARAM(wParam)      (HIWORD(wParam))

#define XBUTTON1      0x0001
#define XBUTTON2      0x0002

#define WM_PARENTNOTIFY                 0x0210
#define WM_ENTERMENULOOP                0x0211
#define WM_EXITMENULOOP                 0x0212
#define WM_NEXTMENU                     0x0213
#define WM_SIZING                       0x0214
#define WM_CAPTURECHANGED               0x0215
#define WM_MOVING                       0x0216
#define WM_DEVICECHANGE                 0x0219
#define WM_MDICREATE                    0x0220
#define WM_MDIDESTROY                   0x0221
#define WM_MDIACTIVATE                  0x0222
#define WM_MDIRESTORE                   0x0223
#define WM_MDINEXT                      0x0224
#define WM_MDIMAXIMIZE                  0x0225
#define WM_MDITILE                      0x0226
#define WM_MDICASCADE                   0x0227
#define WM_MDIICONARRANGE               0x0228
#define WM_MDIGETACTIVE                 0x0229
#define WM_MDISETMENU                   0x0230
#define WM_ENTERSIZEMOVE                0x0231
#define WM_EXITSIZEMOVE                 0x0232
#define WM_DROPFILES                    0x0233
#define WM_MDIREFRESHMENU               0x0234
#define WM_IME_SETCONTEXT               0x0281
#define WM_IME_NOTIFY                   0x0282
#define WM_IME_CONTROL                  0x0283
#define WM_IME_COMPOSITIONFULL          0x0284
#define WM_IME_SELECT                   0x0285
#define WM_IME_CHAR                     0x0286
#define WM_IME_REQUEST                  0x0288
#define WM_IME_KEYDOWN                  0x0290
#define WM_IME_KEYUP                    0x0291
#define WM_NCMOUSEHOVER                 0x02A0
#define WM_MOUSEHOVER                   0x02A1
#define WM_NCMOUSELEAVE                 0x02A2
#define WM_MOUSELEAVE                   0x02A3
#define WM_WTSSESSION_CHANGE            0x02B1
#define WM_TABLET_FIRST                 0x02c0
#define WM_TABLET_LAST                  0x02df
#define WM_CUT                          0x0300
#define WM_COPY                         0x0301
#define WM_PASTE                        0x0302
#define WM_CLEAR                        0x0303
#define WM_UNDO                         0x0304
#define WM_RENDERFORMAT                 0x0305
#define WM_RENDERALLFORMATS             0x0306
#define WM_DESTROYCLIPBOARD             0x0307
#define WM_DRAWCLIPBOARD                0x0308
#define WM_PAINTCLIPBOARD               0x0309
#define WM_VSCROLLCLIPBOARD             0x030A
#define WM_SIZECLIPBOARD                0x030B
#define WM_ASKCBFORMATNAME              0x030C
#define WM_CHANGECBCHAIN                0x030D
#define WM_HSCROLLCLIPBOARD             0x030E
#define WM_QUERYNEWPALETTE              0x030F
#define WM_PALETTEISCHANGING            0x0310
#define WM_PALETTECHANGED               0x0311
#define WM_HOTKEY                       0x0312
#define WM_PRINT                        0x0317
#define WM_PRINTCLIENT                  0x0318
#define WM_APPCOMMAND                   0x0319
#define WM_THEMECHANGED                 0x031A
#define WM_HANDHELDFIRST                0x0358
#define WM_HANDHELDLAST                 0x035F
#define WM_AFXFIRST                     0x0360
#define WM_AFXLAST                      0x037F
#define WM_PENWINFIRST                  0x0380
#define WM_PENWINLAST                   0x038F
#define WM_USER                         0x0400
#define WM_APP                          0x8000

#define WMSZ_LEFT           1
#define WMSZ_RIGHT          2
#define WMSZ_TOP            3
#define WMSZ_TOPLEFT        4
#define WMSZ_TOPRIGHT       5
#define WMSZ_BOTTOM         6
#define WMSZ_BOTTOMLEFT     7
#define WMSZ_BOTTOMRIGHT    8

#define SIZE_RESTORED       0
#define SIZE_MINIMIZED      1
#define SIZE_MAXIMIZED      2
#define SIZE_MAXSHOW        3
#define SIZE_MAXHIDE        4

typedef struct tagWINDOWPOS {
    HWND    hwnd;
    HWND    hwndInsertAfter;
    int     x;
    int     y;
    int     cx;
    int     cy;
    UINT    flags;
} WINDOWPOS, *LPWINDOWPOS, *PWINDOWPOS;

#define MK_LBUTTON          0x0001
#define MK_RBUTTON          0x0002
#define MK_SHIFT            0x0004
#define MK_CONTROL          0x0008
#define MK_MBUTTON          0x0010
#define MK_XBUTTON1         0x0020
#define MK_XBUTTON2         0x0040

typedef struct tagTRACKMOUSEEVENT {
    DWORD cbSize;
    DWORD dwFlags;
    HWND  hwndTrack;
    DWORD dwHoverTime;
} TRACKMOUSEEVENT, *LPTRACKMOUSEEVENT;

WINUSERAPI
BOOL
WINAPI
TrackMouseEvent(
    __inout LPTRACKMOUSEEVENT lpEventTrack);

#define FVIRTKEY  TRUE          /* Assumed to be == TRUE */
#define FNOINVERT 0x02
#define FSHIFT    0x04
#define FCONTROL  0x08
#define FALT      0x10

typedef struct tagACCEL {
    BYTE   fVirt;               /* Also called the flags field */
    WORD   key;
    WORD   cmd;
} ACCEL, *LPACCEL;

#define FALSE 0
#define TRUE 1

#define SW_HIDE             0
#define SW_SHOWNORMAL       1
#define SW_NORMAL           1
#define SW_SHOWMINIMIZED    2
#define SW_SHOWMAXIMIZED    3
#define SW_MAXIMIZE         3
#define SW_SHOWNOACTIVATE   4
#define SW_SHOW             5
#define SW_MINIMIZE         6
#define SW_SHOWMINNOACTIVE  7
#define SW_SHOWNA           8
#define SW_RESTORE          9
#define SW_SHOWDEFAULT      10
#define SW_FORCEMINIMIZE    11
#define SW_MAX              11

#define IDI_APPLICATION     32512
#define IDI_HAND            32513
#define IDI_QUESTION        32514
#define IDI_EXCLAMATION     32515
#define IDI_ASTERISK        32516
#define IDI_WINLOGO         32517

#define IDOK                1
#define IDCANCEL            2
#define IDABORT             3
#define IDRETRY             4
#define IDIGNORE            5
#define IDYES               6
#define IDNO                7
#define IDCLOSE         8
#define IDHELP          9
#define IDTRYAGAIN      10
#define IDCONTINUE      11
#define IDTIMEOUT 32000

#define IDC_ARROW           32512
#define IDC_IBEAM           32513
#define IDC_WAIT            32514
#define IDC_CROSS           32515
#define IDC_UPARROW         32516
#define IDC_SIZE            32640
#define IDC_ICON            32641
#define IDC_SIZENWSE        32642
#define IDC_SIZENESW        32643
#define IDC_SIZEWE          32644
#define IDC_SIZENS          32645
#define IDC_SIZEALL         32646
#define IDC_NO              32648
#define IDC_HAND            32649
#define IDC_APPSTARTING     32650
#define IDC_HELP            32651

#define WHITE_BRUSH         0
#define LTGRAY_BRUSH        1
#define GRAY_BRUSH          2
#define DKGRAY_BRUSH        3
#define BLACK_BRUSH         4
#define NULL_BRUSH          5
#define HOLLOW_BRUSH        NULL_BRUSH
#define WHITE_PEN           6
#define BLACK_PEN           7
#define NULL_PEN            8
#define OEM_FIXED_FONT      10
#define ANSI_FIXED_FONT     11
#define ANSI_VAR_FONT       12
#define SYSTEM_FONT         13
#define DEVICE_DEFAULT_FONT 14
#define DEFAULT_PALETTE     15
#define SYSTEM_FIXED_FONT   16
#define DEFAULT_GUI_FONT    17
#define DC_BRUSH            18
#define DC_PEN              19


typedef struct tagMSG {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
} MSG, *PMSG, *LPMSG;

WINUSERAPI
BOOL
WINAPI
GetMessageA(
    __out LPMSG lpMsg,
    __in_opt HWND hWnd,
    __in UINT wMsgFilterMin,
    __in UINT wMsgFilterMax);
WINUSERAPI
BOOL
WINAPI
TranslateMessage(
    __in CONST MSG *lpMsg);
WINUSERAPI
LRESULT
WINAPI
DispatchMessageA(
    __in CONST MSG *lpMsg);
#define MOD_ALT         0x0001
#define MOD_CONTROL     0x0002
#define MOD_SHIFT       0x0004
#define MOD_WIN         0x0008
WINUSERAPI
LRESULT
WINAPI
SendMessageA(
    __in HWND hWnd,
    __in UINT Msg,
    __in WPARAM wParam,
    __in LPARAM lParam);
WINUSERAPI
BOOL
WINAPI
PostMessageA(
    __in_opt HWND hWnd,
    __in UINT Msg,
    __in WPARAM wParam,
    __in LPARAM lParam);
WINUSERAPI
LRESULT
WINAPI
DefWindowProcA(
    __in HWND hWnd,
    __in UINT Msg,
    __in WPARAM wParam,
    __in LPARAM lParam);
WINUSERAPI
VOID
WINAPI
PostQuitMessage(
    __in int nExitCode);

typedef __stdcall LRESULT (*WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef struct tagWNDCLASSA {
    UINT        style;
    WNDPROC     lpfnWndProc;
    int         cbClsExtra;
    int         cbWndExtra;
    HINSTANCE   hInstance;
    HICON       hIcon;
    HCURSOR     hCursor;
    HBRUSH      hbrBackground;
    LPCSTR      lpszMenuName;
    LPCSTR      lpszClassName;
} WNDCLASSA;
WINUSERAPI
ATOM
WINAPI
RegisterClassA(
    __in CONST WNDCLASSA *lpWndClass);

typedef struct tagWNDCLASSEXA {
	UINT cbSize;
	UINT style;
	WNDPROC lpfnWndProc;
	int cbClsExtra;
	int cbWndExtra;
	HINSTANCE hInstance;
	HICON hIcon;
	HCURSOR hCursor;
	HBRUSH hbrBackground;
	LPCSTR lpszMenuName;
	LPCSTR lpszClassName;
	HICON hIconSm;
} WNDCLASSEXA;
WINUSERAPI
ATOM
WINAPI
RegisterClassExA(
    __in CONST WNDCLASSEXA *);
WINUSERAPI
HWND
WINAPI
CreateWindowExA(
    __in DWORD dwExStyle,
    __in_opt LPCSTR lpClassName,
    __in_opt LPCSTR lpWindowName,
    __in DWORD dwStyle,
    __in int X,
    __in int Y,
    __in int nWidth,
    __in int nHeight,
    __in_opt HWND hWndParent,
    __in_opt HMENU hMenu,
    __in_opt HINSTANCE hInstance,
    __in_opt LPVOID lpParam);
WINUSERAPI
BOOL
WINAPI
DestroyWindow(
    __in HWND hWnd);
WINUSERAPI
BOOL
WINAPI
ShowWindow(
    __in HWND hWnd,
    __in int nCmdShow);
WINUSERAPI
BOOL
WINAPI
CloseWindow(
    __in  HWND hWnd);
WINUSERAPI
BOOL
WINAPI
MoveWindow(
    __in HWND hWnd,
    __in int X,
    __in int Y,
    __in int nWidth,
    __in int nHeight,
    __in BOOL bRepaint);
WINUSERAPI
BOOL
WINAPI
SetWindowPos(
    __in HWND hWnd,
    __in_opt HWND hWndInsertAfter,
    __in int X,
    __in int Y,
    __in int cx,
    __in int cy,
    __in UINT uFlags);
WINUSERAPI
BOOL
WINAPI
BringWindowToTop(
    __in HWND hWnd);
WINUSERAPI
BOOL
WINAPI
EndDialog(
    __in HWND hDlg,
    __in INT_PTR nResult);
WINUSERAPI
HWND
WINAPI
GetDlgItem(
    __in_opt HWND hDlg,
    __in int nIDDlgItem);
WINUSERAPI
BOOL
WINAPI
SetDlgItemInt(
    __in HWND hDlg,
    __in int nIDDlgItem,
    __in UINT uValue,
    __in BOOL bSigned);
WINUSERAPI
UINT
WINAPI
GetDlgItemInt(
    __in HWND hDlg,
    __in int nIDDlgItem,
    __out_opt BOOL *lpTranslated,
    __in BOOL bSigned);
WINUSERAPI
BOOL
WINAPI
SetDlgItemTextA(
    __in HWND hDlg,
    __in int nIDDlgItem,
    __in LPCSTR lpString);
WINUSERAPI
UINT
WINAPI
GetDlgItemTextA(
    __in HWND hDlg,
    __in int nIDDlgItem,
    __out_ecount(cchMax) LPSTR lpString,
    __in int cchMax);
WINUSERAPI
BOOL
WINAPI
CheckDlgButton(
    __in HWND hDlg,
    __in int nIDButton,
    __in UINT uCheck);
WINUSERAPI
BOOL
WINAPI
CheckRadioButton(
    __in HWND hDlg,
    __in int nIDFirstButton,
    __in int nIDLastButton,
    __in int nIDCheckButton);
WINUSERAPI
UINT
WINAPI
IsDlgButtonChecked(
    __in HWND hDlg,
    __in int nIDButton);
WINUSERAPI
LRESULT
WINAPI
SendDlgItemMessageA(
    __in HWND hDlg,
    __in int nIDDlgItem,
    __in UINT Msg,
    __in WPARAM wParam,
    __in LPARAM lParam);
WINUSERAPI
HMENU
WINAPI
LoadMenuA(
    __in_opt HINSTANCE hInstance,
    __in LPCSTR lpMenuName);
WINUSERAPI
HMENU
WINAPI
GetMenu(
    __in HWND hWnd);
WINUSERAPI
BOOL
WINAPI
SetMenu(
    __in HWND hWnd,
    __in_opt HMENU hMenu);
WINUSERAPI
BOOL
WINAPI
ChangeMenuA(
    __in HMENU hMenu,
    __in UINT cmd,
    __in_opt LPCSTR lpszNewItem,
    __in UINT cmdInsert,
    __in UINT flags);
WINUSERAPI
UINT
WINAPI
GetMenuState(
    __in HMENU hMenu,
    __in UINT uId,
    __in UINT uFlags);
WINUSERAPI
HMENU
WINAPI
CreateMenu(VOID);
WINUSERAPI
HMENU
WINAPI
CreatePopupMenu(VOID);
WINUSERAPI
BOOL
WINAPI
DestroyMenu(
    __in HMENU hMenu);
WINUSERAPI
DWORD
WINAPI
CheckMenuItem(
    __in HMENU hMenu,
    __in UINT uIDCheckItem,
    __in UINT uCheck);
WINUSERAPI
BOOL
WINAPI
EnableMenuItem(
    __in HMENU hMenu,
    __in UINT uIDEnableItem,
    __in UINT uEnable);
WINUSERAPI
HMENU
WINAPI
GetSubMenu(
    __in HMENU hMenu,
    __in int nPos);
WINUSERAPI
UINT
WINAPI
GetMenuItemID(
    __in HMENU hMenu,
    __in int nPos);
WINUSERAPI
int
WINAPI
GetMenuItemCount(
    __in_opt HMENU hMenu);
WINUSERAPI
BOOL
WINAPI
InsertMenuA(
    __in HMENU hMenu,
    __in UINT uPosition,
    __in UINT uFlags,
    __in UINT_PTR uIDNewItem,
    __in_opt LPCSTR lpNewItem);
WINUSERAPI
BOOL
WINAPI
AppendMenuA(
    __in HMENU hMenu,
    __in UINT uFlags,
    __in UINT_PTR uIDNewItem,
    __in_opt LPCSTR lpNewItem);
WINUSERAPI
BOOL
WINAPI
ModifyMenuA(
    __in HMENU hMnu,
    __in UINT uPosition,
    __in UINT uFlags,
    __in UINT_PTR uIDNewItem,
    __in_opt LPCSTR lpNewItem);
WINUSERAPI
BOOL
WINAPI RemoveMenu(
    __in HMENU hMenu,
    __in UINT uPosition,
    __in UINT uFlags);
WINUSERAPI
BOOL
WINAPI
DeleteMenu(
    __in HMENU hMenu,
    __in UINT uPosition,
    __in UINT uFlags);

typedef struct tagMENUITEMINFOA
{
    UINT     cbSize;
    UINT     fMask;
    UINT     fType;
    UINT     fState;
    UINT     wID;
    HMENU    hSubMenu;
    HBITMAP  hbmpChecked;
    HBITMAP  hbmpUnchecked;
    ULONG_PTR dwItemData;
    LPSTR    dwTypeData;
    UINT     cch;
    HBITMAP  hbmpItem;
}   MENUITEMINFOA, *LPMENUITEMINFOA, CONST *LPCMENUITEMINFOA;
WINUSERAPI
BOOL
WINAPI
InsertMenuItemA(
    __in HMENU hmenu,
    __in UINT item,
    __in BOOL fByPosition,
    __in LPCMENUITEMINFOA lpmi);

typedef struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT, *LPRECT;

WINUSERAPI
int
WINAPI
DrawTextA(
    __in HDC hdc,
    __inout_ecount(cchText) LPCSTR lpchText,
    __in int cchText,
    __inout LPRECT lprc,
    __in UINT format);
WINUSERAPI
HDC
WINAPI
GetDC(
    __in_opt HWND hWnd);
WINUSERAPI
int
WINAPI
ReleaseDC(
    __in_opt HWND hWnd,
    __in HDC hDC);

typedef struct tagPAINTSTRUCT {
    HDC         hdc;
    BOOL        fErase;
    RECT        rcPaint;
    BOOL        fRestore;
    BOOL        fIncUpdate;
    BYTE        rgbReserved[32];
} PAINTSTRUCT, *LPPAINTSTRUCT;
WINUSERAPI
HDC
WINAPI
BeginPaint(
    __in HWND hWnd,
    __out LPPAINTSTRUCT lpPaint);
WINUSERAPI
BOOL
WINAPI
EndPaint(
    __in HWND hWnd,
    __in CONST PAINTSTRUCT *lpPaint);
WINUSERAPI
BOOL
WINAPI
InvalidateRect(
    __in_opt HWND hWnd,
    __in_opt CONST RECT *lpRect,
    __in BOOL bErase);
WINUSERAPI
BOOL
WINAPI
SetWindowTextA(
    __in HWND hWnd,
    __in_opt LPCSTR lpString);
WINUSERAPI
int
WINAPI
GetWindowTextA(
    __in HWND hWnd,
    __out_ecount(nMaxCount) LPSTR lpString,
    __in int nMaxCount);
WINUSERAPI
int
WINAPI
MessageBoxA(
    __in_opt HWND hWnd,
    __in_opt LPCSTR lpText,
    __in_opt LPCSTR lpCaption,
    __in UINT uType);

typedef struct tagHELPINFO {      // Structure pointed to by lParam of WM_HELP
    UINT    cbSize;
    int     iContextType;
    int     iCtrlId;
    HANDLE  hItemHandle;
    DWORD_PTR dwContextId;
    POINT   MousePos;
} HELPINFO, *LPHELPINFO;
typedef VOID (CALLBACK *MSGBOXCALLBACK)(LPHELPINFO lpHelpInfo);
typedef struct tagMSGBOXPARAMSA
{
    UINT        cbSize;
    HWND        hwndOwner;
    HINSTANCE   hInstance;
    LPCSTR      lpszText;
    LPCSTR      lpszCaption;
    DWORD       dwStyle;
    LPCSTR      lpszIcon;
    DWORD_PTR   dwContextHelpId;
    MSGBOXCALLBACK      lpfnMsgBoxCallback;
    DWORD       dwLanguageId;
} MSGBOXPARAMSA, *PMSGBOXPARAMSA, *LPMSGBOXPARAMSA;
WINUSERAPI
int
WINAPI
MessageBoxIndirectA(
    __in CONST MSGBOXPARAMSA * lpmbp);

WINUSERAPI
BOOL
WINAPI
CheckMenuRadioItem(
    __in HMENU hmenu,
    __in UINT first,
    __in UINT last,
    __in UINT check,
    __in UINT flags);
WINUSERAPI
HICON
WINAPI
LoadIconA(
    __in_opt HINSTANCE hInstance,
    __in LPCSTR lpIconName);
WINUSERAPI
HCURSOR
WINAPI
LoadCursorA(
    __in_opt HINSTANCE hInstance,
    __in LPCSTR lpCursorName);
WINAPI PVOID GetStockObject(__in int i);
WINUSERAPI
BOOL
WINAPI
UpdateWindow(
    __in HWND hWnd);

#define FORMAT_MESSAGE_ALLOCATE_BUFFER 0x00000100
#define FORMAT_MESSAGE_IGNORE_INSERTS  0x00000200
#define FORMAT_MESSAGE_FROM_STRING     0x00000400
#define FORMAT_MESSAGE_FROM_HMODULE    0x00000800
#define FORMAT_MESSAGE_FROM_SYSTEM     0x00001000
#define FORMAT_MESSAGE_ARGUMENT_ARRAY  0x00002000
#define FORMAT_MESSAGE_MAX_WIDTH_MASK  0x000000FF

DWORD
WINAPI
GetLastError(
    VOID
    );
VOID
WINAPI
SetLastError(
    __in DWORD dwErrCode
    );
DWORD
WINAPI
FormatMessageA(
    DWORD dwFlags,
    LPVOID lpSource,
    DWORD dwMessageId,
    DWORD dwLanguageId,
    LPSTR lpBuffer,
    DWORD nSize,
    void *Arguments
    );

EOS

def self.test
	cls = alloc_c_struct('WNDCLASSEXA', 
	:cbsize => :size,
	:lpfnwndproc => callback_alloc_c('__stdcall int wndproc(int, int, int, int)') { |hwnd, msg, wp, lp| test_wndproc(hwnd, msg, wp, lp) },
	:hicon => loadicona(0, IDI_APPLICATION),
	:hcursor => loadcursora(0, IDC_ARROW),
	:hbrbackground => getstockobject(DKGRAY_BRUSH),
	:lpszclassname => 'flublu',
	:hiconsm => loadicona(0, IDI_APPLICATION))

	registerclassexa(cls)

	hwnd = createwindowexa(nil, 'flublu', 'lol title', WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, 0, 0)
	showwindow(hwnd, SW_SHOW)
	updatewindow(hwnd)

	msg = alloc_c_struct('MSG')
	while getmessagea(msg, 0, 0, 0) != 0
		translatemessage(msg)
		dispatchmessagea(msg)
	end

	return msg[:wparam]
end

MSGNAME = constants.grep(/WM_/).inject({}) { |h, c| h.update const_get(c) => c }

def self.test_wndproc(hwnd, msg, wp, lp)
puts "testwproc #{MSGNAME[msg] || msg}"
	case msg
	when WM_CREATE
	when WM_PAINT
		ps = alloc_c_struct('PAINTSTRUCT')
		rc = beginpaint(hwnd, ps)
		# stuff
		endpaint(hwnd, ps)
	when WM_CHAR
		case wp
		when ?q, 0x1b; postquitmessage(0)	# 1b = esc
		end
	when WM_LBUTTONDOWN
		r = alloc_c_struct('RECT', :left => 0, :top => 42, :right => 28, :bottom => 58)
		invalidaterect(hwnd, r, FALSE)	# false/true -> paint background
		updatewindow(hwnd)
	when WM_DESTROY
		postquitmessage(0)
	else return defwindowproca(hwnd, msg, wp, lp)
	end
	0
end

test
	end

	module Protect
		@@lasterror = Time.now
		def protect
			yield
		rescue Object
			puts $!.message, $!.backtrace   # also dump on stdout, for c/c
			delay = Time.now-@@lasterror
			sleep 1-delay if delay < 1      # msgbox flood protection
			@@lasterror = Time.now
			messagebox([$!.message, $!.backtrace].join("\n"), $!.class.name)
		end
	end
end
end
