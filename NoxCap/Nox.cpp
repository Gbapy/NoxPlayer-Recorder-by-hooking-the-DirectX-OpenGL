// Nox.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "Nox.h"
#include "app-helpers.h"
#include "hook-helpers.h"
#include "RemoteOps.h"
#include "graphics-hook-info.h"
//#include "RemoteOps.h"
#include "obfuscate.h"
#include "inject-library.h"
#include <io.h>
#include <vector>
#include <CommCtrl.h>
#include <shlobj.h>
#include <iostream>
#include <sstream>
#include <process.h>
#include <oleacc.h>
#include <TlHelp32.h>

#include <opencv2\core\core.hpp>
#include <opencv2\imgproc\imgproc.hpp>
#include <opencv2\highgui\highgui.hpp>

using namespace std;
using namespace cv;

struct dstr {
	char *array;
	SIZE_T len; /* number of characters, excluding null terminator */
	SIZE_T capacity;
};


enum gs_color_format {
	GS_UNKNOWN,
	GS_A8,
	GS_R8,
	GS_RGBA,
	GS_BGRX,
	GS_BGRA,
	GS_R10G10B10A2,
	GS_RGBA16,
	GS_R16,
	GS_RGBA16F,
	GS_RGBA32F,
	GS_RG16F,
	GS_RG32F,
	GS_R16F,
	GS_R32F,
	GS_DXT1,
	GS_DXT3,
	GS_DXT5,
	GS_R8G8,
};

enum hook_rate {
	HOOK_RATE_SLOW,
	HOOK_RATE_NORMAL,
	HOOK_RATE_FAST,
	HOOK_RATE_FASTEST
};

enum window_priority {
	WINDOW_PRIORITY_CLASS,
	WINDOW_PRIORITY_TITLE,
	WINDOW_PRIORITY_EXE,
};

enum capture_mode {
	CAPTURE_MODE_ANY,
	CAPTURE_MODE_WINDOW,
	CAPTURE_MODE_HOTKEY
};

struct game_capture_config {
	char *title;
	char *wClass;
	char *executable;
	enum window_priority priority;
	enum capture_mode mode;
	UINT32 scale_cx;
	UINT32 scale_cy;
	bool cursor;
	bool force_shmem;
	bool force_scaling;
	bool allow_transparency;
	bool limit_framerate;
	bool capture_overlays;
	bool anticheat_hook;
	enum hook_rate hook_rate;
};


typedef struct _NOXINFO_
{
	char	wName[MAX_PATH];
	HWND	hWnd;
	double	nFrameCount;
	bool	bStatus;
	DWORD	processID;
	HANDLE	hProcess = NULL;
	HANDLE	event_init = NULL;
	HANDLE	event_restart = NULL;
	HANDLE	event_ready = NULL;
	HANDLE	event_exit = NULL;
	HANDLE	event_stop = NULL;
	bool	is_app = false;
	wchar_t *app_sid;
	UINT32 cx;
	UINT32 cy;
	UINT32 pitch;
	struct dstr title;
	struct dstr wClass;
	struct dstr executable;
	bool process_is_64bit;
	bool convert_16bit;
	struct game_capture_config config;
	void *texture;
	struct hook_info *global_hook_info;
	HANDLE hook_data_map;
	HANDLE global_hook_info_map;
	HANDLE texture_mutexes[2];
	bool capturing;
	union {
		struct {
			struct shmem_data *shmem_data;
			UCHAR *texture_buffers[2];
		};

		struct shtex_data *shtex_data;
		void *data;
	};
	FARPROC copy_texture;
	UCHAR *renderData;
	BOOL	active = false;
}NOXINFO, *PNOXINFO;

#define GC_EVENT_FLAGS (EVENT_MODIFY_STATE | SYNCHRONIZE)
#define GC_MUTEX_FLAGS (SYNCHRONIZE)
#define GS_DYNAMIC (1 << 1)

graphics_offsets offsets32 = { 0 };
graphics_offsets offsets64 = { 0 };

enum capture_result { CAPTURE_FAIL, CAPTURE_RETRY, CAPTURE_SUCCESS };

#define MAX_LOADSTRING 100
#define UNUSED_PARAMETER(param) (void)param
#define DbgOut(x) OutputDebugStringA(x)

typedef HANDLE(WINAPI * OPEN_PROCESS_PROC)(DWORD, BOOL, DWORD);

OPEN_PROCESS_PROC	open_process_proc = NULL;

vector<NOXINFO> Noxs;
int				selectedNox = -1;
int				nWidthResized = 800;
int				nHeightResized = 600;
int				nFrameCnt = 0;
int				ScreenDPI = USER_DEFAULT_SCREEN_DPI;

double			DPIScaleFactorX = 1;

TCHAR			szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR			szWindowClass[MAX_LOADSTRING];			// the main window class name

bool			startFlag = false;

std::string		mainPath;
wchar_t			hook_dll_path[MAX_PATH] = { 0 };

HINSTANCE		hInst;								// current instance
HWND			hMainDlg = NULL;
HMODULE			glModule = NULL;
DWORD			hTargetProcessID = NULL;

// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

void warn(char *msg) {
	DbgOut(msg);
}

static inline enum gs_color_format convert_format(UINT32 format)
{
	switch (format) {
	case DXGI_FORMAT_R8G8B8A8_UNORM:
		return GS_RGBA;
	case DXGI_FORMAT_B8G8R8X8_UNORM:
		return GS_BGRX;
	case DXGI_FORMAT_B8G8R8A8_UNORM:
		return GS_BGRA;
	case DXGI_FORMAT_R10G10B10A2_UNORM:
		return GS_R10G10B10A2;
	case DXGI_FORMAT_R16G16B16A16_UNORM:
		return GS_RGBA16;
	case DXGI_FORMAT_R16G16B16A16_FLOAT:
		return GS_RGBA16F;
	case DXGI_FORMAT_R32G32B32A32_FLOAT:
		return GS_RGBA32F;
	}

	return GS_UNKNOWN;
}

BOOL FileExists(const char *filePathPtr)
{
	char filePath[MAX_PATH];

	// Strip quotation marks (if any)
	if (filePathPtr[0] == '"')
	{
		strcpy(filePath, filePathPtr + 1);
	}
	else
	{
		strcpy(filePath, filePathPtr);
	}

	// Strip quotation marks (if any)
	if (filePath[strlen(filePath) - 1] == '"')
		filePath[strlen(filePath) - 1] = 0;

	return (_access(filePath, 0) != -1);
}

static inline HMODULE kernel32(void)
{
	static HMODULE kernel32_handle = NULL;
	if (!kernel32_handle)
		kernel32_handle = GetModuleHandleW(L"kernel32");
	return kernel32_handle;
}

static inline HANDLE open_process(DWORD desired_access, bool inherit_handle,
	DWORD process_id)
{
	open_process_proc = NULL;
	if (!open_process_proc)
		open_process_proc = (OPEN_PROCESS_PROC)get_obfuscated_func(
		kernel32(), "NuagUykjcxr", 0x1B694B59451ULL);

	return open_process_proc(desired_access, inherit_handle, process_id);
}


static inline int inject_library(HANDLE process, const wchar_t *dll)
{
	return inject_library_obf(process, dll, "D|hkqkW`kl{k\\osofj",
		0xa178ef3655e5ade7, "[uawaRzbhh{tIdkj~~",
		0x561478dbd824387c, "[fr}pboIe`dlN}",
		0x395bfbc9833590fd, "\\`zs}gmOzhhBq",
		0x12897dd89168789a, "GbfkDaezbp~X",
		0x76aff7238788f7db);
}

static inline bool has_utf8_bom(const char *in_char)
{
	UCHAR *in = (UCHAR *)in_char;
	return (in && in[0] == 0xef && in[1] == 0xbb && in[2] == 0xbf);
}

SIZE_T utf8_to_wchar(const char *in, SIZE_T insize, wchar_t *out,
	SIZE_T outsize, int flags)
{
	int i_insize = (int)insize;
	int ret;

	if (i_insize == 0)
		i_insize = (int)strlen(in);

	/* prevent bom from being used in the string */
	if (has_utf8_bom(in)) {
		if (i_insize >= 3) {
			in += 3;
			i_insize -= 3;
		}
	}

	ret = MultiByteToWideChar(CP_UTF8, 0, in, i_insize, out, (int)outsize);

	UNUSED_PARAMETER(flags);
	return (ret > 0) ? (SIZE_T)ret : 0;
}

SIZE_T os_utf8_to_wcs(const char *str, SIZE_T len, wchar_t *dst,
	SIZE_T dst_size)
{
	SIZE_T in_len;
	SIZE_T out_len;

	if (!str)
		return 0;

	in_len = len ? len : strlen(str);
	out_len = dst ? (dst_size - 1) : utf8_to_wchar(str, in_len, NULL, 0, 0);

	if (dst) {
		if (!dst_size)
			return 0;

		if (out_len)
			out_len =
			utf8_to_wchar(str, in_len, dst, out_len + 1, 0);

		dst[out_len] = 0;
	}

	return out_len;
}

SIZE_T os_utf8_to_wcs_ptr(const char *str, SIZE_T len, wchar_t **pstr)
{
	if (str) {
		SIZE_T out_len = os_utf8_to_wcs(str, len, NULL, 0);

		*pstr = (wchar_t *)malloc((out_len + 1) * sizeof(wchar_t));
		return os_utf8_to_wcs(str, len, *pstr, out_len + 1);
	}
	else {
		*pstr = NULL;
		return 0;
	}
}

static inline bool hook_direct(PNOXINFO pNox)
{
	HANDLE process;
	int ret;

	process = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pNox->processID);
	//process = open_process(PROCESS_ALL_ACCESS, false, pNox->processID);
	if (!process) {
		int error = GetLastError();
		warn("hook_direct: could not open process: %s (%lu)");
		return false;
	}

	ret = inject_library(process, hook_dll_path);
	CloseHandle(process);

	if (ret != 0) {
		warn("hook_direct: inject failed: %d");
		return false;
	}

	return true;
}

static inline HANDLE open_event_plus_id(PNOXINFO pNox,
	const wchar_t *name, DWORD id)
{
	wchar_t new_name[64];
	_snwprintf(new_name, 64, L"%s%lu", name, id);
	return pNox->is_app ? open_app_event(pNox->app_sid, new_name)
		: open_event(new_name);
}

static inline HANDLE open_event_gc(PNOXINFO pNox, const wchar_t *name)
{
	return open_event_plus_id(pNox, name, pNox->processID);
}

bool OpenNOXEvent(PNOXINFO pNox) {
	pNox->event_restart = open_event_gc(pNox, EVENT_CAPTURE_RESTART);
	if (!pNox->event_restart) {
		DbgOut("init_events: failed to get hook_restart\n"
			"event: %lu");
		return false;
	}

	pNox->event_stop = open_event_gc(pNox, EVENT_CAPTURE_STOP);
	if (!pNox->event_stop) {
		DbgOut("init_events: failed to get hook_stop event\n");
		return false;
	}

	pNox->event_init = open_event_gc(pNox, EVENT_HOOK_INIT);
	if (!pNox->event_init) {
		DbgOut("init_events: failed to get hook_init event\n");
		return false;
	}

	pNox->event_ready = open_event_gc(pNox, EVENT_HOOK_READY);
	if (!pNox->event_ready) {
		DbgOut("init_events: failed to get hook_ready event\n");
		return false;
	}

	pNox->event_exit = open_event_gc(pNox, EVENT_HOOK_EXIT);
	if (!pNox->event_exit) {
		DbgOut("init_events: failed to get hook_exit event\n");
		return false;
	}
	return true;
}

static inline bool attempt_existing_hook(PNOXINFO pNox)
{
	pNox->event_restart = open_event_gc(pNox, EVENT_CAPTURE_RESTART);
	if (pNox->event_restart) {
		DbgOut("existing hook found, signaling process\n");
		SetEvent(pNox->event_restart);
		return true;
	}

	return false;
}

static inline HANDLE open_map_plus_id(PNOXINFO pNox, const wchar_t *name, DWORD id)
{
	wchar_t new_name[64];
	_snwprintf(new_name, 64, L"%s%lu", name, id);

	return pNox->is_app ? open_app_map(pNox->app_sid, new_name)
		: OpenFileMappingW(GC_MAPPING_FLAGS, false, new_name);
}

static inline HANDLE open_hook_info(PNOXINFO pNox)
{
	return open_map_plus_id(pNox, SHMEM_HOOK_INFO, pNox->processID);
}

static inline bool init_hook_info(PNOXINFO pNox)
{
	pNox->global_hook_info_map = open_hook_info(pNox);
	if (!pNox->global_hook_info_map) {
		warn("init_hook_info: get_hook_info failed/n");
		return false;
	}

	pNox->global_hook_info = (hook_info *)MapViewOfFile(pNox->global_hook_info_map,
		FILE_MAP_ALL_ACCESS, 0, 0,
		sizeof(*pNox->global_hook_info));
	if (!pNox->global_hook_info) {
		warn("init_hook_info: failed to map data view/n");
		return false;
	}

	pNox->config.mode = CAPTURE_MODE_ANY;
	pNox->config.priority = WINDOW_PRIORITY_EXE;
	pNox->config.cursor = false;
	pNox->config.allow_transparency = false;
	pNox->config.limit_framerate = false;
	pNox->config.capture_overlays = false;
	pNox->config.anticheat_hook = true;
	pNox->config.force_scaling = true;

	RECT rect;
	GetWindowRect(GetDlgItem(hMainDlg, IDC_PREVIEW), &rect);
	pNox->config.scale_cx = rect.right - rect.left;
	pNox->config.scale_cy = rect.bottom - rect.top;

	if (pNox->config.force_shmem) {
		warn("init_hook_info: user is forcing shared memory (multi-adapter compatibility mode)");
	}

	pNox->global_hook_info->offsets = pNox->process_is_64bit ? offsets64 : offsets32;
	
	pNox->global_hook_info->capture_overlay = pNox->config.capture_overlays;
	pNox->global_hook_info->force_shmem = pNox->config.force_shmem;
	pNox->global_hook_info->use_scale = pNox->config.force_scaling;
	if (pNox->config.scale_cx)
		pNox->global_hook_info->cx = pNox->config.scale_cx;
	if (pNox->config.scale_cy)
		pNox->global_hook_info->cy = pNox->config.scale_cy;
	pNox->global_hook_info->frame_interval = 30;
	//reset_frame_interval(gc);

	pNox->global_hook_info->force_shmem = true;
	pNox->hook_data_map = INVALID_HANDLE_VALUE;
	pNox->texture = NULL;
	pNox->renderData = NULL;
	return true;
}

static inline HANDLE open_mutex_plus_id(PNOXINFO pNox,
	const wchar_t *name, DWORD id)
{
	wchar_t new_name[64];
	_snwprintf(new_name, 64, L"%s%lu", name, id);
	return pNox->is_app ? open_app_mutex(pNox->app_sid, new_name)
		: open_mutex(new_name);
}

static inline HANDLE open_mutex_gc(PNOXINFO pNox, const wchar_t *name)
{
	return open_mutex_plus_id(pNox, name, pNox->processID);
}

static inline bool init_texture_mutexes(PNOXINFO pNox)
{
	pNox->texture_mutexes[0] = open_mutex_gc(pNox, MUTEX_TEXTURE1);
	pNox->texture_mutexes[1] = open_mutex_gc(pNox, MUTEX_TEXTURE2);

	if (!pNox->texture_mutexes[0] || !pNox->texture_mutexes[1]) {
		DWORD error = GetLastError();
		if (error == 2) {
			DbgOut("hook not loaded yet, retrying../n");
		}
		else {
			warn("failed to open texture mutexes: %lu/n");
		}
		return false;
	}

	return true;
}

bool AddNox(DWORD processID) {
	NOXINFO nox;
	nox.nFrameCount = 0;
	nox.bStatus = false;

	nox.processID = processID;
	nox.hProcess = open_process(
		PROCESS_QUERY_INFORMATION | SYNCHRONIZE, false, nox.processID);
	CloseHandle(nox.hProcess);
	nox.is_app = is_app(nox.hProcess);
	if (nox.is_app) {
		nox.app_sid = get_app_sid(nox.hProcess);
	}
	if (!attempt_existing_hook(&nox)) {
		if (!hook_direct(&nox)) {
			DbgOut("Fail to inject into target process\n");
			return FALSE;
		}
	}
	if (!init_texture_mutexes(&nox)) {
		return false;
	}
	if (!init_hook_info(&nox)) {
		return FALSE;
	}
	if (!OpenNOXEvent(&nox)) {
		DbgOut("Fail to Open NoxRecorder Event\n");
		return FALSE;
	}
	SetEvent(nox.event_init);
	nox.hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, nox.processID);
	Noxs.push_back(nox);
	return TRUE;
}

BOOL CALLBACK EnumWindowsProcMy(HWND hwnd, LPARAM lParam)
{
	char buf[MAX_PATH];
	if (!GetClassName(hwnd, buf, MAX_PATH)) return TRUE;

	char *p = strstr(buf, "Qt5QWindowIcon");
	if (p)
	{
		bool flag = false;
		for (int i = 0; i < Noxs.size(); i++) {
			if (Noxs[i].hWnd == hwnd) {
				flag = true;
				break;
			}
		}
		
		if (!flag) {
			//AddNox(hwnd);
		}
	}
	return TRUE;
}

PBITMAPINFO CreateBitmapInfoStruct(HBITMAP hBmp)
{
	BITMAP bmp;
	PBITMAPINFO pbmi;
	WORD    cClrBits;

	// Retrieve the bitmap color format, width, and height.  
	if (!GetObject(hBmp, sizeof(BITMAP), (LPSTR)&bmp)) return NULL;

	// Convert the color format to a count of bits.  
	cClrBits = (WORD)(bmp.bmPlanes * bmp.bmBitsPixel);
	if (cClrBits == 1)
		cClrBits = 1;
	else if (cClrBits <= 4)
		cClrBits = 4;
	else if (cClrBits <= 8)
		cClrBits = 8;
	else if (cClrBits <= 16)
		cClrBits = 16;
	else if (cClrBits <= 24)
		cClrBits = 24;
	else cClrBits = 32;

	// Allocate memory for the BITMAPINFO structure. (This structure  
	// contains a BITMAPINFOHEADER structure and an array of RGBQUAD  
	// data structures.)  

	if (cClrBits < 24)
		pbmi = (PBITMAPINFO)LocalAlloc(LPTR,
		sizeof(BITMAPINFOHEADER) +
		sizeof(RGBQUAD) * (1 << cClrBits));

	// There is no RGBQUAD array for these formats: 24-bit-per-pixel or 32-bit-per-pixel 

	else
		pbmi = (PBITMAPINFO)LocalAlloc(LPTR,
		sizeof(BITMAPINFOHEADER));

	// Initialize the fields in the BITMAPINFO structure.  

	pbmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	pbmi->bmiHeader.biWidth = bmp.bmWidth;
	pbmi->bmiHeader.biHeight = bmp.bmHeight;
	pbmi->bmiHeader.biPlanes = bmp.bmPlanes;
	pbmi->bmiHeader.biBitCount = bmp.bmBitsPixel;
	if (cClrBits < 24)
		pbmi->bmiHeader.biClrUsed = (1 << cClrBits);

	// If the bitmap is not compressed, set the BI_RGB flag.  
	pbmi->bmiHeader.biCompression = BI_RGB;

	// Compute the number of bytes in the array of color  
	// indices and store the result in biSizeImage.  
	// The width must be DWORD aligned unless the bitmap is RLE 
	// compressed. 
	pbmi->bmiHeader.biSizeImage = ((pbmi->bmiHeader.biWidth * cClrBits + 31) & ~31) / 8
		* pbmi->bmiHeader.biHeight;
	// Set biClrImportant to 0, indicating that all of the  
	// device colors are important.  
	pbmi->bmiHeader.biClrImportant = 0;
	return pbmi;
}

void CreateBMPFile(LPTSTR pszFile, HBITMAP hBMP)
{
	HANDLE hf;                 // file handle  
	BITMAPFILEHEADER hdr;       // bitmap file-header  
	PBITMAPINFOHEADER pbih;     // bitmap info-header  
	LPBYTE lpBits;              // memory pointer  
	DWORD dwTotal;              // total count of bytes  
	DWORD cb;                   // incremental count of bytes  
	BYTE *hp;                   // byte pointer  
	DWORD dwTmp;
	PBITMAPINFO pbi;
	HDC hDC;

	hDC = CreateCompatibleDC(GetWindowDC(GetDesktopWindow()));
	SelectObject(hDC, hBMP);

	pbi = CreateBitmapInfoStruct(hBMP);
	if (pbi == NULL) return;
	pbih = (PBITMAPINFOHEADER)pbi;
	lpBits = (LPBYTE)GlobalAlloc(GMEM_FIXED, pbih->biSizeImage);

	if (!lpBits) return;

	// Retrieve the color table (RGBQUAD array) and the bits  
	// (array of palette indices) from the DIB.  
	if (!GetDIBits(hDC, hBMP, 0, (WORD)pbih->biHeight, lpBits, pbi,
		DIB_RGB_COLORS)) return;

	// Create the .BMP file.  
	hf = CreateFile(pszFile,
		GENERIC_READ | GENERIC_WRITE,
		(DWORD)0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		(HANDLE)NULL);
	if (hf == INVALID_HANDLE_VALUE) return;

	hdr.bfType = 0x4d42;        // 0x42 = "B" 0x4d = "M"  
	// Compute the size of the entire file.  
	hdr.bfSize = (DWORD)(sizeof(BITMAPFILEHEADER) +
		pbih->biSize + pbih->biClrUsed
		* sizeof(RGBQUAD) + pbih->biSizeImage);
	hdr.bfReserved1 = 0;
	hdr.bfReserved2 = 0;

	// Compute the offset to the array of color indices.  
	hdr.bfOffBits = (DWORD) sizeof(BITMAPFILEHEADER) +
		pbih->biSize + pbih->biClrUsed
		* sizeof(RGBQUAD);

	// Copy the BITMAPFILEHEADER into the .BMP file.  
	if (!WriteFile(hf, (LPVOID)&hdr, sizeof(BITMAPFILEHEADER),
		(LPDWORD)&dwTmp, NULL)) return;

	// Copy the BITMAPINFOHEADER and RGBQUAD array into the file.  
	if (!WriteFile(hf, (LPVOID)pbih, sizeof(BITMAPINFOHEADER)
		+ pbih->biClrUsed * sizeof(RGBQUAD),
		(LPDWORD)&dwTmp, (NULL))) return;

	// Copy the array of color indices into the .BMP file.  
	dwTotal = cb = pbih->biSizeImage;
	hp = lpBits;
	if (!WriteFile(hf, (LPSTR)hp, (int)cb, (LPDWORD)&dwTmp, NULL)) return;

	// Close the .BMP file.  
	if (!CloseHandle(hf)) return;

	// Free memory.  
	GlobalFree((HGLOBAL)lpBits);
}

void ShowResultImage(HWND hWnd, HBITMAP bitmap) {
	HDC hdc = GetWindowDC(GetDlgItem(hWnd, IDC_PREVIEW));
	HDC hdcMem = CreateCompatibleDC(NULL);
	
	HGDIOBJ oldBitmap;
	RECT rect;
	GetClientRect(GetDlgItem(hWnd, IDC_PREVIEW), &rect);

	SetStretchBltMode(hdc, HALFTONE);

	oldBitmap = SelectObject(hdcMem, bitmap);

	StretchBlt(hdc, 0, 0, rect.right - rect.left, rect.bottom - rect.top, hdcMem, 0, 0, nWidthResized, nHeightResized, SRCCOPY);

	SelectObject(hdcMem, oldBitmap);
	ReleaseDC(GetDlgItem(hWnd, IDC_PREVIEW), hdc);
	DeleteDC(hdcMem);
	ReleaseDC(hWnd, hdc);
	DeleteDC(hdc);
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	wchar_t buf[MAX_PATH] = { 0 };
	wchar_t *hook_path = L"Noxcap.dll";

	GetModuleFileNameW(GetModuleHandle(NULL), buf, MAX_PATH);
	for (int i = wcslen(buf) - 1; i >= 0; i--) {
		if (buf[i] == '\\') {
			for (int j = 0; j <= i; j++) {
				hook_dll_path[j] = buf[j];
			}
			for (int j = 0; j < wcslen(hook_path); j++) {
				hook_dll_path[i + j + 1] = hook_path[j];
			}
			break;
		}
	}
	//if (!loadGLProcess()) {
	//	DbgOut("Fail to load GL Modulr(Functions)/n");
	//	return -1;
	//}
	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_NOX, szWindowClass, MAX_LOADSTRING);

	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, (DLGPROC)WndProc);
	return 1;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;
	
	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_NOX));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_NOX);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));
	
	return RegisterClassEx(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // Store instance handle in our global variable

   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

int CompensateXDPI(int val)
{
	if (ScreenDPI == USER_DEFAULT_SCREEN_DPI)
		return val;
	else
	{
		double tmpVal = (double)val * DPIScaleFactorX;

		if (tmpVal > 0)
			return (int)floor(tmpVal);
		else
			return (int)ceil(tmpVal);
	}
}

LRESULT ListItemAdd(HWND list, int index, char *string)
{
	LVITEM li;
	memset(&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index;
	li.iSubItem = 0;
	return ListView_InsertItem(list, &li);
}

LRESULT ListItemAddW(HWND list, int index, wchar_t *string)
{
	LVITEMW li;
	memset(&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index;
	li.iSubItem = 0;
	return SendMessageW(list, LVM_INSERTITEMW, 0, (LPARAM)(&li));
}

LRESULT ListSubItemSet(HWND list, int index, int subIndex, char *string)
{
	LVITEM li;
	memset(&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index;
	li.iSubItem = subIndex;
	return ListView_SetItem(list, &li);
}

void UpdateNoxList(HWND hWnd) {
	vector<NOXINFO> tmp;
	bool flag = false;

	for (int i = 0; i < Noxs.size(); i++) {
		if (GetWindowText(Noxs[i].hWnd, Noxs[i].wName, MAX_PATH)) {
			tmp.push_back(Noxs[i]);
		}
		else{
			flag = true;
		}
	}

	Noxs.clear();
	for (int i = 0; i < tmp.size(); i++) {
		Noxs.push_back(tmp[i]);
	}
	tmp.clear();
	HWND hList = GetDlgItem(hWnd, IDC_LIST1);
	if (flag || Noxs.size() != SendMessage(hList, LVM_GETITEMCOUNT, 0, 0)) {
		int line = 1;
		LVITEM item;
		memset(&item, 0, sizeof(item));
		item.mask = LVIF_TEXT;

		
		SendMessage(hList, LVM_DELETEALLITEMS, 0, (LPARAM)&item);
		for (int i = 0; i < Noxs.size(); i++) {
			ListItemAdd(hList, i, Noxs[i].wName);
			if (Noxs[i].bStatus)
				ListSubItemSet(hList, i, 1, "Capturing");
			else
				ListSubItemSet(hList, i, 1, "Stopped");
		}
	}
}

static int CALLBACK BrowseCallbackProc(HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData)
{

	if (uMsg == BFFM_INITIALIZED)
	{
		std::string tmp = (const char *)lpData;
		std::cout << "path: " << tmp << std::endl;
		SendMessage(hwnd, BFFM_SETSELECTION, TRUE, lpData);
	}

	return 0;
}

std::string BrowseFolder(std::string saved_path)
{
	TCHAR path[MAX_PATH];

	const char * path_param = saved_path.c_str();

	BROWSEINFO bi = { 0 };
	bi.lpszTitle = ("Browse for folder...");
	bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
	bi.lpfn = BrowseCallbackProc;
	bi.lParam = (LPARAM)path_param;

	LPITEMIDLIST pidl = SHBrowseForFolder(&bi);

	if (pidl != 0)
	{
		//get the name of the folder and put it in path
		SHGetPathFromIDList(pidl, path);

		//free memory used
		IMalloc * imalloc = 0;
		if (SUCCEEDED(SHGetMalloc(&imalloc)))
		{
			imalloc->Free(pidl);
			imalloc->Release();
		}

		return path;
	}

	return "";
}

void SetCurrentStatus(void* threadArg) {
	HWND hWnd = (HWND)threadArg;
	while (true)
	{
		selectedNox = ListView_GetSelectionMark(GetDlgItem(hWnd, IDC_LIST1));
		if (mainPath.empty()) {
			EnableWindow(GetDlgItem(hWnd, IDOK), FALSE);
			Sleep(100);
			continue;
		}
		if (selectedNox != -1) {
			EnableWindow(GetDlgItem(hWnd, IDOK), TRUE);
			if (Noxs[selectedNox].bStatus)
				SetWindowText(GetDlgItem(hWnd, IDOK), "Stop");
			else
				SetWindowText(GetDlgItem(hWnd, IDOK), "Start");
		}
		else
			EnableWindow(GetDlgItem(hWnd, IDOK), FALSE);
		for (int i = 0; i < Noxs.size(); i++) {
			if (Noxs[i].bStatus)
				ListSubItemSet(GetDlgItem(hWnd, IDC_LIST1), i, 1, "Capturing");
			else
				ListSubItemSet(GetDlgItem(hWnd, IDC_LIST1), i, 1, "Stopped");
		}
		Sleep(100);
	}
}

static inline enum capture_result init_capture_data(PNOXINFO pNox)
{
	pNox->cx = pNox->global_hook_info->cx;
	pNox->cy = pNox->global_hook_info->cy;
	pNox->pitch = pNox->global_hook_info->pitch;

	if (pNox->data) {
		UnmapViewOfFile(pNox->data);
		pNox->data = NULL;
	}

	if (pNox->hook_data_map != INVALID_HANDLE_VALUE)
		CloseHandle(pNox->hook_data_map);

	pNox->hook_data_map = open_map_plus_id(pNox, SHMEM_TEXTURE,
		pNox->global_hook_info->map_id);
	if (!pNox->hook_data_map) {
		DWORD error = GetLastError();
		if (error == 2) {
			return CAPTURE_RETRY;
		}
		else {
			warn("init_capture_data: failed to open file mapping/n");
		}
		return CAPTURE_FAIL;
	}

	pNox->data = MapViewOfFile(pNox->hook_data_map, FILE_MAP_ALL_ACCESS, 0, 0,
		pNox->global_hook_info->map_size);
	if (!pNox->data) {
		warn("init_capture_data: failed to map data view/n");
		return CAPTURE_FAIL;
	}
	pNox->active = true;
	return CAPTURE_SUCCESS;
}

static void copy_b5g6r5_tex(PNOXINFO pNox, int cur_texture,
	UCHAR *data, UINT32 pitch)
{
	UCHAR *input = pNox->texture_buffers[cur_texture];
	UINT32 gc_cx = pNox->cx;
	UINT32 gc_cy = pNox->cy;
	UINT32 gc_pitch = pNox->pitch;

	for (uint32_t y = 0; y < gc_cy; y++) {
		uint8_t *row = input + (gc_pitch * y);
		uint8_t *out = data + (pitch * y);

		for (uint32_t x = 0; x < gc_cx; x += 8) {
			__m128i pixels_blue, pixels_green, pixels_red;
			__m128i pixels_result;
			__m128i *pixels_dest;

			__m128i *pixels_src =
				(__m128i *)(row + x * sizeof(uint16_t));
			__m128i pixels = _mm_load_si128(pixels_src);

			__m128i zero = _mm_setzero_si128();
			__m128i pixels_low = _mm_unpacklo_epi16(pixels, zero);
			__m128i pixels_high = _mm_unpackhi_epi16(pixels, zero);

			__m128i blue_channel_mask = _mm_set1_epi32(0x0000001F);
			__m128i blue_offset = _mm_set1_epi32(0x00000003);
			__m128i green_channel_mask = _mm_set1_epi32(0x000007E0);
			__m128i green_offset = _mm_set1_epi32(0x00000008);
			__m128i red_channel_mask = _mm_set1_epi32(0x0000F800);
			__m128i red_offset = _mm_set1_epi32(0x00000300);

			pixels_blue =
				_mm_and_si128(pixels_low, blue_channel_mask);
			pixels_blue = _mm_slli_epi32(pixels_blue, 3);
			pixels_blue = _mm_add_epi32(pixels_blue, blue_offset);

			pixels_green =
				_mm_and_si128(pixels_low, green_channel_mask);
			pixels_green =
				_mm_add_epi32(pixels_green, green_offset);
			pixels_green = _mm_slli_epi32(pixels_green, 5);

			pixels_red =
				_mm_and_si128(pixels_low, red_channel_mask);
			pixels_red = _mm_add_epi32(pixels_red, red_offset);
			pixels_red = _mm_slli_epi32(pixels_red, 8);

			pixels_result = _mm_set1_epi32(0xFF000000);
			pixels_result =
				_mm_or_si128(pixels_result, pixels_blue);
			pixels_result =
				_mm_or_si128(pixels_result, pixels_green);
			pixels_result = _mm_or_si128(pixels_result, pixels_red);

			pixels_dest = (__m128i *)(out + x * sizeof(uint32_t));
			_mm_store_si128(pixels_dest, pixels_result);

			pixels_blue =
				_mm_and_si128(pixels_high, blue_channel_mask);
			pixels_blue = _mm_slli_epi32(pixels_blue, 3);
			pixels_blue = _mm_add_epi32(pixels_blue, blue_offset);

			pixels_green =
				_mm_and_si128(pixels_high, green_channel_mask);
			pixels_green =
				_mm_add_epi32(pixels_green, green_offset);
			pixels_green = _mm_slli_epi32(pixels_green, 5);

			pixels_red =
				_mm_and_si128(pixels_high, red_channel_mask);
			pixels_red = _mm_add_epi32(pixels_red, red_offset);
			pixels_red = _mm_slli_epi32(pixels_red, 8);

			pixels_result = _mm_set1_epi32(0xFF000000);
			pixels_result =
				_mm_or_si128(pixels_result, pixels_blue);
			pixels_result =
				_mm_or_si128(pixels_result, pixels_green);
			pixels_result = _mm_or_si128(pixels_result, pixels_red);

			pixels_dest =
				(__m128i *)(out + (x + 4) * sizeof(uint32_t));
			_mm_store_si128(pixels_dest, pixels_result);
		}
	}
}

static void copy_b5g5r5a1_tex(PNOXINFO pNox, int cur_texture,
	UCHAR *data, UINT32 pitch)
{
	UCHAR *input = pNox->texture_buffers[cur_texture];
	UINT32 gc_cx = pNox->cx;
	UINT32 gc_cy = pNox->cy;
	UINT32 gc_pitch = pNox->pitch;

	for (uint32_t y = 0; y < gc_cy; y++) {
		uint8_t *row = input + (gc_pitch * y);
		uint8_t *out = data + (pitch * y);

		for (uint32_t x = 0; x < gc_cx; x += 8) {
			__m128i pixels_blue, pixels_green, pixels_red,
				pixels_alpha;
			__m128i pixels_result;
			__m128i *pixels_dest;

			__m128i *pixels_src =
				(__m128i *)(row + x * sizeof(uint16_t));
			__m128i pixels = _mm_load_si128(pixels_src);

			__m128i zero = _mm_setzero_si128();
			__m128i pixels_low = _mm_unpacklo_epi16(pixels, zero);
			__m128i pixels_high = _mm_unpackhi_epi16(pixels, zero);

			__m128i blue_channel_mask = _mm_set1_epi32(0x0000001F);
			__m128i blue_offset = _mm_set1_epi32(0x00000003);
			__m128i green_channel_mask = _mm_set1_epi32(0x000003E0);
			__m128i green_offset = _mm_set1_epi32(0x000000C);
			__m128i red_channel_mask = _mm_set1_epi32(0x00007C00);
			__m128i red_offset = _mm_set1_epi32(0x00000180);
			__m128i alpha_channel_mask = _mm_set1_epi32(0x00008000);
			__m128i alpha_offset = _mm_set1_epi32(0x00000001);
			__m128i alpha_mask32 = _mm_set1_epi32(0xFF000000);

			pixels_blue =
				_mm_and_si128(pixels_low, blue_channel_mask);
			pixels_blue = _mm_slli_epi32(pixels_blue, 3);
			pixels_blue = _mm_add_epi32(pixels_blue, blue_offset);

			pixels_green =
				_mm_and_si128(pixels_low, green_channel_mask);
			pixels_green =
				_mm_add_epi32(pixels_green, green_offset);
			pixels_green = _mm_slli_epi32(pixels_green, 6);

			pixels_red =
				_mm_and_si128(pixels_low, red_channel_mask);
			pixels_red = _mm_add_epi32(pixels_red, red_offset);
			pixels_red = _mm_slli_epi32(pixels_red, 9);

			pixels_alpha =
				_mm_and_si128(pixels_low, alpha_channel_mask);
			pixels_alpha = _mm_srli_epi32(pixels_alpha, 15);
			pixels_alpha =
				_mm_sub_epi32(pixels_alpha, alpha_offset);
			pixels_alpha =
				_mm_andnot_si128(pixels_alpha, alpha_mask32);

			pixels_result = pixels_red;
			pixels_result =
				_mm_or_si128(pixels_result, pixels_alpha);
			pixels_result =
				_mm_or_si128(pixels_result, pixels_blue);
			pixels_result =
				_mm_or_si128(pixels_result, pixels_green);

			pixels_dest = (__m128i *)(out + x * sizeof(uint32_t));
			_mm_store_si128(pixels_dest, pixels_result);

			pixels_blue =
				_mm_and_si128(pixels_high, blue_channel_mask);
			pixels_blue = _mm_slli_epi32(pixels_blue, 3);
			pixels_blue = _mm_add_epi32(pixels_blue, blue_offset);

			pixels_green =
				_mm_and_si128(pixels_high, green_channel_mask);
			pixels_green =
				_mm_add_epi32(pixels_green, green_offset);
			pixels_green = _mm_slli_epi32(pixels_green, 6);

			pixels_red =
				_mm_and_si128(pixels_high, red_channel_mask);
			pixels_red = _mm_add_epi32(pixels_red, red_offset);
			pixels_red = _mm_slli_epi32(pixels_red, 9);

			pixels_alpha =
				_mm_and_si128(pixels_high, alpha_channel_mask);
			pixels_alpha = _mm_srli_epi32(pixels_alpha, 15);
			pixels_alpha =
				_mm_sub_epi32(pixels_alpha, alpha_offset);
			pixels_alpha =
				_mm_andnot_si128(pixels_alpha, alpha_mask32);

			pixels_result = pixels_red;
			pixels_result =
				_mm_or_si128(pixels_result, pixels_alpha);
			pixels_result =
				_mm_or_si128(pixels_result, pixels_blue);
			pixels_result =
				_mm_or_si128(pixels_result, pixels_green);

			pixels_dest =
				(__m128i *)(out + (x + 4) * sizeof(uint32_t));
			_mm_store_si128(pixels_dest, pixels_result);
		}
	}
}

static inline void copy_16bit_tex(PNOXINFO pNox, int cur_texture,
	UCHAR *data, UINT32 pitch)
{
	if (pNox->global_hook_info->format == DXGI_FORMAT_B5G5R5A1_UNORM) {
		copy_b5g5r5a1_tex(pNox, cur_texture, data, pitch);

	}
	else if (pNox->global_hook_info->format == DXGI_FORMAT_B5G6R5_UNORM) {
		copy_b5g6r5_tex(pNox, cur_texture, data, pitch);
	}
}

void ShowResultImage(HWND hWnd, Mat *frame) {
	HDC hdc = GetDC(GetDlgItem(hWnd, IDC_PREVIEW));
	HDC hdcMem = CreateCompatibleDC(hdc);
	HGDIOBJ oldBitmap;
	HBITMAP hBmp = CreateBitmap(frame->cols, frame->rows, 1, 8 * frame->channels(), frame->data);
	RECT rect;
	GetClientRect(GetDlgItem(hWnd, IDC_PREVIEW), &rect);

	SetStretchBltMode(hdc, HALFTONE);

	oldBitmap = SelectObject(hdcMem, hBmp);

	StretchBlt(hdc, 0, 0, rect.right - rect.left, rect.bottom - rect.top, hdcMem, 0, 0, frame->cols, frame->rows, SRCCOPY);

	SelectObject(hdcMem, oldBitmap);
	DeleteDC(hdcMem);
	ReleaseDC(hWnd, hdc);
	DeleteDC(hdc);
	DeleteObject(hBmp);
}

static void copy_shmem_tex(PNOXINFO pNox)
{
	int cur_texture;
	HANDLE mutex = NULL;
	uint32_t pitch;
	int next_texture;

	if (!pNox->shmem_data)
		return;

	cur_texture = pNox->shmem_data->last_tex;

	if (cur_texture < 0 || cur_texture > 1)
		return;

	next_texture = cur_texture == 1 ? 0 : 1;

	if (object_signalled(pNox->texture_mutexes[cur_texture])) {
		mutex = pNox->texture_mutexes[cur_texture];

	}
	else if (object_signalled(pNox->texture_mutexes[next_texture])) {
		mutex = pNox->texture_mutexes[next_texture];
		cur_texture = next_texture;
	}
	else {
		return;
	}
	if (pNox->renderData != NULL) {
		free(pNox->renderData);
	}
	pNox->renderData = (UCHAR *)malloc(pNox->pitch * pNox->cy);
	memcpy(pNox->renderData, pNox->texture_buffers[cur_texture],
		pNox->pitch * pNox->cy);
	if (selectedNox != -1) {
		if (pNox->hProcess == Noxs[selectedNox].hProcess) {
			uchar *rd = pNox->renderData;

			Mat frame = Mat::zeros(pNox->cy, pNox->cx, CV_8UC4);
			for (int i = 0; i < pNox->cy; i++) {
				for (int j = 0; j < pNox->cx; j++) {
					int n = pNox->pitch * i + j * 4;
					frame.at<Vec4b>(i, j) = Vec4b(rd[n], rd[n + 1], rd[n + 2], rd[n + 3]);
				}
			}
			ShowResultImage(hMainDlg, &frame);
			frame.release();
		}
	}
	free(pNox->renderData);
	pNox->renderData = NULL;
	
	ReleaseMutex(mutex);
}

static inline bool init_shmem_capture(PNOXINFO pNox)
{
	gs_color_format format;

	pNox->texture_buffers[0] = (UCHAR *)pNox->data + pNox->shmem_data->tex1_offset;
	pNox->texture_buffers[1] = (UCHAR *)pNox->data + pNox->shmem_data->tex2_offset;

	pNox->convert_16bit = (pNox->global_hook_info->format == DXGI_FORMAT_B5G5R5A1_UNORM ||
		pNox->global_hook_info->format == DXGI_FORMAT_B5G6R5_UNORM ? true : false);
	format = pNox->convert_16bit
		? GS_BGRA
		: convert_format(pNox->global_hook_info->format);

	copy_shmem_tex(pNox);
	return true;
}

static inline bool init_shtex_capture(PNOXINFO pNox)
{
	//DESTROYTEX(pNox->texture);
	//pNox->texture = gs_texture_open_shared(gc->shtex_data->tex_handle);

	//if (!pNox->texture) {
	//	warn("init_shtex_capture: failed to open shared handle");
	//	return false;
	//}

	return true;
}

static bool start_capture(PNOXINFO pNox)
{
	DbgOut("Starting capture/n");

	if (pNox->global_hook_info->type == CAPTURE_TYPE_MEMORY) {
		if (!init_shmem_capture(pNox)) {
			return false;
		}

		DbgOut("memory capture successful/n");
	}
	else {
		if (!init_shtex_capture(pNox)) {
			return false;
		}

		DbgOut("shared texture capture successful/n");
	}
	return true;
}

BOOL CALLBACK EnumChildWindows(HWND hwnd, LPARAM lParam)
{
	HANDLE hProcess = (HANDLE)lParam;

	HDC hdc = GetWindowDC(hwnd);
	HMODULE h = GetRemoteModuleHandle(hProcess, "opengl32.DLL");
	if (!h) return TRUE;
	DWORD addr = (DWORD)GetRemoteProcAddress(hProcess, h, "wglSwapBuffers", 0, FALSE);
	if (!!addr) {
		DWORD td;
		CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, (LPVOID)hdc, CREATE_SUSPENDED, &td); //0x0047C580
		HANDLE hh = OpenThread(THREAD_ALL_ACCESS, TRUE, td);
		ResumeThread(hh);
	}
	return TRUE;
}

BOOL GetTargetProcess()
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return(FALSE);
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		if (strstr(pe32.szExeFile, "NoxVMHandle.exe")) {
			hTargetProcessID = pe32.th32ProcessID;
			return(TRUE);
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return(TRUE);
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;
	WORD lw = LOWORD(wParam);

	switch (message)
	{
	case WM_INITDIALOG:
		{
			_beginthread(SetCurrentStatus, 0, hWnd);
			hMainDlg = hWnd;
			SetTimer(hWnd, 1, 30, NULL);
			LVCOLUMNW LvCol;
			HWND hList = GetDlgItem(hWnd, IDC_LIST1);

			SendMessage(hList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
				LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP | LVS_EX_TWOCLICKACTIVATE | LVS_EX_LABELTIP
				);

			memset(&LvCol, 0, sizeof(LvCol));
			LvCol.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
			LvCol.pszText = L"NoxPlayer Name";
			LvCol.cx = CompensateXDPI(186);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage(hList, LVM_INSERTCOLUMNW, 0, (LPARAM)&LvCol);
			
			LvCol.pszText = L"Status";
			LvCol.cx = CompensateXDPI(64);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage(hList, LVM_INSERTCOLUMNW, 2, (LPARAM)&LvCol);

			LvCol.pszText = L"ScreenShots";
			LvCol.cx = CompensateXDPI(128);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage(hList, LVM_INSERTCOLUMNW, 3, (LPARAM)&LvCol);
			EnableWindow(GetDlgItem(hWnd, IDOK), FALSE);
		}
		break;
	case WM_NOTIFY:
	case WM_COMMAND:
		if (lw == IDC_FLODER_BROWSER) {
			mainPath = BrowseFolder("");
			
			if (!mainPath.empty())
				SetWindowText(GetDlgItem(hWnd, IDC_PATH), mainPath.c_str());
		}
		if (lw == IDOK) {
			if (selectedNox == -1) break;
			Noxs[selectedNox].bStatus = !Noxs[selectedNox].bStatus;
		}
		if (lw == IDC_CLOSE) {
			exit(0);
		}
		break;
	case WM_TIMER:
		{
			EnumWindows(EnumWindowsProcMy, 0);
			PROCESSENTRY32 pe;
			if(GetTargetProcess()) {
				AddNox(hTargetProcessID);
			}
			UpdateNoxList(hWnd);
			if (Noxs.size() == 0) {
				break;
			}
			for (int i = 0; i < Noxs.size(); i++) {
				//EnumChildWindows(Noxs[i].hWnd, (LPARAM)Noxs[i].hProcess);
				if (Noxs[i].event_ready && object_signalled(Noxs[i].event_ready)) {
					DbgOut("capture initializing!/n");
					enum capture_result result = init_capture_data(&Noxs[i]);

					if (result == CAPTURE_SUCCESS)
						Noxs[i].capturing = start_capture(&Noxs[i]);
					else
						DbgOut("init_capture_data failed/n");
					
					if (result != CAPTURE_RETRY && !Noxs[i].capturing) {
						//stop_capture(gc);
					}
				}
				if (Noxs[i].active && object_signalled(Noxs[i].hProcess) == false) {
					copy_shmem_tex(&Noxs[i]);
				}
				

				
				//HMODULE h = GetRemoteModuleHandle(Noxs[i].hProcess, "dxgi.DLL");
				//DWORD addr = (DWORD)GetRemoteProcAddress(Noxs[i].hProcess, h, "CreateDXGIFactory2", 0, FALSE);
				
				
				//DWORD td;
				//CreateRemoteThread(Noxs[i].hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)0x0047C580, NULL, CREATE_SUSPENDED, &td); //0x0047C580
				//HANDLE hh = OpenThread(THREAD_ALL_ACCESS, TRUE, td);
				//ResumeThread(hh);
				
				//char buf[MAX_PATH];// = { 0x89, 0x04, 0x24, 0x89, 0x04, 0x24 };

				//SIZE_T lpNumberOfBytesWritten;
				//for (int n = 0; n < 850; n++) {
				//	WriteProcessMemory(Noxs[i].hProcess, (LPVOID)addr, buf, MAX_PATH, &lpNumberOfBytesWritten);
				//	addr += lpNumberOfBytesWritten;
				//}
			}
		}
		break;
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
			// TODO: Add any drawing code here...
		EndPaint(hWnd, &ps);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
