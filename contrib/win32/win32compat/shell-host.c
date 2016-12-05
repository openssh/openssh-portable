/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
* Primitive shell-host to support parsing of cmd.exe input and async IO redirection
*
* Author: Ray Heyes <ray.hayes@microsoft.com>
* PTY with ANSI emulation wrapper 
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Microsoft openssh win32 port
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <Windows.h>
#include <Strsafe.h>
#include <stdio.h>
#include <io.h>

#define MAX_CONSOLE_COLUMNS 9999
#define MAX_CONSOLE_ROWS 9999
#define MAX_CMD_LEN 8191 // msdn
#define WM_APPEXIT WM_USER+1
#define MAX_EXPECTED_BUFFER_SIZE 1024

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING  0x4
#endif

#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif

typedef BOOL (WINAPI *__t_SetCurrentConsoleFontEx)(
        _In_ HANDLE               hConsoleOutput,
        _In_ BOOL                 bMaximumWindow,
        _In_ PCONSOLE_FONT_INFOEX lpConsoleCurrentFontEx
        );
__t_SetCurrentConsoleFontEx __SetCurrentConsoleFontEx;

typedef BOOL (WINAPI *__t_UnhookWinEvent)(
        _In_ HWINEVENTHOOK hWinEventHook
        );
__t_UnhookWinEvent __UnhookWinEvent;

typedef HWINEVENTHOOK (WINAPI *__t_SetWinEventHook)(
        _In_ UINT         eventMin,
        _In_ UINT         eventMax,
        _In_ HMODULE      hmodWinEventProc,
        _In_ WINEVENTPROC lpfnWinEventProc,
        _In_ DWORD        idProcess,
        _In_ DWORD        idThread,
        _In_ UINT         dwflags
        );
__t_SetWinEventHook __SetWinEventHook;


typedef struct consoleEvent {
    DWORD event;
    HWND  hwnd;
    LONG  idObject;
    LONG  idChild;
    void* prior;
    void* next;
} consoleEvent;

struct key_translation
{
    char incoming[5];
    int vk;
    char outgoing[1];
} key_translation;

struct key_translation keys[] = { 
    { "\x1b",       VK_ESCAPE,  "\x1b" },
    { "\r",         VK_RETURN,  "\r" },
    { "\b",         VK_BACK,    "\b" },
    { "\x7f",       VK_BACK,    "\x7f" },
    { "\t",         VK_TAB,     "\t" },
    { "\x1b[A",     VK_UP,       0 },
    { "\x1b[B",     VK_DOWN,     0 },
    { "\x1b[C",     VK_RIGHT,    0 },
    { "\x1b[D",     VK_LEFT,     0 },
    { "\x1b[1~",    VK_HOME,     0 },
    { "\x1b[2~",    VK_INSERT,   0 },
    { "\x1b[3~",    VK_DELETE,   0 },
    { "\x1b[4~",    VK_END,      0 },
    { "\x1b[5~",    VK_PRIOR,    0 },
    { "\x1b[6~",    VK_NEXT,     0 },
    { "\x1b[11~",   VK_F1,       0 },
    { "\x1b[12~",   VK_F2,       0 },
    { "\x1b[13~",   VK_F3,       0 },
    { "\x1b[14~",   VK_F4,       0 },
    { "\x1b[15~",   VK_F5,       0 },
    { "\x1b[17~",   VK_F6,       0 },
    { "\x1b[18~",   VK_F7,       0 },
    { "\x1b[19~",   VK_F8,       0 },
    { "\x1b[20~",   VK_F9,       0 },
    { "\x1b[21~",   VK_F10,      0 },
    { "\x1b[23~",   VK_F11,      0 },
    { "\x1b[24~",   VK_F12,      0 }
};

consoleEvent* head = NULL;
consoleEvent* tail = NULL;

BOOL bRet = FALSE;
BOOL bNoScrollRegion = FALSE;
BOOL bStartup = TRUE;
BOOL bAnsi = FALSE;
BOOL bHookEvents = FALSE;

HANDLE child_out = INVALID_HANDLE_VALUE;
HANDLE child_in = INVALID_HANDLE_VALUE;
HANDLE child_err = INVALID_HANDLE_VALUE;
HANDLE pipe_in = INVALID_HANDLE_VALUE;
HANDLE pipe_out = INVALID_HANDLE_VALUE;
HANDLE pipe_err = INVALID_HANDLE_VALUE;
HANDLE child = INVALID_HANDLE_VALUE;
HANDLE hConsoleBuffer = INVALID_HANDLE_VALUE;

HANDLE monitor_thread = INVALID_HANDLE_VALUE;
HANDLE io_thread = INVALID_HANDLE_VALUE;
HANDLE ux_thread = INVALID_HANDLE_VALUE;

DWORD hostProcessId = 0;
DWORD hostThreadId = 0;
DWORD childProcessId = 0;
DWORD dwStatus = 0;
DWORD currentLine = 0;
DWORD lastLineLength = 0;

UINT cp = 0;

UINT ViewPortY = 0;
UINT lastViewPortY = 0;

BOOL bFullScreen = FALSE;
BOOL bUseAnsiEmulation = TRUE;

UINT savedViewPortY = 0;
UINT savedLastViewPortY = 0;

DWORD in_cmd_len = 0;
char in_cmd[MAX_CMD_LEN];

CRITICAL_SECTION criticalSection;

CONSOLE_SCREEN_BUFFER_INFOEX  consoleInfo;
CONSOLE_SCREEN_BUFFER_INFOEX  nextConsoleInfo;
STARTUPINFO inputSi;

#define GOTO_CLEANUP_ON_FALSE(exp) do {			\
	ret = (exp);					            \
	if (ret == FALSE)				            \
		goto cleanup;				            \
} while(0)						                \

#define GOTO_CLEANUP_ON_ERR(exp) do {			\
	if ((exp) != 0)				                \
		goto cleanup;				            \
} while(0)						                \

// Console keystroke handling
void SendKeyStroke(HANDLE hInput, int keyStroke, char character)
{
    DWORD wr = 0;
    INPUT_RECORD ir;

    ir.EventType = KEY_EVENT;
    ir.Event.KeyEvent.bKeyDown = TRUE;
    ir.Event.KeyEvent.wRepeatCount = 1;
    ir.Event.KeyEvent.wVirtualKeyCode = keyStroke;
    ir.Event.KeyEvent.wVirtualScanCode = 0;
    ir.Event.KeyEvent.dwControlKeyState = 0;
    ir.Event.KeyEvent.uChar.UnicodeChar = 0;
    if(character != 0)
        ir.Event.KeyEvent.uChar.AsciiChar = character;

    WriteConsoleInputA(hInput, &ir, 1, &wr);

    ir.Event.KeyEvent.bKeyDown = FALSE;
    WriteConsoleInputA(hInput, &ir, 1, &wr);
}

void ProcessIncomingKeys(char * ansikey) {
    int nKey = 0;
    int index = ARRAYSIZE(keys);

    while (nKey < index) {
        if (strcmp(ansikey, keys[nKey].incoming) == 0) {
            SendKeyStroke(child_in, keys[nKey].vk, keys[nKey].outgoing[0]);
            break;
        }
        else
            nKey++;
    }

    if (nKey == index) {
        SendKeyStroke(child_in, 0, ansikey[0]);
    }
}

// VT output routines
void SendLF(HANDLE hInput) {
    DWORD wr = 0;

    if (bUseAnsiEmulation)
        WriteFile(hInput, "\n", 1, &wr, NULL);
}

void SendClearScreen(HANDLE hInput) {
    DWORD wr = 0;

    if (bUseAnsiEmulation)
        WriteFile(hInput, "\033[2J", 4, &wr, NULL);
}

void SendClearScreenFromCursor(HANDLE hInput) {
    DWORD wr = 0;

    if (bUseAnsiEmulation)
        WriteFile(hInput, "\033[1J", 4, &wr, NULL);
}

void SendHideCursor(HANDLE hInput) {
    DWORD wr = 0;

    if (bUseAnsiEmulation)
        WriteFile(hInput, "\033[?25l", 6, &wr, NULL);
}

void SendShowCursor(HANDLE hInput) {
    DWORD wr = 0;

    if (bUseAnsiEmulation)
        WriteFile(hInput, "\033[?25h", 6, &wr, NULL);
}

void SendCursorPositionRequest(HANDLE hInput) {
    DWORD wr = 0;

    if (bUseAnsiEmulation)
        WriteFile(hInput, "\033[6n", 4, &wr, NULL);
}

void SendSetCursor(HANDLE hInput, int X, int Y) {

    DWORD wr = 0;
    DWORD out = 0;

    char formatted_output[255];

    out = _snprintf_s(formatted_output, sizeof(formatted_output), _TRUNCATE, "\033[%d;%dH", Y, X);
    if (bUseAnsiEmulation)
        WriteFile(hInput, formatted_output, out, &wr, NULL);
}

void SendVerticalScroll(HANDLE hInput, int lines) {

    DWORD wr = 0;
    DWORD out = 0;
    char formatted_output[255];

    LONG vn = abs(lines);

    if (lines > 0) {

        out = snprintf(formatted_output, sizeof(formatted_output), "\033[%dT", vn);

        if (bUseAnsiEmulation)
            WriteFile(hInput, formatted_output, out, &wr, NULL);
    }
    // Not supporting the [S at the moment.
}

void SendHorizontalScroll(HANDLE hInput, int cells) {

    DWORD wr = 0;
    DWORD out = 0;
    char formatted_output[255];

    out = snprintf(formatted_output, sizeof(formatted_output), "\033[%dG", cells);

    if (bUseAnsiEmulation)
        WriteFile(hInput, formatted_output, out, &wr, NULL);
}

void SendCharacter(HANDLE hInput, WORD attributes, wchar_t character) {

    DWORD wr = 0;
    DWORD out = 0;
    DWORD current = 0;

    char formatted_output[2048];

    static WORD pattributes = 0;

    USHORT Color = 0;
	ULONG Status = 0;
	
	PSTR Next;
    size_t SizeLeft;

    if (!character)
        return;

    Next = formatted_output;
    SizeLeft = sizeof formatted_output;

	//
	// Handle the foreground intensity
	//
	if ((attributes & FOREGROUND_INTENSITY) != 0) {
		Color = 1;
	}
	else {
		Color = 0;
	}

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, "\033[%u", Color);

    //
    // Handle the background intensity
    //
    if ((attributes & BACKGROUND_INTENSITY) != 0) {
        Color = 1;
    }
    else {
        Color = 39;
    }

    StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

    //
    // Handle the underline
    //
    if ((attributes & COMMON_LVB_UNDERSCORE) != 0) {
        Color = 4;
    }
    else {
        Color = 24;
    }

    StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

    //
    // Handle reverse video
    //
    if ((attributes & COMMON_LVB_REVERSE_VIDEO) != 0) {
        Color = 7;
    }
    else {
        Color = 27;
    }

    StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

    //
    // Add background and foreground colors to buffer.
    //
    Color = 30 +
        4 * ((attributes & FOREGROUND_BLUE) != 0) +
        2 * ((attributes & FOREGROUND_GREEN) != 0) +
        1 * ((attributes & FOREGROUND_RED) != 0);

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

    Color = 40 +
        4 * ((attributes & BACKGROUND_BLUE) != 0) +
        2 * ((attributes & BACKGROUND_GREEN) != 0) +
        1 * ((attributes & BACKGROUND_RED) != 0);

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, "m", Color);

    if (bUseAnsiEmulation && attributes != pattributes)
        WriteFile(hInput, formatted_output, (Next - formatted_output), &wr, NULL);

    // East asian languages have 2 bytes for each character, only use the first
    if (!(attributes & COMMON_LVB_TRAILING_BYTE))
    {
        int nSize = WideCharToMultiByte(CP_UTF8,
            0,
            &character,
            1,
            Next,
            10,
            NULL,
            NULL);

        if(nSize > 0)
            WriteFile(hInput, Next, nSize, &wr, NULL);
    }

    pattributes = attributes;
}

void SendBuffer(HANDLE hInput, CHAR_INFO *buffer, DWORD bufferSize) {
	
    if (bufferSize <= 0)
        return;

    for (DWORD i = 0; i < bufferSize; i++)
    { 
        SendCharacter(hInput, buffer[i].Attributes, buffer[i].Char.UnicodeChar);
    }
}

void CalculateAndSetCursor(HANDLE hInput, UINT aboveTopLine, UINT viewPortHeight, UINT x, UINT y) {

    SendSetCursor(pipe_out, x + 1, y + 1);
    currentLine = y;
}

void SizeWindow(HANDLE hInput) {

    SMALL_RECT srWindowRect;
    COORD coordScreen;
    BOOL bSuccess = FALSE;

    // The input window does not scroll currently to ease calculations
    // on the paint/draw.
    bNoScrollRegion = TRUE;

    // Set the default font to Consolas
    CONSOLE_FONT_INFOEX matchingFont;
    matchingFont.cbSize = sizeof(matchingFont);
    matchingFont.nFont = 0;
    matchingFont.dwFontSize.X = 0;
    matchingFont.dwFontSize.Y = 16;
    matchingFont.FontFamily = FF_DONTCARE;
    matchingFont.FontWeight = FW_NORMAL;
    wcscpy(matchingFont.FaceName, L"Consolas");

    bSuccess = __SetCurrentConsoleFontEx(child_out, FALSE, &matchingFont);

    // This information is the live screen 
    ZeroMemory(&consoleInfo, sizeof(consoleInfo));
    consoleInfo.cbSize = sizeof(consoleInfo);

    bSuccess = GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

    // Get the largest size we can size the console window to.
    coordScreen = GetLargestConsoleWindowSize(child_out);

    // Define the new console window size and scroll position.
    if (inputSi.dwXCountChars == 0 || inputSi.dwYCountChars == 0) {
        inputSi.dwXCountChars = 80;
        inputSi.dwYCountChars = 25;
    }

    srWindowRect.Right = (SHORT)(min(inputSi.dwXCountChars, coordScreen.X) - 1);
    srWindowRect.Bottom = (SHORT)(min(inputSi.dwYCountChars, coordScreen.Y) - 1);
    srWindowRect.Left = srWindowRect.Top = (SHORT)0;

    /// Define the new console buffer size to be the maximum possible.
    coordScreen.X = 100;
    coordScreen.Y = 9999;

    if (SetConsoleWindowInfo(child_out, TRUE, &srWindowRect)) {

        bSuccess = SetConsoleScreenBufferSize(child_out, coordScreen);
    }
    else {
        if (SetConsoleScreenBufferSize(child_out, coordScreen)) {

            bSuccess = SetConsoleWindowInfo(child_out, TRUE, &srWindowRect);
        }

    }

    bSuccess = GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);
}

// End of VT output routines

DWORD WINAPI MonitorChild(_In_ LPVOID lpParameter) {
    WaitForSingleObject(child, INFINITE);
    PostThreadMessage(hostThreadId, WM_APPEXIT, 0, 0);
    return 0;
}

DWORD ProcessEvent(void *p) {

    char f[255];
    wchar_t chUpdate;

    WORD  wAttributes;
    WORD  wX;
    WORD  wY;

    DWORD dwProcessId;
    DWORD wr = 0;
    DWORD dwMode;

    DWORD event;
    HWND hwnd;
    LONG idObject;
    LONG idChild;

    if (!p)
    {
        return ERROR_INVALID_PARAMETER;
    }

    consoleEvent* current = (consoleEvent *)p;

    if(current) { 
        event = current->event;
        hwnd = current->hwnd;
        idObject = current->idObject;
        idChild = current->idChild;
    }
    else {
        return ERROR_INVALID_PARAMETER;
    }

    if (event < EVENT_CONSOLE_CARET || event > EVENT_CONSOLE_LAYOUT)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (child_out == INVALID_HANDLE_VALUE || child_out == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    GetWindowThreadProcessId(hwnd, &dwProcessId);

    if (childProcessId != dwProcessId)
    {
        return ERROR_SUCCESS;
    }

    ZeroMemory(&consoleInfo, sizeof(consoleInfo));
    consoleInfo.cbSize = sizeof(consoleInfo);

    GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

    UINT viewPortHeight = consoleInfo.srWindow.Bottom - consoleInfo.srWindow.Top + 1;
    UINT viewPortWidth = consoleInfo.srWindow.Right - consoleInfo.srWindow.Left + 1;

    switch (event) {
    case EVENT_CONSOLE_CARET:
    {
        COORD co;

        if (idObject == CONSOLE_CARET_SELECTION) {
            co.X = HIWORD(idChild);
            co.Y = LOWORD(idChild);
        }
        else {
            co.X = HIWORD(idChild);
            co.Y = LOWORD(idChild);
        }

        break;
    }
    case EVENT_CONSOLE_UPDATE_REGION:
    {
        SMALL_RECT readRect;

        readRect.Top = HIWORD(idObject);
        readRect.Left = LOWORD(idObject);
        readRect.Bottom = HIWORD(idChild);
        readRect.Right = LOWORD(idChild);

        // Detect a "cls" (Windows).
        if (!bStartup &&
            (readRect.Top == consoleInfo.srWindow.Top || readRect.Top == nextConsoleInfo.srWindow.Top))
        {
            BOOL isClearCommand = FALSE;
            isClearCommand = (consoleInfo.dwSize.X == readRect.Right + 1) && (consoleInfo.dwSize.Y == readRect.Bottom + 1);

            // If cls then inform app to clear its buffers and return.
            if (isClearCommand)
            {
                SendClearScreen(pipe_out);
                ViewPortY = 0;
                lastViewPortY = 0;

                return ERROR_SUCCESS;
            }
        }

        // Figure out the buffer size
        COORD coordBufSize;
        coordBufSize.Y = readRect.Bottom - readRect.Top + 1;
        coordBufSize.X = readRect.Right - readRect.Left + 1;

        // Security check:  the maximum screen buffer size is 9999 columns x 9999 lines so check
        // the computed buffer size for overflow.  since the X and Y in the COORD structure
        // are shorts they could be negative.
        if (coordBufSize.X < 0 || coordBufSize.X > MAX_CONSOLE_COLUMNS ||
            coordBufSize.Y < 0 || coordBufSize.Y > MAX_CONSOLE_ROWS)
        {
            return ERROR_INVALID_PARAMETER;
        }

        // Compute buffer size
        DWORD bufferSize = coordBufSize.X * coordBufSize.Y;

        if (bufferSize > MAX_EXPECTED_BUFFER_SIZE) {

            if (!bStartup) {
                SendClearScreen(pipe_out);
                ViewPortY = 0;
                lastViewPortY = 0;
            }

            return ERROR_SUCCESS;
        }

        // Create the screen scrape buffer
        CHAR_INFO *pBuffer = (PCHAR_INFO)malloc(sizeof(CHAR_INFO) * bufferSize);

        if (!pBuffer)
        {
            return ERROR_INSUFFICIENT_BUFFER;
        }

        // The top left destination cell of the temporary buffer is row 0, col 0.
        COORD coordBufCoord;
        coordBufCoord.X = 0;
        coordBufCoord.Y = 0;

        // Copy the block from the screen buffer to the temp. buffer.
        if (!ReadConsoleOutput(child_out, pBuffer, coordBufSize, coordBufCoord, &readRect))
        {
            DWORD dwError = GetLastError();

            free(pBuffer);
            return dwError;
        }

        if (readRect.Top > currentLine)
            for(SHORT n = currentLine; n < readRect.Top; n++)
                SendLF(pipe_out);

        // Set cursor location based on the reported location from the message.
        CalculateAndSetCursor(pipe_out, ViewPortY, viewPortHeight, readRect.Left, 
            readRect.Top);

        // Send the entire block.
        SendBuffer(pipe_out, pBuffer, bufferSize);

        lastViewPortY = ViewPortY;
        lastLineLength = readRect.Left;

        free(pBuffer);

        break;
    }
    case EVENT_CONSOLE_UPDATE_SIMPLE:
    {
        chUpdate = LOWORD(idChild);
        wAttributes = HIWORD(idChild);
        wX = LOWORD(idObject);
        wY = HIWORD(idObject);

        // Set cursor location based on the reported location from the message.
        CalculateAndSetCursor(pipe_out, ViewPortY, viewPortHeight, wX, wY);

        // Send the one character. Note that a CR doesn't end up here.
        SendCharacter(pipe_out, wAttributes, chUpdate);

        break;
    }
    case EVENT_CONSOLE_UPDATE_SCROLL:
    {
        DWORD out = 0;
        LONG vd = idChild;
        LONG hd = idObject;

        LONG vn = abs(vd);

        if (vd > 0) {
            if(ViewPortY > 0)
                ViewPortY -= vn;
        }
        else {
            ViewPortY += vn;
        }

        break;
    }
    case EVENT_CONSOLE_LAYOUT:
    {
        if (consoleInfo.dwMaximumWindowSize.X == consoleInfo.dwSize.X &&
            consoleInfo.dwMaximumWindowSize.Y == consoleInfo.dwSize.Y &&
           (consoleInfo.dwCursorPosition.X == 0 && consoleInfo.dwCursorPosition.Y == 0))
        {
            // Screen has switched to fullscreen mode
            SendClearScreen(pipe_out);

            savedViewPortY = ViewPortY;
            savedLastViewPortY = lastViewPortY;

            ViewPortY = 0;
            lastViewPortY = 0;;

            bFullScreen = TRUE;
        }
        else
        {
            // Leave full screen mode if applicable
            if (bFullScreen) {
                SendClearScreen(pipe_out);

                ViewPortY = savedViewPortY;
                lastViewPortY = savedLastViewPortY;
                bFullScreen = FALSE;
            }
        }

        break;
    }
    }

    ZeroMemory(&consoleInfo, sizeof(consoleInfo));
    consoleInfo.cbSize = sizeof(consoleInfo);

    GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

    return ERROR_SUCCESS;
}

DWORD WINAPI ProcessEventQueue(LPVOID p) {

    static SHORT lastX = 0;
    static SHORT lastY = 0;

    while (1) {

        while (head) {

            EnterCriticalSection(&criticalSection);

            consoleEvent* current = head;

            if (current) {
                if (current->next)
                {
                    head = current->next;
                    head->prior = NULL;
                }
                else
                {
                    head = NULL;
                    tail = NULL;
                }
            }

            LeaveCriticalSection(&criticalSection);

            if (current)
            {
                ProcessEvent(current);
                free(current);
            }
        }

        if (child_in  != INVALID_HANDLE_VALUE && child_in  != NULL &&
            child_out != INVALID_HANDLE_VALUE && child_out != NULL)
        {
            DWORD dwInputMode;
            DWORD dwOutputMode;

            if (GetConsoleMode(child_in, &dwInputMode) && GetConsoleMode(child_out, &dwOutputMode)) {
                if (((dwOutputMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == ENABLE_VIRTUAL_TERMINAL_PROCESSING) &&
                    ((dwInputMode & ENABLE_VIRTUAL_TERMINAL_INPUT) == ENABLE_VIRTUAL_TERMINAL_INPUT))
                {
                    bAnsi = TRUE;
                }
                else {
                    bAnsi = FALSE;
                }
            }

            ZeroMemory(&consoleInfo, sizeof(consoleInfo));
            consoleInfo.cbSize = sizeof(consoleInfo);

            // This information is the live buffer that's currently in use.
            GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

            // Set the cursor to the last known good location according to the live buffer.
            if (lastX != consoleInfo.dwCursorPosition.X ||
                lastY != consoleInfo.dwCursorPosition.Y) {

                SendSetCursor(pipe_out, consoleInfo.dwCursorPosition.X + 1,
                    consoleInfo.dwCursorPosition.Y + 1);
            }

            lastX = consoleInfo.dwCursorPosition.X;
            lastY = consoleInfo.dwCursorPosition.Y;
        }

        Sleep(100);
    }

    return 0;
}

void QueueEvent(
    DWORD event,
    HWND hwnd,
    LONG idObject,
    LONG idChild) {

    consoleEvent* current = NULL;

    EnterCriticalSection(&criticalSection);

    current = malloc(sizeof(consoleEvent));

    if (current) {
        if (!head) {
            current->event = event;
            current->hwnd = hwnd;
            current->idChild = idChild;
            current->idObject = idObject;

            // No links head == tail
            current->next = NULL;
            current->prior = NULL;

            head = current;
            tail = current;
        }
        else {
            current->event = event;
            current->hwnd = hwnd;
            current->idChild = idChild;
            current->idObject = idObject;

            // Current tail points to new tail
            tail->next = current;

            // New tail points to old tail
            current->prior = tail;
            current->next = NULL;

            // Update the tail pointer to the new
            // last event
            tail = current;
        }
    }

    LeaveCriticalSection(&criticalSection);

    return;
}

DWORD WINAPI ProcessPipes(LPVOID p) {

    BOOL ret;
    DWORD dwStatus;

    /* process data from pipe_in and route appropriately */
    while (1) {
        char buf[128];
        ZeroMemory(buf, 128);

        DWORD rd = 0, wr = 0, i = -1;

        GOTO_CLEANUP_ON_FALSE(ReadFile(pipe_in, buf, 128, &rd, NULL));

        bStartup = FALSE;

        while (++i < rd) {

            INPUT_RECORD ir;

	        if (buf[i] == 3) {/*Ctrl+C - Raise Ctrl+C*/
		        GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
		        continue;
	        }

            if (bAnsi) {
                ir.EventType = KEY_EVENT;
                ir.Event.KeyEvent.bKeyDown = TRUE;
                ir.Event.KeyEvent.wRepeatCount = 1;
                ir.Event.KeyEvent.wVirtualKeyCode = 0;
                ir.Event.KeyEvent.wVirtualScanCode = 0;
                ir.Event.KeyEvent.uChar.AsciiChar = buf[i];
                ir.Event.KeyEvent.dwControlKeyState = 0;
                WriteConsoleInputA(child_in, &ir, 1, &wr);

                ir.Event.KeyEvent.bKeyDown = FALSE;
                WriteConsoleInputA(child_in, &ir, 1, &wr);
            }
            else {
                ProcessIncomingKeys(buf);
                break;
            }
        }
    }

cleanup:
    dwStatus = GetLastError();

    return 0;
}

void CALLBACK ConsoleEventProc(HWINEVENTHOOK hWinEventHook,
    DWORD event,
    HWND hwnd,
    LONG idObject,
    LONG idChild,
    DWORD dwEventThread,
    DWORD dwmsEventTime)
{
    QueueEvent(event, hwnd, idObject, idChild);
}

DWORD ProcessMessages(void* p)
{
    BOOL ret;
    DWORD dwMode;
    DWORD dwStatus;
    SECURITY_ATTRIBUTES sa;
    MSG msg;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    while (child_in == (HANDLE)-1)
    {
        child_in = CreateFile(TEXT("CONIN$"), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa, OPEN_EXISTING, 0, NULL);
    }

    if (child_in == (HANDLE)-1)
        goto cleanup;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    while (child_out == (HANDLE)-1)
    {
        child_out = CreateFile(TEXT("CONOUT$"), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa, OPEN_EXISTING, 0, NULL);
    }

    if (child_out == (HANDLE)-1)
        goto cleanup;

    child_err = child_out;

    SizeWindow(child_out);

    // Get the current buffer information after all the adjustments.
    GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

    // Loop for the console output events
    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (msg.message == WM_APPEXIT)
        {
            break;
        }
        else
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);            
        }
    }

cleanup:
    dwStatus = GetLastError();

    if (child_in != INVALID_HANDLE_VALUE)
        CloseHandle(child_in);
    if (child_out != INVALID_HANDLE_VALUE)
        CloseHandle(child_out);
    return 0;
}

int start_with_pty(int ac, wchar_t **av) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    wchar_t cmd[MAX_CMD_LEN];
    SECURITY_ATTRIBUTES sa;
    BOOL ret;
    DWORD dwThreadId;
    DWORD dwMode;
    DWORD dwStatus;
    HANDLE hEventHook = NULL;
    HMODULE hm_kernel32 = NULL, hm_user32 = NULL;

    if ((hm_kernel32 = LoadLibraryW(L"kernel32.dll")) == NULL ||
        (hm_user32 = LoadLibraryW(L"user32.dll")) == NULL ||
        (__SetCurrentConsoleFontEx = (__t_SetCurrentConsoleFontEx)GetProcAddress(hm_kernel32, "SetCurrentConsoleFontEx")) == NULL ||
        (__UnhookWinEvent = (__t_UnhookWinEvent)GetProcAddress(hm_user32, "UnhookWinEvent")) == NULL ||
        (__SetWinEventHook = (__t_SetWinEventHook)GetProcAddress(hm_user32, "SetWinEventHook")) == NULL) {
        printf("cannot support a pseudo terminal. \n");
        return -1;
    }

    pipe_in  = GetStdHandle(STD_INPUT_HANDLE);
    pipe_out = GetStdHandle(STD_OUTPUT_HANDLE);
    pipe_err = GetStdHandle(STD_ERROR_HANDLE);

    /* copy pipe handles passed through std io*/
    if ((pipe_in  == INVALID_HANDLE_VALUE)
     || (pipe_out == INVALID_HANDLE_VALUE)
     || (pipe_err == INVALID_HANDLE_VALUE))
        return -1;

    cp = GetConsoleCP();

    /* Windows PTY sends cursor positions in absolute coordinates starting from <0,0>
     * We send a clear screen upfront to simplify client */
    SendClearScreen(pipe_out);

    ZeroMemory(&inputSi, sizeof(STARTUPINFO));
    GetStartupInfo(&inputSi);

    memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
    sa.bInheritHandle = TRUE;

    /* WM_APPEXIT */
    hostThreadId = GetCurrentThreadId();
    hostProcessId = GetCurrentProcessId();

    InitializeCriticalSection(&criticalSection);

    hEventHook = __SetWinEventHook(EVENT_CONSOLE_CARET, EVENT_CONSOLE_LAYOUT, NULL,
        ConsoleEventProc, 0, 0, WINEVENT_OUTOFCONTEXT);

    memset(&si, 0, sizeof(STARTUPINFO));
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    // Copy our parent buffer sizes
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = 0;

    /* disable inheritance on pipe_in*/
    GOTO_CLEANUP_ON_FALSE(SetHandleInformation(pipe_in, HANDLE_FLAG_INHERIT, 0));

    /*TODO - pick this up from system32*/
    cmd[0] = L'\0';
    if (ac)
	GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, L"cmd.exe"));

    ac--;
    av++;
    if (ac)
        GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, L" /c"));
    while (ac) {
        GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, L" "));
        GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, *av));
        ac--;
        av++;
    }

    SetConsoleCtrlHandler(NULL, FALSE);
    GOTO_CLEANUP_ON_FALSE(CreateProcess(NULL, cmd, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, 
        NULL, NULL, &si, &pi));
    childProcessId = pi.dwProcessId;

    FreeConsole();
    Sleep(20);
    while (!AttachConsole(pi.dwProcessId))
    {
        DWORD exit_code;
        if (GetExitCodeProcess(pi.hProcess, &exit_code) && exit_code != STILL_ACTIVE)
                break;
        Sleep(100);
    }

    /* monitor child exist */
    child = pi.hProcess;
    monitor_thread = CreateThread(NULL, 0, MonitorChild, NULL, 0, NULL);
    if (monitor_thread == INVALID_HANDLE_VALUE)
        goto cleanup;

    /* disable Ctrl+C hander in this process*/
    SetConsoleCtrlHandler(NULL, TRUE);

    io_thread = CreateThread(NULL, 0, ProcessPipes, NULL, 0, NULL);
    if (io_thread == INVALID_HANDLE_VALUE)
        goto cleanup;

    ux_thread = CreateThread(NULL, 0, ProcessEventQueue, NULL, 0, NULL);
    if (ux_thread == INVALID_HANDLE_VALUE)
        goto cleanup;

    ProcessMessages(NULL);

cleanup:
    dwStatus = GetLastError();

    DeleteCriticalSection(&criticalSection);

    if (child != INVALID_HANDLE_VALUE)
        TerminateProcess(child, 0);
    if (monitor_thread != INVALID_HANDLE_VALUE)
        WaitForSingleObject(monitor_thread, INFINITE);
    if (ux_thread != INVALID_HANDLE_VALUE)
        TerminateThread(ux_thread, S_OK);
    if (hEventHook)
        __UnhookWinEvent(hEventHook);

    FreeConsole();

    return 0;
}

HANDLE child_pipe_read;
HANDLE child_pipe_write;
DWORD WINAPI MonitorChild_nopty(
        _In_ LPVOID lpParameter
        ) {
        WaitForSingleObject(child, INFINITE);
        CloseHandle(pipe_in);
        //printf("XXXX CHILD PROCESS DEAD XXXXX");
        return 0;
}

int start_withno_pty(int ac, wchar_t **av) {
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        wchar_t cmd[MAX_CMD_LEN];
        SECURITY_ATTRIBUTES sa;
        BOOL ret;

        pipe_in = GetStdHandle(STD_INPUT_HANDLE);
        pipe_out = GetStdHandle(STD_OUTPUT_HANDLE);
        pipe_err = GetStdHandle(STD_ERROR_HANDLE);

        /* copy pipe handles passed through std io*/
        if ((pipe_in == INVALID_HANDLE_VALUE)
                || (pipe_out == INVALID_HANDLE_VALUE)
                || (pipe_err == INVALID_HANDLE_VALUE))
                return -1;

        memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
        sa.bInheritHandle = TRUE;
        if (!CreatePipe(&child_pipe_read, &child_pipe_write, &sa, 128))
                return -1;

        memset(&si, 0, sizeof(STARTUPINFO));
        memset(&pi, 0, sizeof(PROCESS_INFORMATION));

        si.cb = sizeof(STARTUPINFO);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = child_pipe_read;
        si.hStdOutput = pipe_out;
        si.hStdError = pipe_err;

        /* disable inheritance on child_pipe_write and pipe_in*/
        GOTO_CLEANUP_ON_FALSE(SetHandleInformation(pipe_in, HANDLE_FLAG_INHERIT, 0));
        GOTO_CLEANUP_ON_FALSE(SetHandleInformation(child_pipe_write, HANDLE_FLAG_INHERIT, 0));

        /*TODO - pick this up from system32*/
        cmd[0] = L'\0';
        GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, L"cmd.exe"));
        ac -= 2;
        av += 2;
        if (ac)
                GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, L" /c"));
        while (ac) {
                GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, L" "));
                GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, *av));
                ac--;
                av++;
        }

        GOTO_CLEANUP_ON_FALSE(CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi));

        /* close unwanted handles*/
        CloseHandle(child_pipe_read);
        child_pipe_read = INVALID_HANDLE_VALUE;

        child = pi.hProcess;
        /* monitor child exist */
        monitor_thread = CreateThread(NULL, 0, MonitorChild_nopty, NULL, 0, NULL);
        if (monitor_thread == INVALID_HANDLE_VALUE)
                goto cleanup;

        /* disable Ctrl+C hander in this process*/
        SetConsoleCtrlHandler(NULL, TRUE);

        /* process data from pipe_in and route appropriately */
        while (1) {
                char buf[128];
                DWORD rd = 0, wr = 0, i = 0;
                GOTO_CLEANUP_ON_FALSE(ReadFile(pipe_in, buf, 128, &rd, NULL));

                while (i < rd) {

                        /* skip arrow keys */
                        if ((rd - i >= 3) && (buf[i] == '\033') && (buf[i + 1] == '[')
                                && (buf[i + 2] >= 'A') && (buf[i + 2] <= 'D')) {
                                i += 3;
                                continue;
                        }

                        /* skip tab */
                        if (buf[i] == '\t') {
                                i++;
                                continue;
                        }

                        // Ctrl +C
                        if (buf[i] == '\003') {
                                GOTO_CLEANUP_ON_FALSE(GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0));
                                in_cmd_len = 0;
                                i++;
                                continue;
                        }

                        // for backspace, we need to send space and another backspace for visual erase
                        if (buf[i] == '\b') {
                                if (in_cmd_len > 0) {
                                        GOTO_CLEANUP_ON_FALSE(WriteFile(pipe_out, "\b \b", 3, &wr, NULL));
                                        in_cmd_len--;
                                }
                                i++;
                                continue;
                        }

                        //for CR and LF
                        if ((buf[i] == '\r') || (buf[i] == '\n')) {

                                /* TODO - do a much accurate mapping */
                                GOTO_CLEANUP_ON_FALSE(WriteFile(pipe_out, buf + i, 1, &wr, NULL));
                                if ((buf[i] == '\r') && ((i == rd - 1) || (buf[i + 1] != '\n'))) {
                                        buf[i] = '\n';
                                        GOTO_CLEANUP_ON_FALSE(WriteFile(pipe_out, buf + i, 1, &wr, NULL));
                                }
                                in_cmd[in_cmd_len] = buf[i];
                                in_cmd_len++;
                                GOTO_CLEANUP_ON_FALSE(WriteFile(child_pipe_write, in_cmd, in_cmd_len, &wr, NULL));
                                in_cmd_len = 0;
                                i++;
                                continue;
                        }


                        GOTO_CLEANUP_ON_FALSE(WriteFile(pipe_out, buf + i, 1, &wr, NULL));
                        in_cmd[in_cmd_len] = buf[i];
                        in_cmd_len++;
                        if (in_cmd_len == MAX_CMD_LEN - 1) {
                                GOTO_CLEANUP_ON_FALSE(WriteFile(child_pipe_write, in_cmd, in_cmd_len, &wr, NULL));
                                in_cmd_len = 0;
                        }

                        i++;
                }
        }

cleanup:

        if (child != INVALID_HANDLE_VALUE)
                TerminateProcess(child, 0);
        if (monitor_thread != INVALID_HANDLE_VALUE)
                WaitForSingleObject(monitor_thread, INFINITE);
        return 0;        
}

int wmain(int ac, wchar_t **av) {


        /* create job to hold all child processes */
        {
                /* TODO - this does not work as expected*/
                HANDLE job = CreateJobObject(NULL, NULL);
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info;
                memset(&job_info, 0, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_info, sizeof(job_info)))
                        return -1;
                CloseHandle(job);
        }

        if ((ac == 1) || wcscmp(av[1], L"-nopty"))
                return start_with_pty(ac, av);
        else
                return start_withno_pty(ac, av);
}