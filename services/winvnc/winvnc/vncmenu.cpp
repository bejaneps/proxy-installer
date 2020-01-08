//  Copyright (C) 2002 UltraVNC Team Members. All Rights Reserved.
//  Copyright (C) 2002 RealVNC Ltd. All Rights Reserved.
//  Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
//
//  This file is part of the VNC system.
//
//  The VNC system is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//
// If the source code for the VNC system is not available from the place 
// whence you received this file, check http://www.uk.research.att.com/vnc or contact
// the authors on vnc@uk.research.att.com for information on obtaining it.


// vncMenu

// Implementation of a system tray icon & menu for WinVNC

#include "stdhdrs.h"
#include "winvnc.h"
#include "vncservice.h"
#include "vncconndialog.h"
#include <lmcons.h>
#include <wininet.h>
#include <shlobj.h>

// Header

#include "vncmenu.h"
#include "HideDesktop.h"
#include "common/win32_helpers.h"
#include "vncosversion.h"

#ifndef __GNUC__
// [v1.0.2-jp1 fix]
#pragma comment(lib, "imm32.lib")
#endif

extern bool G_1111;
// Constants
#ifdef IPV6V4
const UINT MENU_ADD_CLIENT6_MSG_INIT = RegisterWindowMessage("WinVNC.AddClient6.Message.Init");
const UINT MENU_ADD_CLIENT6_MSG = RegisterWindowMessage("WinVNC.AddClient6.Message");
#endif

const UINT MENU_ADD_CLIENT_MSG_INIT = RegisterWindowMessage("WinVNC.AddClient.Message.Init");
const UINT MENU_ADD_CLIENT_MSG = RegisterWindowMessage("WinVNC.AddClient.Message");
const UINT MENU_AUTO_RECONNECT_MSG = RegisterWindowMessage("WinVNC.AddAutoClient.Message");
const UINT MENU_STOP_RECONNECT_MSG = RegisterWindowMessage("WinVNC.AddStopClient.Message");
const UINT MENU_STOP_ALL_RECONNECT_MSG = RegisterWindowMessage("WinVNC.AddStopAllClient.Message");
const UINT MENU_REPEATER_ID_MSG = RegisterWindowMessage("WinVNC.AddRepeaterID.Message");
// adzm 2010-02-10 - Changed this window message (added 2) to prevent receiving the same message from older UltraVNC builds 
// which will send this message between processes with process-local pointers to strings as the wParam and lParam

const UINT FileTransferSendPacketMessage = RegisterWindowMessage("UltraVNC.Viewer.FileTransferSendPacketMessage");

const char *MENU_CLASS_NAME = "WinVNC Tray Icon";

BOOL g_restore_ActiveDesktop = FALSE;
bool RunningAsAdministrator ();
// [v1.0.2-jp1 fix] Load resouce from dll
extern HINSTANCE	hInstResDLL;

extern bool			fShutdownOrdered;
extern char g_hookstring[16];

extern BOOL SPECIAL_SC_PROMPT;

// sf@2007 - WTS notifications stuff
#define NOTIFY_FOR_THIS_SESSION 0
typedef BOOL (WINAPI *WTSREGISTERSESSIONNOTIFICATION)(HWND, DWORD);
typedef BOOL (WINAPI *WTSUNREGISTERSESSIONNOTIFICATION)(HWND);

static HMODULE DMdll = NULL; 
typedef HRESULT (CALLBACK *P_DwmIsCompositionEnabled) (BOOL *pfEnabled); 
static P_DwmIsCompositionEnabled pfnDwmIsCompositionEnabled = NULL; 
typedef HRESULT (CALLBACK *P_DwmEnableComposition) (BOOL   fEnable); 
static P_DwmEnableComposition pfnDwmEnableComposition = NULL; 
static BOOL AeroWasEnabled = FALSE;
DWORD GetExplorerLogonPid();

void Set_uninstall_service_as_admin();
void Set_install_service_as_admin();
void Set_stop_service_as_admin();
void Set_start_service_as_admin();

DWORD GetCurrentSessionID();
static unsigned int WM_TASKBARCREATED = 0;
void Open_homepage();
void Open_forum();

#define MSGFLT_ADD		1
typedef BOOL (WINAPI *CHANGEWINDOWMESSAGEFILTER)(UINT message, DWORD dwFlag);

void Enable_softwareCAD_elevated();
void delete_softwareCAD_elevated();
void Reboot_in_safemode_elevated();
bool IsSoftwareCadEnabled();
bool ISUACENabled();
void Reboot_with_force_reboot_elevated();
//HACK to use name in autoreconnect from service with dyn dns
extern char dnsname[255];
HWND G_MENU_HWND = NULL;
extern in6_addr G_LPARAM_IN6;


static inline VOID UnloadDM(VOID) 
 { 
         pfnDwmEnableComposition = NULL; 
         pfnDwmIsCompositionEnabled = NULL; 
         if (DMdll) FreeLibrary(DMdll); 
         DMdll = NULL; 
 } 
static inline BOOL LoadDM(VOID) 
 { 
         if (DMdll) 
                 return TRUE; 
  
         DMdll = LoadLibraryA("dwmapi.dll"); 
         if (!DMdll) return FALSE; 
  
         pfnDwmIsCompositionEnabled = (P_DwmIsCompositionEnabled)GetProcAddress(DMdll, "DwmIsCompositionEnabled");  
         pfnDwmEnableComposition = (P_DwmEnableComposition)GetProcAddress(DMdll, "DwmEnableComposition"); 
  
         return TRUE; 
 } 



//bool disable_aero_set=false;
static inline VOID DisableAero(VOID) 
 { 
	    /* if (disable_aero_set)
		 {
			 vnclog.Print(LL_INTINFO, VNCLOG("DisableAero already done %i \n"),AeroWasEnabled);
			 return;
		 }*/
         BOOL pfnDwmEnableCompositiond = FALSE; 
         //AeroWasEnabled = FALSE; 
  
         if (!LoadDM()) 
                 return; 
  
         if (pfnDwmIsCompositionEnabled && SUCCEEDED(pfnDwmIsCompositionEnabled(&pfnDwmEnableCompositiond))) 
                 ; 
         else 
                 return; 
  
		 //disable_aero_set=true;
		 vnclog.Print(LL_INTINFO, VNCLOG("DisableAero %i \n"),pfnDwmEnableCompositiond);
          if (!pfnDwmEnableCompositiond)
			  return; 

  
		  if (pfnDwmEnableComposition && SUCCEEDED(pfnDwmEnableComposition(FALSE))) {			  
			AeroWasEnabled = pfnDwmEnableCompositiond;
		  }
		 
 } 
  
 static inline VOID ResetAero(VOID) 
 { 
	     vnclog.Print(LL_INTINFO, VNCLOG("Reset %i \n"),AeroWasEnabled);
         if (pfnDwmEnableComposition && AeroWasEnabled) 
         { 
                 if (SUCCEEDED(pfnDwmEnableComposition(AeroWasEnabled))) 
                         ; 
                 else 
                         ; 
         } 
		 //disable_aero_set=false;
         UnloadDM(); 
 } 

// adzm - 2010-07 - Disable more effects or font smoothing
static bool IsUserDesktop()
{
	//only kill wallpaper if desktop is user desktop
	HDESK desktop = GetThreadDesktop(GetCurrentThreadId());
	DWORD dummy;
	char new_name[256];
	if (GetUserObjectInformation(desktop, UOI_NAME, &new_name, 256, &dummy))
	{
		if (strcmp(new_name,"Default")==0) {
			return true;
		}
	}	

	return false;
}

// adzm - 2010-07 - Disable more effects or font smoothing
static void KillWallpaper()
{
	HideDesktop();
}

static void RestoreWallpaper()
{
  RestoreDesktop();
}

// adzm - 2010-07 - Disable more effects or font smoothing
static void KillEffects()
{
	DisableEffects();
}

// adzm - 2010-07 - Disable more effects or font smoothing
static void RestoreEffects()
{
	EnableEffects();
}

// adzm - 2010-07 - Disable more effects or font smoothing
static void KillFontSmoothing()
{
	DisableFontSmoothing();
}

// adzm - 2010-07 - Disable more effects or font smoothing
static void RestoreFontSmoothing()
{
	EnableFontSmoothing();
}

// Implementation

vncMenu::vncMenu(vncServer *server)
{
	vnclog.Print(LL_INTERR, VNCLOG("vncmenu(server)\n"));
	hWTSDll = NULL;
	ports_set=false;
    CoInitialize(0);

	HMODULE hUser32 = LoadLibrary("user32.dll");
	CHANGEWINDOWMESSAGEFILTER pfnFilter = NULL;
	if (hUser32)
	{
	pfnFilter =(CHANGEWINDOWMESSAGEFILTER)GetProcAddress(hUser32,"ChangeWindowMessageFilter");
	if (pfnFilter) 
		{	
			pfnFilter(MENU_ADD_CLIENT_MSG, MSGFLT_ADD);
			pfnFilter(MENU_ADD_CLIENT_MSG_INIT, MSGFLT_ADD);
#ifdef IPV6V4
			pfnFilter(MENU_ADD_CLIENT6_MSG, MSGFLT_ADD);
			pfnFilter(MENU_ADD_CLIENT6_MSG_INIT, MSGFLT_ADD);
#endif
			pfnFilter(MENU_AUTO_RECONNECT_MSG, MSGFLT_ADD);
			pfnFilter(MENU_STOP_RECONNECT_MSG, MSGFLT_ADD);
			pfnFilter(MENU_STOP_ALL_RECONNECT_MSG, MSGFLT_ADD);
			pfnFilter(MENU_REPEATER_ID_MSG, MSGFLT_ADD);
		}
    FreeLibrary (hUser32);
	}

	// Save the server pointer
	m_server = server;

	// Set the initial user name to something sensible...
	vncService::CurrentUser((char *)&m_username, sizeof(m_username));

	//if (strcmp(m_username, "") == 0)
	//	strcpy((char *)&m_username, "SYSTEM");
	//vnclog.Print(LL_INTERR, VNCLOG("########### vncMenu::vncMenu - UserName = %s\n"), m_username);

	// Create a dummy window to handle tray icon messages
	WNDCLASSEX wndclass;

	wndclass.cbSize			= sizeof(wndclass);
	wndclass.style			= 0;
	wndclass.lpfnWndProc	= vncMenu::WndProc;
	wndclass.cbClsExtra		= 0;
	wndclass.cbWndExtra		= 0;
	wndclass.hInstance		= hAppInstance;
	wndclass.hIcon			= LoadIcon(NULL, IDI_APPLICATION);
	wndclass.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wndclass.hbrBackground	= (HBRUSH) GetStockObject(WHITE_BRUSH);
	wndclass.lpszMenuName	= (const char *) NULL;
	wndclass.lpszClassName	= MENU_CLASS_NAME;
	wndclass.hIconSm		= LoadIcon(NULL, IDI_APPLICATION);

	RegisterClassEx(&wndclass);

	m_hwnd = CreateWindow(MENU_CLASS_NAME,
				MENU_CLASS_NAME,
				WS_OVERLAPPEDWINDOW,
				CW_USEDEFAULT,
				CW_USEDEFAULT,
				200, 200,
				NULL,
				NULL,
				hAppInstance,
				NULL);
	G_MENU_HWND = m_hwnd;
	if (m_hwnd == NULL)
	{
		PostQuitMessage(0);
		return;
	}

	if (!hWTSDll) hWTSDll = LoadLibrary( ("wtsapi32.dll") );
	if (hWTSDll)
	{
		WTSREGISTERSESSIONNOTIFICATION FunctionWTSRegisterSessionNotification;    
		FunctionWTSRegisterSessionNotification = (WTSREGISTERSESSIONNOTIFICATION)GetProcAddress((HINSTANCE)hWTSDll, "WTSRegisterSessionNotification" );
		if (FunctionWTSRegisterSessionNotification)
			FunctionWTSRegisterSessionNotification( m_hwnd, NOTIFY_FOR_THIS_SESSION );
	}

	// record which client created this window
    helper::SafeSetWindowUserData(m_hwnd, (LONG_PTR) this);

	// Ask the server object to notify us of stuff
	server->AddNotify(m_hwnd);

	// Initialise the properties dialog object
	if (!m_properties.Init(m_server))
	{
		PostQuitMessage(0);
		return;
	}

	SetTimer(m_hwnd, 1, 5000, NULL);


	// sf@2002
	if (!m_ListDlg.Init(m_server))
	{
		PostQuitMessage(0);
		return;
	}

	CoUninitialize();
}

vncMenu::~vncMenu()
{
	vnclog.Print(LL_INTERR, VNCLOG("vncmenu killed\n"));

	if (hWTSDll)
	{
		WTSUNREGISTERSESSIONNOTIFICATION FunctionWTSUnRegisterSessionNotification=NULL;
		FunctionWTSUnRegisterSessionNotification = (WTSUNREGISTERSESSIONNOTIFICATION)GetProcAddress((HINSTANCE)hWTSDll,"WTSUnRegisterSessionNotification" );
		if (FunctionWTSUnRegisterSessionNotification)
			FunctionWTSUnRegisterSessionNotification( m_hwnd );
		FreeLibrary( hWTSDll );
		hWTSDll = NULL;
	}

	// Tell the server to stop notifying us!
	if (m_server != NULL)
		m_server->RemNotify(m_hwnd);

	if (m_server->RemoveWallpaperEnabled())
		RestoreWallpaper();
	// adzm - 2010-07 - Disable more effects or font smoothing
	if (m_server->RemoveEffectsEnabled())
		RestoreEffects();
	if (m_server->RemoveFontSmoothingEnabled())
		RestoreFontSmoothing();
	if (m_server->RemoveAeroEnabled())
		ResetAero();
	CoUninitialize();
}

// Get the local ip addresses as a human-readable string.
// If more than one, then with \n between them.
// If not available, then gets a message to that effect.
// The ip address is not likely to change while running
// this function is an overhead, each time calculating the ip
// the ip is just used in the tray tip
char old_buffer[512];
char old_buflen=0;
int dns_counter=0; // elimate to many dns requests once every 250s is ok
void 
vncMenu::GetIPAddrString(char *buffer, int buflen) {
	if (old_buflen!=0 && dns_counter<12)
	{
		dns_counter++;
		strcpy(buffer,old_buffer);
		return;
	}
	dns_counter=0;
    char namebuf[256];

    if (gethostname(namebuf, 256) != 0) {
		strncpy(buffer, "Host name unavailable", buflen);
		return;
    };

#ifdef IPV6V4
	*buffer = '\0';

	LPSOCKADDR sockaddr_ip;	
	struct addrinfo hint;
	struct addrinfo *serverinfo = 0;
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	struct sockaddr_in6 *pIpv6Addr;
	struct sockaddr_in *pIpv4Addr;
	struct sockaddr_in6 Ipv6Addr;
	struct sockaddr_in Ipv4Addr;
	memset(&Ipv6Addr, 0, sizeof(Ipv6Addr));
	memset(&Ipv4Addr, 0, sizeof(Ipv4Addr));

	//make sure the buffer is not overwritten


	if (getaddrinfo(namebuf, 0, &hint, &serverinfo) == 0)
	{
		struct addrinfo *p;
		if (!G_ipv6_allowed)
		{
			p = serverinfo;
			for (p = serverinfo; p != NULL; p = p->ai_next) {
				switch (p->ai_family) {
				case AF_INET:
				{
					pIpv4Addr = (struct sockaddr_in *) p->ai_addr;
					memcpy(&Ipv4Addr, pIpv4Addr, sizeof(Ipv4Addr));
					Ipv4Addr.sin_family = AF_INET;
					char			szText[256];
					sprintf(szText, "%s-", inet_ntoa(Ipv4Addr.sin_addr));
					int len = strlen(buffer);
					int len2 = strlen(szText);
					if (len + len2 < buflen) strcat_s(buffer, buflen, szText);
					break;
				}
				case AF_INET6:
				{
					break;
				}
				default:
					break;
				}
			}
		}

		
		if (G_ipv6_allowed)
		{
			p = serverinfo;
			for (p = serverinfo; p != NULL; p = p->ai_next) {
				switch (p->ai_family) {
				case AF_INET:
				{
					break;
				}
				case AF_INET6:
				{
					char ipstringbuffer[46];
					DWORD ipbufferlength = 46;
					ipbufferlength = 46;
					memset(ipstringbuffer, 0, 46);
					pIpv6Addr = (struct sockaddr_in6 *) p->ai_addr;
					memcpy(&Ipv6Addr, pIpv6Addr, sizeof(Ipv6Addr));
					Ipv6Addr.sin6_family = AF_INET6;
					sockaddr_ip = (LPSOCKADDR)p->ai_addr;
					WSAAddressToString(sockaddr_ip, (DWORD)p->ai_addrlen, NULL, ipstringbuffer, &ipbufferlength);
					char			szText[256];
					memset(szText, 0, 256);
					strncpy(szText, ipstringbuffer, ipbufferlength - 4);
					strcat(szText, "-");
					int len = strlen(buffer);
					int len2 = strlen(szText);
					if (len + len2 < buflen)strcat_s(buffer, buflen, szText);
					break;
				}
				default:
					break;
				}
			}
		}
	}
	freeaddrinfo(serverinfo);
#else
    HOSTENT *ph = gethostbyname(namebuf);
    if (!ph) {
		strncpy(buffer, "IP address unavailable", buflen);
		return;
    };

    *buffer = '\0';
    char digtxt[5];
    for (int i = 0; ph->h_addr_list[i]; i++) {
    	for (int j = 0; j < ph->h_length; j++) {
			sprintf(digtxt, "%d.", (unsigned char) ph->h_addr_list[i][j]);
			strncat(buffer, digtxt, (buflen-1)-strlen(buffer));
		}	
		buffer[strlen(buffer)-1] = '\0';
		if (ph->h_addr_list[i+1] != 0)
			strncat(buffer, ", ", (buflen-1)-strlen(buffer));
    }

#endif
	if (strlen(buffer)<512 && m_server->AuthClientCount()==0 ) // just in case it would be bigger then our buffer
	{
		if (old_buflen!=0)//first time old_buflen=0
		{
			if (strcmp(buffer,old_buffer)!=NULL) //ip changed
			{
				vnclog.Print(LL_INTERR, VNCLOG("IP interface change detected %s %s\n"),buffer,old_buffer);
				if (m_server->SockConnected())
				{
					// if connected restart
					m_server->SockConnect(false);
					m_server->SockConnect(true);
				}
			}
		}
	old_buflen=strlen(buffer);
	memset(old_buffer,0,512);
	strncpy(old_buffer,buffer,strlen(buffer));
	}
}

// sf@2007
void vncMenu::Shutdown(bool kill_client)
{
	vnclog.Print(LL_INTERR, VNCLOG("vncMenu::Shutdown: Close menu - Disconnect all - Shutdown server\n"));
	SendMessage(m_hwnd, WM_CLOSE, 0, 0);
	if (kill_client) m_server->KillAuthClients();
	G_MENU_HWND = NULL;
}

//extern BOOL G_HTTP;

char newuser[UNLEN+1];
// Process window messages
LRESULT CALLBACK vncMenu::WndProc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	// This is a static method, so we don't know which instantiation we're 
	// dealing with. We use Allen Hadden's (ahadden@taratec.com) suggestion 
	// from a newsgroup to get the pseudo-this.
     vncMenu *_this = helper::SafeGetWindowUserData<vncMenu>(hwnd);
	//	Beep(100,10);
	//	vnclog.Print(LL_INTINFO, VNCLOG("iMsg 0x%x \n"),iMsg);

	 if (iMsg==WM_TASKBARCREATED)
	 {
		 if (_this->m_server->RunningFromExternalService())
			{
				Sleep(1000);
				vnclog.Print(LL_INTINFO,
				VNCLOG("WM_TASKBARCREATED \n"));
				// User has changed!
				strcpy(_this->m_username, newuser);
				vnclog.Print(LL_INTINFO,
				VNCLOG("############## Kill vncMenu thread\n"));
				// Order impersonation thread killing
				KillTimer(hwnd,1);
				PostQuitMessage(0);
			}
	 }

	switch (iMsg)
	{

	// Every five seconds, a timer message causes the icon to update
	case WM_TIMER:
		// sf@2007 - Can't get the WTS_CONSOLE_CONNECT message work properly for now..
		// So use a hack instead
        // jdp reread some ini settings
        _this->m_properties.ReloadDynamicSettings();

		if (_this->m_server->RunningFromExternalService())
			{
				strcpy(newuser,"");
				if (vncService::CurrentUser((char *) &newuser, sizeof(newuser)))
				{
					// Check whether the user name has changed!
					if (_stricmp(newuser, _this->m_username) != 0)
					{
						Sleep(1000);
						vnclog.Print(LL_INTINFO,
						VNCLOG("user name has changed\n"));
						// User has changed!
						strcpy(_this->m_username, newuser);
						vnclog.Print(LL_INTINFO,
						VNCLOG("############## Kill vncMenu thread\n"));
						// Order impersonation thread killing
						PostQuitMessage(0);
						break;
					}
				}
			}

		// *** HACK for running servicified
		if (vncService::RunningAsService())
			{
				// Trigger a check of the current user
				PostMessage(hwnd, WM_USERCHANGED, 0, 0);
			}
		break;

		// DEAL WITH NOTIFICATIONS FROM THE SERVER:
	case WM_SRV_CLIENT_AUTHENTICATED:
	case WM_SRV_CLIENT_DISCONNECT:

		if (_this->m_server->AuthClientCount() != 0) {
			// adzm - 2010-07 - Disable more effects or font smoothing
			if (IsUserDesktop()) {
				if (_this->m_server->RemoveWallpaperEnabled())
					KillWallpaper();
				if (_this->m_server->RemoveEffectsEnabled())
					KillEffects();
				if (_this->m_server->RemoveFontSmoothingEnabled())
					KillFontSmoothing();
			}
			if (_this->m_server->RemoveAeroEnabled()) // Moved, redundant if //PGM @ Advantig
				DisableAero(); // Moved, redundant if //PGM @ Advantig
			VNCOS.SetAeroState();
		} else {
			if (_this->m_server->RemoveAeroEnabled()) // Moved, redundant if //PGM @ Advantig
				ResetAero(); // Moved, redundant if //PGM @ Advantig
			if (_this->m_server->RemoveWallpaperEnabled()) { // Added { //PGM @ Advantig
				Sleep(2000); // Added 2 second delay to help wallpaper restore //PGM @ Advantig
				RestoreWallpaper();
			} //PGM @ Advantig
			// adzm - 2010-07 - Disable more effects or font smoothing
			if (_this->m_server->RemoveEffectsEnabled()) {
				RestoreEffects();
			}
			if (_this->m_server->RemoveFontSmoothingEnabled()) {
				RestoreFontSmoothing();
			}
		}
		return 0;

		// STANDARD MESSAGE HANDLING
	case WM_CREATE:
		WM_TASKBARCREATED = RegisterWindowMessage("TaskbarCreated");
		return 0;

	case WM_COMMAND:
		// User has clicked an item on the tray menu
		switch (LOWORD(wParam))
		{
		case ID_DEFAULT_PROPERTIES:
			// Show the default properties dialog, unless it is already displayed
			vnclog.Print(LL_INTINFO, VNCLOG("show default properties requested\n"));
			_this->m_properties.ShowAdmin(TRUE, FALSE);
			break;

        case ID_ADMIN_PROPERTIES:
			// Show the properties dialog, unless it is already displayed
			vnclog.Print(LL_INTINFO, VNCLOG("show user properties requested\n"));
			_this->m_properties.ShowAdmin(TRUE, TRUE);
			break;
		
		case ID_OUTGOING_CONN:
			// Connect out to a listening VNC viewer
			{
				vncConnDialog *newconn = new vncConnDialog(_this->m_server);
				if (newconn)
				{
					newconn->DoDialog();
					// delete newconn; // NO ! Already done in vncConnDialog.
				}
			}
			break;

		case ID_KILLCLIENTS:
			// Disconnect all currently connected clients
			vnclog.Print(LL_INTINFO, VNCLOG("KillAuthClients() ID_KILLCLIENTS \n"));
			_this->m_server->KillAuthClients();
			break;

		// sf@2002
		case ID_LISTCLIENTS:
			_this->m_ListDlg.Display();
			break;

		case ID_VISITUSONLINE_HOMEPAGE:
			{
						HANDLE hProcess,hPToken;
						DWORD id=GetExplorerLogonPid();
						if (id!=0) 
						{
							hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,id);
							if(!OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
													|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
													|TOKEN_READ|TOKEN_WRITE,&hPToken)) break;

							char dir[MAX_PATH];
							char exe_file_name[MAX_PATH];
							GetModuleFileName(0, exe_file_name, MAX_PATH);
							strcpy(dir, exe_file_name);
							strcat(dir, " -openhomepage");
				
							{
								STARTUPINFO          StartUPInfo;
								PROCESS_INFORMATION  ProcessInfo;
								ZeroMemory(&StartUPInfo,sizeof(STARTUPINFO));
								ZeroMemory(&ProcessInfo,sizeof(PROCESS_INFORMATION));
								StartUPInfo.wShowWindow = SW_SHOW;
								StartUPInfo.lpDesktop = "Winsta0\\Default";
								StartUPInfo.cb = sizeof(STARTUPINFO);
						
								CreateProcessAsUser(hPToken,NULL,dir,NULL,NULL,FALSE,DETACHED_PROCESS,NULL,NULL,&StartUPInfo,&ProcessInfo);
                                if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
                                if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);

							}
						}
			}
			break;

		case ID_VISITUSONLINE_FORUM:
			{
						HANDLE hProcess,hPToken;
						DWORD id=GetExplorerLogonPid();
						if (id!=0) 
						{
							hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,id);
							if(!OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
													|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
													|TOKEN_READ|TOKEN_WRITE,&hPToken)) break;

							char dir[MAX_PATH];
							char exe_file_name[MAX_PATH];
							GetModuleFileName(0, exe_file_name, MAX_PATH);
							strcpy(dir, exe_file_name);
							strcat(dir, " -openforum");
				
							{
								STARTUPINFO          StartUPInfo;
								PROCESS_INFORMATION  ProcessInfo;
								ZeroMemory(&StartUPInfo,sizeof(STARTUPINFO));
								ZeroMemory(&ProcessInfo,sizeof(PROCESS_INFORMATION));
								StartUPInfo.wShowWindow = SW_SHOW;
								StartUPInfo.lpDesktop = "Winsta0\\Default";
								StartUPInfo.cb = sizeof(STARTUPINFO);
						
								CreateProcessAsUser(hPToken,NULL,dir,NULL,NULL,FALSE,DETACHED_PROCESS,NULL,NULL,&StartUPInfo,&ProcessInfo);
                                if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
                                if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);

							}
						}
			}
			break;

		case ID_CLOSE:
			// User selected Close from the tray menu
			fShutdownOrdered=TRUE;
			Sleep(1000);
			vnclog.Print(LL_INTINFO, VNCLOG("KillAuthClients() ID_CLOSE \n"));
			_this->m_server->KillAuthClients();
			PostMessage(hwnd, WM_CLOSE, 0, 0);
			break;
		case ID_SOFTWARECAD:
			{
			HANDLE hProcess=NULL,hPToken=NULL;
			DWORD id=GetExplorerLogonPid();
				if (id!=0) 
				{
					hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,id);
					if (!hProcess) goto error;
					if(!OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
											|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
											| TOKEN_READ | TOKEN_WRITE, &hPToken))
					{
						CloseHandle(hProcess);
						goto error;
					}

					char dir[MAX_PATH];
					char exe_file_name[MAX_PATH];
					GetModuleFileName(0, exe_file_name, MAX_PATH);
					strcpy(dir, exe_file_name);
					strcat(dir, " -softwarecadhelper");
		
					{
					STARTUPINFO          StartUPInfo;
					PROCESS_INFORMATION  ProcessInfo;
					HANDLE Token=NULL;
					HANDLE process=NULL;
					ZeroMemory(&StartUPInfo,sizeof(STARTUPINFO));
					ZeroMemory(&ProcessInfo,sizeof(PROCESS_INFORMATION));
					StartUPInfo.wShowWindow = SW_SHOW;
					StartUPInfo.lpDesktop = "Winsta0\\Default";
					StartUPInfo.cb = sizeof(STARTUPINFO);
			
					CreateProcessAsUser(hPToken,NULL,dir,NULL,NULL,FALSE,DETACHED_PROCESS,NULL,NULL,&StartUPInfo,&ProcessInfo);
					DWORD errorcode=GetLastError();
					if (process) CloseHandle(process);
					if (Token) CloseHandle(Token);
					if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);
					if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
					if (errorcode == 1314) goto error;	
					break;
					}
				error:
					Enable_softwareCAD_elevated();
				}
			}
			break;

		case ID_DELSOFTWARECAD:
			{
			HANDLE hProcess=NULL,hPToken=NULL;
			DWORD id=GetExplorerLogonPid();
				if (id!=0) 
				{
					hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,id);
					if (!hProcess) goto error2;
					if(!OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
											|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
											| TOKEN_READ | TOKEN_WRITE, &hPToken))
					{
						CloseHandle(hProcess);
						goto error2;
					}

					char dir[MAX_PATH];
					char exe_file_name[MAX_PATH];
					GetModuleFileName(0, exe_file_name, MAX_PATH);
					strcpy(dir, exe_file_name);
					strcat(dir, " -delsoftwarecadhelper");
		
					{
					STARTUPINFO          StartUPInfo;
					PROCESS_INFORMATION  ProcessInfo;
					HANDLE Token=NULL;
					HANDLE process=NULL;
					ZeroMemory(&StartUPInfo,sizeof(STARTUPINFO));
					ZeroMemory(&ProcessInfo,sizeof(PROCESS_INFORMATION));
					StartUPInfo.wShowWindow = SW_SHOW;
					StartUPInfo.lpDesktop = "Winsta0\\Default";
					StartUPInfo.cb = sizeof(STARTUPINFO);
			
					CreateProcessAsUser(hPToken,NULL,dir,NULL,NULL,FALSE,DETACHED_PROCESS,NULL,NULL,&StartUPInfo,&ProcessInfo);
					DWORD errorcode=GetLastError();
					if (process) CloseHandle(process);
					if (Token) CloseHandle(Token);
					if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);
					if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
					if (errorcode == 1314) goto error2;
					break;
					error2:
						delete_softwareCAD_elevated();

					}
				}
			}
			break;

		case ID_REBOOTSAFEMODE:
			{
			HANDLE hProcess = NULL, hPToken = NULL;
			DWORD id=GetExplorerLogonPid();
				if (id!=0) 
				{
					hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,id);
					if (!hProcess) goto error3;
					if(!OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
											|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
											| TOKEN_READ | TOKEN_WRITE, &hPToken))
					{
						CloseHandle(hProcess);
						goto error3;
					}

					char dir[MAX_PATH];
					char exe_file_name[MAX_PATH];
					GetModuleFileName(0, exe_file_name, MAX_PATH);
					strcpy(dir, exe_file_name);
					strcat(dir, " -rebootsafemodehelper");
		
					{
					STARTUPINFO          StartUPInfo;
					PROCESS_INFORMATION  ProcessInfo;
					HANDLE Token=NULL;
					HANDLE process=NULL;
					ZeroMemory(&StartUPInfo,sizeof(STARTUPINFO));
					ZeroMemory(&ProcessInfo,sizeof(PROCESS_INFORMATION));
					StartUPInfo.wShowWindow = SW_SHOW;
					StartUPInfo.lpDesktop = "Winsta0\\Default";
					StartUPInfo.cb = sizeof(STARTUPINFO);
			
					CreateProcessAsUser(hPToken,NULL,dir,NULL,NULL,FALSE,DETACHED_PROCESS,NULL,NULL,&StartUPInfo,&ProcessInfo);
					DWORD errorcode=GetLastError();
					if (process) CloseHandle(process);
					if (Token) CloseHandle(Token);
					if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);
					if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
					if (errorcode == 1314) goto error3;
					break;
					error3:
						Reboot_in_safemode_elevated();
					}
				}
			}
			break;

		case ID_REBOOT_FORCE:
			{
			HANDLE hProcess,hPToken;
			DWORD id=GetExplorerLogonPid();
				if (id!=0) 
				{
					hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,id);
					if (!hProcess) goto error4;
					if(!OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
											|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
											| TOKEN_READ | TOKEN_WRITE, &hPToken))
					{
						CloseHandle(hProcess);
						goto error4;
					}

					char dir[MAX_PATH];
					char exe_file_name[MAX_PATH];
					GetModuleFileName(0, exe_file_name, MAX_PATH);
					strcpy(dir, exe_file_name);
					strcat(dir, " -rebootforcedehelper");
		
					{
					STARTUPINFO          StartUPInfo;
					PROCESS_INFORMATION  ProcessInfo;
					HANDLE Token=NULL;
					HANDLE process=NULL;
					ZeroMemory(&StartUPInfo,sizeof(STARTUPINFO));
					ZeroMemory(&ProcessInfo,sizeof(PROCESS_INFORMATION));
					StartUPInfo.wShowWindow = SW_SHOW;
					StartUPInfo.lpDesktop = "Winsta0\\Default";
					StartUPInfo.cb = sizeof(STARTUPINFO);
			
					CreateProcessAsUser(hPToken,NULL,dir,NULL,NULL,FALSE,DETACHED_PROCESS,NULL,NULL,&StartUPInfo,&ProcessInfo);
					DWORD errorcode=GetLastError();
					if (process) CloseHandle(process);
					if (Token) CloseHandle(Token);
					if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);
					if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
					if (errorcode == 1314) goto error4;
					break;
					error4:
						 Reboot_with_force_reboot_elevated();
					}
				}
			}
			break;

		case ID_UNINSTALL_SERVICE:
			{
			HANDLE hProcess,hPToken;
			DWORD id=GetExplorerLogonPid();
				if (id!=0) 
				{
					hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,id);
					if (!hProcess) goto error5;
					if(!OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
											|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
											| TOKEN_READ | TOKEN_WRITE, &hPToken))
					{
						CloseHandle(hProcess);
						goto error5;
					}
					char dir[MAX_PATH];
					char exe_file_name[MAX_PATH];
					GetModuleFileName(0, exe_file_name, MAX_PATH);
					strcpy(dir, exe_file_name);
					strcat(dir, " -uninstallhelper");
		
					{
					STARTUPINFO          StartUPInfo;
					PROCESS_INFORMATION  ProcessInfo;
					HANDLE Token=NULL;
					HANDLE process=NULL;
					ZeroMemory(&StartUPInfo,sizeof(STARTUPINFO));
					ZeroMemory(&ProcessInfo,sizeof(PROCESS_INFORMATION));
					StartUPInfo.wShowWindow = SW_SHOW;
					StartUPInfo.lpDesktop = "Winsta0\\Default";
					StartUPInfo.cb = sizeof(STARTUPINFO);
			
					CreateProcessAsUser(hPToken,NULL,dir,NULL,NULL,FALSE,DETACHED_PROCESS,NULL,NULL,&StartUPInfo,&ProcessInfo);
					DWORD errorcode=GetLastError();
					if (process) CloseHandle(process);
					if (Token) CloseHandle(Token);
					if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);
					if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
					if (errorcode == 1314) goto error5;
					break;
					error5:
						Set_uninstall_service_as_admin();
					}
				}
			}
			break;
		case ID_RUNASSERVICE:
			{
			HANDLE hProcess,hPToken;
			DWORD id=GetExplorerLogonPid();
				if (id!=0) 
				{
					hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,id);
					if (!hProcess) goto error6;
					if(!OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
											|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
											| TOKEN_READ | TOKEN_WRITE, &hPToken))
					{
						if (hProcess) CloseHandle(hProcess);
						goto error6;
					}

					char dir[MAX_PATH];
					char exe_file_name[MAX_PATH];
					GetModuleFileName(0, exe_file_name, MAX_PATH);
					strcpy(dir, exe_file_name);
					strcat(dir, " -installhelper");
		

					STARTUPINFO          StartUPInfo;
					PROCESS_INFORMATION  ProcessInfo;
					ZeroMemory(&StartUPInfo,sizeof(STARTUPINFO));
					ZeroMemory(&ProcessInfo,sizeof(PROCESS_INFORMATION));
					StartUPInfo.wShowWindow = SW_SHOW;
					StartUPInfo.lpDesktop = "Winsta0\\Default";
					StartUPInfo.cb = sizeof(STARTUPINFO);
			
					CreateProcessAsUser(hPToken,NULL,dir,NULL,NULL,FALSE,DETACHED_PROCESS,NULL,NULL,&StartUPInfo,&ProcessInfo);
					DWORD errorcode=GetLastError();
					if (hProcess) CloseHandle(hProcess);
					if (hPToken) CloseHandle(hPToken);
					if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);
					if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
					
					if (errorcode == 1314) goto error6;
					fShutdownOrdered = TRUE;
					Sleep(1000);
					vnclog.Print(LL_INTINFO, VNCLOG("KillAuthClients() ID_CLOSE \n"));
					_this->m_server->KillAuthClients();
					PostMessage(hwnd, WM_CLOSE, 0, 0);
					break;
					error6:
						Set_install_service_as_admin();
				}
			fShutdownOrdered=TRUE;
			Sleep(1000);
			vnclog.Print(LL_INTINFO, VNCLOG("KillAuthClients() ID_CLOSE \n"));
			_this->m_server->KillAuthClients();
			PostMessage(hwnd, WM_CLOSE, 0, 0);
			}
			break;
		case ID_CLOSE_SERVICE:
			{
			HANDLE hProcess,hPToken;
			DWORD id=GetExplorerLogonPid();
				if (id!=0) 
				{
					hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,id);
					if (!hProcess) goto error7;
					if(!OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
											|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
											|TOKEN_READ|TOKEN_WRITE,&hPToken))
					{
						CloseHandle(hProcess);
						goto error7;
					}

					char dir[MAX_PATH];
					char exe_file_name[MAX_PATH];
					GetModuleFileName(0, exe_file_name, MAX_PATH);
					strcpy(dir, exe_file_name);
					strcat(dir, " -stopservicehelper");
		

					STARTUPINFO          StartUPInfo;
					PROCESS_INFORMATION  ProcessInfo;
					HANDLE Token=NULL;
					HANDLE process=NULL;
					ZeroMemory(&StartUPInfo,sizeof(STARTUPINFO));
					ZeroMemory(&ProcessInfo,sizeof(PROCESS_INFORMATION));
					StartUPInfo.wShowWindow = SW_SHOW;
					StartUPInfo.lpDesktop = "Winsta0\\Default";
					StartUPInfo.cb = sizeof(STARTUPINFO);
			
					CreateProcessAsUser(hPToken,NULL,dir,NULL,NULL,FALSE,DETACHED_PROCESS,NULL,NULL,&StartUPInfo,&ProcessInfo);
					DWORD errorcode=GetLastError();
					if (process) CloseHandle(process);
					if (Token) CloseHandle(Token);
					if (hProcess) CloseHandle(hProcess);
					if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);
					if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
					if (errorcode == 1314) goto error7;
					break;
					error7:
						Set_stop_service_as_admin();
				}
			}
			break;
		case ID_START_SERVICE:
			{
			HANDLE hProcess,hPToken;
			DWORD id=GetExplorerLogonPid();
				if (id!=0) 
				{
					hProcess = OpenProcess(MAXIMUM_ALLOWED,FALSE,id);
					if (!hProcess) goto error8;
					if(!OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
											|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID
											|TOKEN_READ|TOKEN_WRITE,&hPToken))
					{
						CloseHandle(hProcess);
						goto error8;
					}

					char dir[MAX_PATH];
					char exe_file_name[MAX_PATH];
					GetModuleFileName(0, exe_file_name, MAX_PATH);
					strcpy(dir, exe_file_name);
					strcat(dir, " -startservicehelper");
		

					STARTUPINFO          StartUPInfo;
					PROCESS_INFORMATION  ProcessInfo;
					HANDLE Token=NULL;
					HANDLE process=NULL;
					ZeroMemory(&StartUPInfo,sizeof(STARTUPINFO));
					ZeroMemory(&ProcessInfo,sizeof(PROCESS_INFORMATION));
					StartUPInfo.wShowWindow = SW_SHOW;
					StartUPInfo.lpDesktop = "Winsta0\\Default";
					StartUPInfo.cb = sizeof(STARTUPINFO);
			
					CreateProcessAsUser(hPToken,NULL,dir,NULL,NULL,FALSE,DETACHED_PROCESS,NULL,NULL,&StartUPInfo,&ProcessInfo);
					DWORD errorcode=GetLastError();
					if (hPToken) CloseHandle(hPToken);
					if (process) CloseHandle(process);
					if (Token) CloseHandle(Token);
					if (hProcess) CloseHandle(hProcess);
					if (ProcessInfo.hProcess) CloseHandle(ProcessInfo.hProcess);
					if (ProcessInfo.hThread) CloseHandle(ProcessInfo.hThread);
					if (errorcode == 1314) goto error8;
					fShutdownOrdered = TRUE;
					Sleep(1000);
					vnclog.Print(LL_INTINFO, VNCLOG("KillAuthClients() ID_CLOSE \n"));
					_this->m_server->KillAuthClients();
					PostMessage(hwnd, WM_CLOSE, 0, 0);
					break;
					error8:
						Set_start_service_as_admin();
					fShutdownOrdered=TRUE;
					Sleep(1000);
					vnclog.Print(LL_INTINFO, VNCLOG("KillAuthClients() ID_CLOSE \n"));
					_this->m_server->KillAuthClients();
					PostMessage(hwnd, WM_CLOSE, 0, 0);
				}
			}
			break;

		}
		return 0;
		
	case WM_CLOSE:
		
		// Only accept WM_CLOSE if the logged on user has AllowShutdown set
		// Error this clock the service restart.
		/*if (!_this->m_properties.AllowShutdown())
		{
			return 0;
		}*/
		// tnatsni Wallpaper fix
		if (_this->m_server->RemoveWallpaperEnabled())
			RestoreWallpaper();
		// adzm - 2010-07 - Disable more effects or font smoothing
		if (_this->m_server->RemoveEffectsEnabled())
			RestoreEffects();
		if (_this->m_server->RemoveFontSmoothingEnabled())
			RestoreFontSmoothing();
		if (_this->m_server->RemoveAeroEnabled())
			ResetAero();

		vnclog.Print(LL_INTERR, VNCLOG("vncMenu WM_CLOSE call - All cleanup done\n"));
		Sleep(2000);
		DestroyWindow(hwnd);
		break;
		
	case WM_DESTROY:
		// The user wants WinVNC to quit cleanly...
		vnclog.Print(LL_INTINFO, VNCLOG("quitting from WM_DESTROY\n"));
		PostQuitMessage(0);
		return 0;
		
	case WM_QUERYENDSESSION:
		{
			//shutdown or reboot
			if((lParam & ENDSESSION_LOGOFF) != ENDSESSION_LOGOFF)
			{
				fShutdownOrdered=TRUE;
				Sleep(1000);
				vnclog.Print(LL_INTERR, VNCLOG("SHUTDOWN OS detected\n"));
				vnclog.Print(LL_INTINFO, VNCLOG("KillAuthClients() ID_CLOSE \n"));
				_this->m_server->OS_Shutdown=true;
				_this->m_server->KillAuthClients();				
				PostMessage(hwnd, WM_CLOSE, 0, 0);
				break;
			}


			DWORD SessionID;
			SessionID=GetCurrentSessionID();
			vnclog.Print(LL_INTERR, VNCLOG("Session ID %i\n"),SessionID);
			if (SessionID!=0)
			{
				fShutdownOrdered=TRUE;
				Sleep(1000);
				vnclog.Print(LL_INTERR, VNCLOG("WM_QUERYENDSESSION session!=0\n"));
				vnclog.Print(LL_INTINFO, VNCLOG("KillAuthClients() ID_CLOSE \n"));
				_this->m_server->KillAuthClients();				
				PostMessage(hwnd, WM_CLOSE, 0, 0);
			}
		}	
		break;
		
	case WM_ENDSESSION:
		vnclog.Print(LL_INTERR, VNCLOG("WM_ENDSESSION\n"));
		break;

	case WM_USERCHANGED:
		// The current user may have changed.
		{
			strcpy(newuser,"");

			if (vncService::CurrentUser((char *) &newuser, sizeof(newuser)))
			{
				//vnclog.Print(LL_INTINFO,
				//	VNCLOG("############### Usernames change: old=\"%s\", new=\"%s\"\n"),
				//	_this->m_username, newuser);

				// Check whether the user name has changed!
				if (_stricmp(newuser, _this->m_username) != 0)
				{
					vnclog.Print(LL_INTINFO,
						VNCLOG("user name has changed\n"));

					// User has changed!
					strcpy(_this->m_username, newuser);

					// We should load in the prefs for the new user
					if (_this->m_properties.m_fUseRegistry)
						_this->m_properties.Load(TRUE);
					else
						_this->m_properties.LoadFromIniFile();
				}
			}
		}
		return 0;

	// [v1.0.2-jp1 fix] Don't show IME toolbar on right click menu.
	case WM_INITMENU:
	case WM_INITMENUPOPUP:
		SendMessage(ImmGetDefaultIMEWnd(hwnd), WM_IME_CONTROL, IMC_CLOSESTATUSWINDOW, 0);
		return 0;

	default:
		// Deal with any of our custom message types		
		// wa@2005 -- added support for the AutoReconnectId
		// removed the previous code that used 999,999
		if ( iMsg == MENU_STOP_RECONNECT_MSG )
		{
			_this->m_server->AutoReconnect(false);
		}
		if ( iMsg == MENU_STOP_ALL_RECONNECT_MSG )
		{
			_this->m_server->StopReconnectAll();
		}
		if ( iMsg == MENU_AUTO_RECONNECT_MSG )
		{
			char szId[MAX_PATH] = {0};
			UINT ret = 0;
			if ( lParam != 0 )
			{
				ret = GlobalGetAtomName( (ATOM)lParam, szId, sizeof( szId ) );
				GlobalDeleteAtom( (ATOM)lParam );
			}
			_this->m_server->AutoReconnect(true);
			
			if ( ret > 0 )
				_this->m_server->AutoReconnectId(szId);
			
			return 0;
		}
		if ( iMsg == MENU_REPEATER_ID_MSG )
 		{
			char szId[MAX_PATH] = {0};
			UINT ret = 0;
			if ( lParam != 0 )
			{
				ret = GlobalGetAtomName( (ATOM)lParam, szId, sizeof( szId ) );
				GlobalDeleteAtom( (ATOM)lParam );
			}
			_this->m_server->IdReconnect(true);
			
			if ( ret > 0 )
				_this->m_server->AutoReconnectId(szId);
			
			return 0;
		}

#ifdef IPV6V4

		if (iMsg == MENU_ADD_CLIENT6_MSG || iMsg == MENU_ADD_CLIENT6_MSG_INIT)
		{

			if (iMsg == MENU_ADD_CLIENT6_MSG_INIT)
				_this->m_server->AutoReconnectAdr("");

			// Add Client message.  This message includes an IP address
			// of a listening client, to which we should connect.

			//adzm 2009-06-20 - Check for special add repeater client message
			if (wParam == 0xFFFFFFFF && (ULONG)lParam == 0xFFFFFFFF) {
				vncConnDialog *newconn = new vncConnDialog(_this->m_server);
				if (newconn)
				{
					if (IDOK != newconn->DoDialog()) {
						if (SPECIAL_SC_PROMPT && _this->m_server->AuthClientCount() == 0 && _this->m_server->UnauthClientCount() == 0) {
							PostMessage(hwnd, WM_COMMAND, ID_CLOSE, 0);
						}
					}
				}
				return 0;
			}

			// If there is no IP address then show the connection dialog
			if (!lParam) {
				vncConnDialog *newconn = new vncConnDialog(_this->m_server);
				if (newconn)
				{
					newconn->DoDialog();
					// winvnc -connect fixed
					//CHECH memeory leak
					//			delete newconn;
				}
				return 0;
			}

			unsigned short nport = 0;
			char *nameDup = 0;
			char szAdrName[64];
			char szId[MAX_PATH] = { 0 };
			// sf@2003 - Values are already converted

			if (_this->m_server->m_retry_timeout != 0 && !fShutdownOrdered) Sleep(5000);

			if ((_this->m_server->AutoReconnect() || _this->m_server->IdReconnect()) && strlen(_this->m_server->AutoReconnectAdr()) > 0)
				{
					struct in6_addr address;
					memset(&address, 0, sizeof(address));
					nport = _this->m_server->AutoReconnectPort();
					VCard32 ipaddress = VSocket::Resolve6(_this->m_server->AutoReconnectAdr(), &address);
					char straddr[INET6_ADDRSTRLEN];
					memset(straddr, 0, INET6_ADDRSTRLEN);
					PCSTR test = inet_ntop(AF_INET6, &address, straddr, sizeof(straddr));
					if (strlen(straddr) == 0) return 0;
					nameDup = _strdup(straddr);
					if (nameDup == 0)
						return 0;
					strcpy(szAdrName, nameDup);
					// Free the duplicate name
					if (nameDup != 0) free(nameDup);
				}
				else
				{
					// Get the IP address stringified
					struct in6_addr address;
					memset(&address, 0, sizeof(address));
					char straddr[INET6_ADDRSTRLEN];
					memset(straddr, 0, INET6_ADDRSTRLEN);
					memcpy(&address, &G_LPARAM_IN6, sizeof(in6_addr));
					PCSTR test = inet_ntop(AF_INET6, &address, straddr, sizeof(straddr));
					if (strlen(straddr)== 0) return 0;
					nameDup = _strdup(straddr);
					if (nameDup == 0) return 0;
					strcpy(szAdrName, nameDup);
					// Free the duplicate name
					if (nameDup != 0) free(nameDup);
					// Get the port number
					nport = (unsigned short)wParam;
					if (nport == 0) nport = INCOMING_PORT_OFFSET;

				}
			// wa@2005 -- added support for the AutoReconnectId
			// (but it's not required)
			bool bId = (strlen(_this->m_server->AutoReconnectId()) > 0);
			if (bId)
				strcpy(szId, _this->m_server->AutoReconnectId());

			// sf@2003
			// Stores the client adr/ports the first time we try to connect
			// This way we can call this message again later to reconnect with the same values
			if ((_this->m_server->AutoReconnect() || _this->m_server->IdReconnect()) && strlen(_this->m_server->AutoReconnectAdr()) == 0)
			{
				if (strlen(dnsname)>0) _this->m_server->AutoReconnectAdr(dnsname);
				else
					_this->m_server->AutoReconnectAdr(szAdrName);
				strcpy(dnsname, "");

				_this->m_server->AutoReconnectPort(nport);
			}

			if (_this->m_server->AutoReconnect())
			{
				_this->m_server->AutoConnectRetry();
			}
			else
			{
				// Attempt to create a new socket
				VSocket *tmpsock;
				tmpsock = new VSocket;
				if (tmpsock) {
					// Connect out to the specified host on the VNCviewer listen port
#ifdef IPV6V4
					if (tmpsock->CreateConnect(szAdrName, nport))
#else
					tmpsock->Create();
					if (tmpsock->Connect(szAdrName, nport)) 
#endif 
					{
						if (bId)
						{
							// wa@2005 -- added support for the AutoReconnectId
							// Set the ID for this client -- code taken from vncconndialog.cpp (ln:142)
							tmpsock->Send(szId, 250);
							tmpsock->SetTimeout(0);

							// adzm 2009-07-05 - repeater IDs
							// Add the new client to this server
							// adzm 2009-08-02
							_this->m_server->AddClient(tmpsock, TRUE, TRUE, 0, NULL, szId, szAdrName, nport,true);
						}
						else {
							// Add the new client to this server
							// adzm 2009-08-02
							_this->m_server->AddClient(tmpsock, TRUE, TRUE, 0, NULL, NULL, szAdrName, nport,true);
						}
					}
					else {
						delete tmpsock;
					}
				}
			}

				return 0;
			}

		if (iMsg == MENU_ADD_CLIENT_MSG || iMsg == MENU_ADD_CLIENT_MSG_INIT)
		{

			if (iMsg == MENU_ADD_CLIENT_MSG_INIT) 
				_this->m_server->AutoReconnectAdr("");

			// Add Client message.  This message includes an IP address
			// of a listening client, to which we should connect.

			//adzm 2009-06-20 - Check for special add repeater client message
			if (wParam == 0xFFFFFFFF && (ULONG) lParam == 0xFFFFFFFF) {
				vncConnDialog *newconn = new vncConnDialog(_this->m_server);
				if (newconn)
				{
					if (IDOK != newconn->DoDialog()) {
						if (SPECIAL_SC_PROMPT && _this->m_server->AuthClientCount() == 0 && _this->m_server->UnauthClientCount() == 0) {
							PostMessage(hwnd, WM_COMMAND, ID_CLOSE, 0);
						}
					}
				}
				return 0;
			}

			// If there is no IP address then show the connection dialog
			if (!lParam) {
				vncConnDialog *newconn = new vncConnDialog(_this->m_server);
				if (newconn)
				{
					newconn->DoDialog();
					// winvnc -connect fixed
					//CHECH memeory leak
					//			delete newconn;
				}
				return 0;
			}

			unsigned short nport = 0;
			char *nameDup = 0;
			char szAdrName[64];
			char szId[MAX_PATH] = {0};
			// sf@2003 - Values are already converted

			if (_this->m_server->m_retry_timeout!=0 && !fShutdownOrdered) Sleep(5000);
			if ((_this->m_server->AutoReconnect() || _this->m_server->IdReconnect()) && strlen(_this->m_server->AutoReconnectAdr()) > 0)
				{
					struct in_addr address;
					nport = _this->m_server->AutoReconnectPort();
					VCard32 ipaddress = VSocket::Resolve4(_this->m_server->AutoReconnectAdr());
					unsigned long ipaddress_long = ipaddress;
					address.S_un.S_addr = ipaddress_long;
					char *name = inet_ntoa(address);
					if (name == 0)
						return 0;
					nameDup = _strdup(name);
					if (nameDup == 0)
						return 0;
					strcpy(szAdrName, nameDup);
					// Free the duplicate name
					if (nameDup != 0) free(nameDup);
				}
				else
				{
					// Get the IP address stringified
					struct in_addr address;
					address.S_un.S_addr = lParam;
					char *name = inet_ntoa(address);
					if (name == 0)
						return 0;
					nameDup = _strdup(name);
					if (nameDup == 0)
						return 0;
					strcpy(szAdrName, nameDup);
					// Free the duplicate name
					if (nameDup != 0) free(nameDup);

					// Get the port number
					nport = (unsigned short)wParam;
					if (nport == 0)
						nport = INCOMING_PORT_OFFSET;

				}
			// wa@2005 -- added support for the AutoReconnectId
			// (but it's not required)
			bool bId = ( strlen(_this->m_server->AutoReconnectId() ) > 0);
			if ( bId )
				strcpy( szId, _this->m_server->AutoReconnectId() );

			// sf@2003
			// Stores the client adr/ports the first time we try to connect
			// This way we can call this message again later to reconnect with the same values
			if ((_this->m_server->AutoReconnect() || _this->m_server->IdReconnect())&& strlen(_this->m_server->AutoReconnectAdr()) == 0)
			{
				if (strlen(dnsname)>0) _this->m_server->AutoReconnectAdr(dnsname);
				else 
					_this->m_server->AutoReconnectAdr(szAdrName);
				strcpy(dnsname,"");

				_this->m_server->AutoReconnectPort(nport);
			}

			if (_this->m_server->AutoReconnect())
			{
				_this->m_server->AutoConnectRetry();
			}
			else
			{
				// Attempt to create a new socket
				VSocket *tmpsock;
				tmpsock = new VSocket;
				if (tmpsock) {
					// Connect out to the specified host on the VNCviewer listen port
#ifdef IPV6V4
					if (tmpsock->CreateConnect(szAdrName, nport))
#else
					tmpsock->Create();
					if (tmpsock->Connect(szAdrName, nport))
#endif 
					{
						if (bId)
						{
							// wa@2005 -- added support for the AutoReconnectId
							// Set the ID for this client -- code taken from vncconndialog.cpp (ln:142)
							tmpsock->Send(szId, 250);
							tmpsock->SetTimeout(0);

							// adzm 2009-07-05 - repeater IDs
							// Add the new client to this server
							// adzm 2009-08-02
							_this->m_server->AddClient(tmpsock, TRUE, TRUE, 0, NULL, szId, szAdrName, nport,true);
						}
						else {
							// Add the new client to this server
							// adzm 2009-08-02
							_this->m_server->AddClient(tmpsock, TRUE, TRUE, 0, NULL, NULL, szAdrName, nport,true);
						}
					}
					else {
						delete tmpsock;
					}
				}
			}

			return 0;
		}
#else
		if (iMsg == MENU_ADD_CLIENT_MSG || iMsg == MENU_ADD_CLIENT_MSG_INIT)
		{

			if (iMsg == MENU_ADD_CLIENT_MSG_INIT)
				_this->m_server->AutoReconnectAdr("");

			// Add Client message.  This message includes an IP address
			// of a listening client, to which we should connect.

			//adzm 2009-06-20 - Check for special add repeater client message
			if (wParam == 0xFFFFFFFF && (ULONG)lParam == 0xFFFFFFFF) {
				vncConnDialog *newconn = new vncConnDialog(_this->m_server);
				if (newconn)
				{
					if (IDOK != newconn->DoDialog()) {
						if (SPECIAL_SC_PROMPT && _this->m_server->AuthClientCount() == 0 && _this->m_server->UnauthClientCount() == 0) {
							PostMessage(hwnd, WM_COMMAND, ID_CLOSE, 0);
						}
					}
				}
				return 0;
			}

			// If there is no IP address then show the connection dialog
			if (!lParam) {
				vncConnDialog *newconn = new vncConnDialog(_this->m_server);
				if (newconn)
				{
					newconn->DoDialog();
					// winvnc -connect fixed
					//CHECH memeory leak
					//			delete newconn;
				}
				return 0;
			}

			unsigned short nport = 0;
			char *nameDup = 0;
			char szAdrName[64];
			char szId[MAX_PATH] = { 0 };
			// sf@2003 - Values are already converted

			if (_this->m_server->m_retry_timeout != 0 && !fShutdownOrdered) Sleep(5000);


			if ((_this->m_server->AutoReconnect()|| _this->m_server->IdReconnect() )&& strlen(_this->m_server->AutoReconnectAdr()) > 0)
			{
				struct in_addr address;
				nport = _this->m_server->AutoReconnectPort();
				VCard32 ipaddress = VSocket::Resolve(_this->m_server->AutoReconnectAdr());
				unsigned long ipaddress_long=ipaddress;
				address.S_un.S_addr = ipaddress_long;
				char *name = inet_ntoa(address);
				if (name == 0)
					return 0;
				nameDup = _strdup(name);
				if (nameDup == 0)
					return 0;
				strcpy(szAdrName, nameDup);
				// Free the duplicate name
				if (nameDup != 0) free(nameDup);
			}
			else
			{
				// Get the IP address stringified
				struct in_addr address;
				address.S_un.S_addr = lParam;
				char *name = inet_ntoa(address);
				if (name == 0)
					return 0;
				nameDup = _strdup(name);
				if (nameDup == 0)
					return 0;
				strcpy(szAdrName, nameDup);
				// Free the duplicate name
				if (nameDup != 0) free(nameDup);

				// Get the port number
				nport = (unsigned short)wParam;
				if (nport == 0)
					nport = INCOMING_PORT_OFFSET;

			}

			// wa@2005 -- added support for the AutoReconnectId
			// (but it's not required)
			bool bId = (strlen(_this->m_server->AutoReconnectId()) > 0);
			if (bId)
				strcpy(szId, _this->m_server->AutoReconnectId());

			// sf@2003
			// Stores the client adr/ports the first time we try to connect
			// This way we can call this message again later to reconnect with the same values
			if ((_this->m_server->AutoReconnect() || _this->m_server->IdReconnect()) && strlen(_this->m_server->AutoReconnectAdr()) == 0)
			{
				if (strlen(dnsname)>0) _this->m_server->AutoReconnectAdr(dnsname);
				else
					_this->m_server->AutoReconnectAdr(szAdrName);
				strcpy(dnsname, "");

				_this->m_server->AutoReconnectPort(nport);
			}

			if (_this->m_server->AutoReconnect())
			{
				_this->m_server->AutoConnectRetry();
			}
			else
			{
				// Attempt to create a new socket
				VSocket *tmpsock;
				tmpsock = new VSocket;
				if (tmpsock) {
					{
						tmpsock->Create();
						if (tmpsock->Connect(szAdrName, nport)) {
							if (bId)
							{
								// wa@2005 -- added support for the AutoReconnectId
								// Set the ID for this client -- code taken from vncconndialog.cpp (ln:142)
								tmpsock->Send(szId, 250);
								tmpsock->SetTimeout(0);

								// adzm 2009-07-05 - repeater IDs
								// Add the new client to this server
								// adzm 2009-08-02
								_this->m_server->AddClient(tmpsock, TRUE, TRUE, 0, NULL, szId, szAdrName, nport,true);
							}
							else {
								// Add the new client to this server
								// adzm 2009-08-02
								_this->m_server->AddClient(tmpsock, TRUE, TRUE, 0, NULL, NULL, szAdrName, nport,true);
							}
						}
						else {
							delete tmpsock;
						}
					}
				}
			}

			return 0;
		}
#endif


		// Process FileTransfer asynchronous Send Packet Message
		if (iMsg == FileTransferSendPacketMessage) 
		{
		  vncClient* pClient = (vncClient*) wParam;
		  if (_this->m_server->IsClient(pClient)) pClient->SendFileChunk();
		}

	}

	// Message not recognised
	return DefWindowProc(hwnd, iMsg, wParam, lParam);
}
