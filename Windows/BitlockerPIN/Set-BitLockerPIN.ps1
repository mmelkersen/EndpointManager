<#
    .SYNOPSIS
    BitLocker PIN Setup

    .DESCRIPTION
    Prompts the interactive user to set a BitLocker PIN and applies it to the system drive.
    Logs activity locally in CMTrace format.

    .NOTES
    Author: WPNinjas
    Date: 2026-05-24
#>

param (
    [switch]$InvokeToInteractiveUser,
    [switch]$ShowUI
)

[string]$UserName = [Environment]::UserName

New-Variable -Name "RegistryKeyPath"        -Value "HKLM:\Software\WPNinjas\BitlockerPin" -Description "Shared var between runspaces" -Scope Global -Force
New-Variable -Name "LogLocation"            -Value "$env:ProgramData\WPNinjas\Logs"        -Description "Shared var between runspaces" -Scope Global -Force
New-Variable -Name "LogName"               -Value "BitLockerPIN-Set"                       -Description "Shared var between runspaces" -Scope Global -Force
New-Variable -Name "CancelUserClosingWindow" -Value $true                                  -Description "Shared var between runspaces" -Scope Global -Force

function Write-Log {
    param (
        [Parameter(Mandatory=$true)][string]$LogOutput,
        [Parameter(Mandatory=$true)][string]$ComponentName,
        [Parameter(Mandatory=$false)][string]$ScriptLine,
        [Parameter(Mandatory=$false)][string]$Path = "$PSScriptRoot\Logs",
        [Parameter(Mandatory=$false)][string]$Name,
        [Parameter(Mandatory=$false)][ValidateSet(1,2,3)][int]$LogLevel = 1
    )

    if (!$ScriptLine) { $ScriptLine = $MyInvocation.ScriptLineNumber }
    if (!$LogOutput)  { return }

    $FullLogName      = "$Path\$Name.log"
    $FullSecondaryLog = $FullLogName.Replace(".log", ".lo_")

    if (Test-Path $FullLogName) {
        if ((Get-Item $FullLogName).Length -gt 1024kb) {
            if (Test-Path $FullSecondaryLog) { Remove-Item -Path $FullSecondaryLog -Force }
            Rename-Item -Path $FullLogName -NewName $FullSecondaryLog
        }
    }

    if (!(Test-Path $Path)) { New-Item -ItemType Directory -Force -Path $Path -ErrorAction SilentlyContinue | Out-Null }

    $TimeGenerated = Get-Date -Format "HH':'mm':'ss.fffffff"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="">'
    $LineFormat = $LogOutput, $TimeGenerated, (Get-Date -Format MM-dd-yyyy),
                  "$ComponentName`:$ScriptLine",
                  [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                  $LogLevel,
                  [Threading.Thread]::CurrentThread.ManagedThreadId
    $Line = $Line -f $LineFormat

    try {
        Write-Host ("[$ComponentName`:$ScriptLine] $LogOutput")
        $Encoding = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::AppendAllLines($FullLogName, [string[]]$Line, $Encoding)
    } catch {}
}

function Start-LoadAssemblys {
    Add-Type -AssemblyName PresentationFramework, System.Drawing, System.Windows.Forms, WindowsFormsIntegration
}

function Start-RunAsSystemPresentToInteractiveUser {
    param ([string]$Path)

    $ApplicationLoader = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;

public class ApplicationLoader
{
    private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
    private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;
    public const uint SW_HIDE = 0x00000000;

    private enum WTS_CONNECTSTATE_CLASS { WTSActive, WTSConnected, WTSConnectQuery, WTSShadow, WTSDisconnected, WTSIdle, WTSListen, WTSReset, WTSDown, WTSInit }
    private enum WTS_INFO_CLASS { WTSInitialProgram, WTSApplicationName, WTSWorkingDirectory, WTSOEMId, WTSSessionId, WTSUserName, WTSWinStationName, WTSDomainName, WTSConnectState, WTSClientBuildNumber, WTSClientName, WTSClientDirectory, WTSClientProductId, WTSClientHardwareId, WTSClientAddress, WTSClientDisplay, WTSClientProtocolType }

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO { public readonly UInt32 SessionID; [MarshalAs(UnmanagedType.LPStr)] public readonly String pWinStationName; public readonly WTS_CONNECTSTATE_CLASS State; }

    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSQuerySessionInformation(System.IntPtr hServer, uint sessionId, WTS_INFO_CLASS wtsInfoClass, out System.IntPtr ppBuffer, out uint pBytesReturned);
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern int WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr ppSessionInfo, out int pCount);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr pMemory);

    [StructLayout(LayoutKind.Sequential)] public struct SECURITY_ATTRIBUTES { public int Length; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }
    [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO { public int cb; public String lpReserved; public String lpDesktop; public String lpTitle; public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }

    enum TOKEN_TYPE : int { TokenPrimary = 1, TokenImpersonation = 2 }
    enum SECURITY_IMPERSONATION_LEVEL : int { SecurityAnonymous = 0, SecurityIdentification = 1, SecurityImpersonation = 2, SecurityDelegation = 3 }

    public const int TOKEN_DUPLICATE    = 0x0002;
    public const uint MAXIMUM_ALLOWED   = 0x2000000;
    public const int NORMAL_PRIORITY_CLASS = 0x20;

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr hSnapshot);
    [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
    public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType, int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("advapi32", SetLastError = true), SuppressUnmanagedCodeSecurity] static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);

    public static bool StartProcessAndBypassUAC(String applicationName, string startingDir, out PROCESS_INFORMATION procInfo) {
        uint winlogonPid = 0;
        IntPtr hUserTokenDup = IntPtr.Zero, hPToken = IntPtr.Zero, hProcess = IntPtr.Zero;
        procInfo = new PROCESS_INFORMATION();
        uint dwSessionId = GetActiveUserSessionID();
        foreach (Process p in Process.GetProcessesByName("winlogon")) { if ((uint)p.SessionId == dwSessionId) { winlogonPid = (uint)p.Id; } }
        hProcess = OpenProcess(MAXIMUM_ALLOWED, false, winlogonPid);
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, ref hPToken)) { CloseHandle(hProcess); return false; }
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.Length = Marshal.SizeOf(sa);
        if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, ref sa, (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int)TOKEN_TYPE.TokenPrimary, ref hUserTokenDup)) { CloseHandle(hProcess); CloseHandle(hPToken); return false; }
        STARTUPINFO si = new STARTUPINFO();
        si.cb = (int)Marshal.SizeOf(si);
        si.lpDesktop = @"winsta0\default";
        si.dwFlags = SW_HIDE;
        bool result = CreateProcessAsUser(hUserTokenDup, null, applicationName, ref sa, ref sa, false, NORMAL_PRIORITY_CLASS, IntPtr.Zero, startingDir, ref si, out procInfo);
        CloseHandle(hProcess); CloseHandle(hPToken); CloseHandle(hUserTokenDup);
        return result;
    }

    public static uint GetActiveUserSessionID(string user_filter = null) {
        var activeSessionId = INVALID_SESSION_ID;
        var pSessionInfo = IntPtr.Zero;
        var sessionCount = 0;
        IntPtr userPtr = IntPtr.Zero, domainPtr = IntPtr.Zero;
        uint bytes = 0;
        if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, out pSessionInfo, out sessionCount) != 0) {
            var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
            var current = pSessionInfo;
            for (var i = 0; i < sessionCount; i++) {
                var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                current += arrayElementSize;
                WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, si.SessionID, WTS_INFO_CLASS.WTSUserName, out userPtr, out bytes);
                WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, si.SessionID, WTS_INFO_CLASS.WTSDomainName, out domainPtr, out bytes);
                var user = Marshal.PtrToStringAnsi(userPtr);
                WTSFreeMemory(userPtr); WTSFreeMemory(domainPtr);
                if ((user_filter == null && si.State == WTS_CONNECTSTATE_CLASS.WTSActive) || (user == user_filter)) { activeSessionId = si.SessionID; }
            }
        }
        if (activeSessionId == INVALID_SESSION_ID) { activeSessionId = WTSGetActiveConsoleSessionId(); }
        return activeSessionId;
    }

    public void Execute(string applicationName) {
        ApplicationLoader.PROCESS_INFORMATION procInfo;
        ApplicationLoader.StartProcessAndBypassUAC(applicationName, null, out procInfo);
    }
}
"@

    Add-Type -TypeDefinition $ApplicationLoader
    $Loader      = New-Object ApplicationLoader
    $CommandLine = "powershell.exe -ExecutionPolicy Bypass -nologo -noprofile -windowstyle hidden -File `"$Path`" -InvokeToInteractiveUser"
    Write-Log -LogOutput "Executing '$CommandLine'" -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
    $Loader.Execute($CommandLine)
}

function Set-PinAcceptedState {
    if (!(Test-String -InputString $syncHash.pbx_passwordfirst.Password)) {
        $syncHash.tbx_passwordnotaccepted.Text    = "PIN must be 4-20 characters, no repeating or sequential characters."
        $syncHash.stk_passwordnotaccepted.Visibility = "Visible"
        $syncHash.btn_accept.IsEnabled            = $false
        return
    }
    if ($syncHash.pbx_passwordfirst.Password -ne $syncHash.pbx_passwordsecond.Password) {
        $syncHash.tbx_passwordnotaccepted.Text    = "PINs do not match."
        $syncHash.stk_passwordnotaccepted.Visibility = "Visible"
        $syncHash.btn_accept.IsEnabled            = $false
        return
    }
    $syncHash.stk_passwordnotaccepted.Visibility = "Hidden"
    $syncHash.btn_accept.IsEnabled               = $true
}

function Get-RegistryKey {
    param (
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Name
    )
    $regKey = Get-Item -LiteralPath $Key -ErrorAction SilentlyContinue
    if ($null -ne $regKey) {
        [string]$value = $regKey.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    }
    return $value
}

function Test-String {
    param ([Parameter(Mandatory=$true)][string]$InputString)

    if ($InputString.Length -lt 4 -or $InputString.Length -gt 20) { return $false }
    if ($InputString -match '(.)\1{2,}') { return $false }

    $alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for ($i = 0; $i -lt $alphabet.Length - 2; $i++) {
        if ($InputString.ToLower().Contains($alphabet.Substring($i, 3))) { return $false }
    }
    return $true
}

function Set-RegistryKey {
    param (
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Value,
        [Parameter(Mandatory=$true)][string]$Type
    )
    if (!(Test-Path -Path $Key)) { New-Item -Path $Key -Force | Out-Null }
    New-ItemProperty -Path $Key -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Update-Window {
    param ($Control, $Property, $Value, [switch]$AppendContent)

    if ($Property -eq "Close") {
        $syncHash.Window.Dispatcher.invoke([action] { $syncHash.Window.Close() }, "Normal")
        return
    }
    $syncHash.$Control.Dispatcher.Invoke([action] {
        if ($PSBoundParameters['AppendContent']) { $syncHash.$Control.AppendText($Value) }
        else { $syncHash.$Control.$Property = $Value }
    }, "Normal")
}

function Set-WindowWorkArea {
    param ([Parameter(Mandatory=$true)][string]$MiddleOrCorner)
    $area = [System.Windows.SystemParameters]::WorkArea
    if ($MiddleOrCorner -eq "Middle") {
        $syncHash.Window.Top  = ($area.Height / 2) - ($syncHash.Window.Height / 2)
        $syncHash.Window.Left = ($area.Width  / 2) - ($syncHash.Window.Width  / 2)
    } else {
        $syncHash.Window.Top  = $area.Height - $syncHash.Window.Height
        $syncHash.Window.Left = $area.Width  - $syncHash.Window.Width
    }
}

function Show-NotificationMessage {

    Start-LoadAssemblys

    $Global:SyncHash = [hashtable]::Synchronized(@{})

    $InitialSessionState = [initialsessionstate]::CreateDefault()
    Get-ChildItem function:/ | Where-Object Source -like "" | ForEach-Object {
        $def     = Get-Content "Function:\$($_.Name)"
        $entry   = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $_.Name, $def
        $InitialSessionState.Commands.Add($entry)
    }
    Get-ChildItem variable:/ | ForEach-Object {
        $varDef  = Get-Content "Variable:\$($_.Name)"
        $entry   = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList "$($_.Name)", $varDef, $null
        if ($_.Description -eq "Shared var between runspaces") { $InitialSessionState.Variables.Add($entry) }
    }

    $SyncHash.Add("SharedSessionState", $InitialSessionState)
    $newRunspace = [runspacefactory]::CreateRunspace($SyncHash["SharedSessionState"])
    $newRunspace.ApartmentState = "STA"
    $newRunspace.ThreadOptions  = "ReuseThread"
    $newRunspace.Open()
    $newRunspace.SessionStateProxy.SetVariable("syncHash", $SyncHash)

    [void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')

    $psCmd = [PowerShell]::Create().AddScript({

        [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="BitLocker PIN Setup" Height="440" Width="500"
        WindowStyle="None" ResizeMode="NoResize"
        Background="Transparent" AllowsTransparency="True"
        Topmost="True" ShowInTaskbar="False">
    <Window.Resources>

        <!-- Lock icon (white) -->
        <DrawingImage x:Key="icon_lock">
            <DrawingImage.Drawing>
                <DrawingGroup ClipGeometry="M0,0 V100 H100 V0 H0 Z">
                    <GeometryDrawing Geometry="F1 M100,100z M0,0z M74.5,93L25.5,93C23,93,21,91,21,88.5L21,45.5C21,43,23,41,25.5,41L74.5,41C77,41,79,43,79,45.5L79,88.5C79,91,77,93,74.5,93z">
                        <GeometryDrawing.Pen><Pen Brush="White" Thickness="4" StartLineCap="Flat" EndLineCap="Flat" LineJoin="Miter"/></GeometryDrawing.Pen>
                    </GeometryDrawing>
                    <GeometryDrawing Geometry="F1 M100,100z M0,0z M50,7L50,7C39,7,30,16,30,27L30,41 70,41 70,27C70,16,61,7,50,7z">
                        <GeometryDrawing.Pen><Pen Brush="White" Thickness="4" StartLineCap="Flat" EndLineCap="Flat" LineJoin="Miter"/></GeometryDrawing.Pen>
                    </GeometryDrawing>
                    <GeometryDrawing Geometry="F1 M100,100z M0,0z M56,63C56,59.7 53.3,57 50,57 46.7,57 44,59.7 44,63 44,65.2 45.2,67.2 47,68.2L47,76C47,77.7 48.3,79 50,79 51.7,79 53,77.7 53,76L53,68.2C54.8,67.2,56,65.2,56,63z">
                        <GeometryDrawing.Pen><Pen Brush="White" Thickness="3" StartLineCap="Flat" EndLineCap="Flat" LineJoin="Miter"/></GeometryDrawing.Pen>
                    </GeometryDrawing>
                </DrawingGroup>
            </DrawingImage.Drawing>
        </DrawingImage>

        <!-- Checkmark icon (green) -->
        <DrawingImage x:Key="icon_check">
            <DrawingImage.Drawing>
                <DrawingGroup ClipGeometry="M0,0 V100 H100 V0 H0 Z">
                    <GeometryDrawing>
                        <GeometryDrawing.Pen><Pen Brush="#2ECC71" Thickness="4"/></GeometryDrawing.Pen>
                        <GeometryDrawing.Geometry><EllipseGeometry RadiusX="38" RadiusY="38" Center="50,50"/></GeometryDrawing.Geometry>
                    </GeometryDrawing>
                    <GeometryDrawing Geometry="F1 M100,100z M0,0z M64.8,39.4L43.6,60.6 35.2,52.2">
                        <GeometryDrawing.Pen><Pen Brush="#2ECC71" Thickness="5" StartLineCap="Round" EndLineCap="Round" LineJoin="Round"/></GeometryDrawing.Pen>
                    </GeometryDrawing>
                </DrawingGroup>
            </DrawingImage.Drawing>
        </DrawingImage>

        <!-- Error X icon (red) -->
        <DrawingImage x:Key="icon_error">
            <DrawingImage.Drawing>
                <DrawingGroup ClipGeometry="M0,0 V100 H100 V0 H0 Z">
                    <GeometryDrawing>
                        <GeometryDrawing.Pen><Pen Brush="#E74C3C" Thickness="4"/></GeometryDrawing.Pen>
                        <GeometryDrawing.Geometry><EllipseGeometry RadiusX="38" RadiusY="38" Center="50,50"/></GeometryDrawing.Geometry>
                    </GeometryDrawing>
                    <GeometryDrawing>
                        <GeometryDrawing.Pen><Pen Brush="#E74C3C" Thickness="5" StartLineCap="Round" EndLineCap="Round"/></GeometryDrawing.Pen>
                        <GeometryDrawing.Geometry>
                            <GeometryGroup>
                                <LineGeometry StartPoint="34,34" EndPoint="66,66"/>
                                <LineGeometry StartPoint="66,34" EndPoint="34,66"/>
                            </GeometryGroup>
                        </GeometryDrawing.Geometry>
                    </GeometryDrawing>
                </DrawingGroup>
            </DrawingImage.Drawing>
        </DrawingImage>

        <!-- Fade-in animation (targets triggering element via empty TargetName binding) -->
        <Storyboard x:Key="FadeIn">
            <DoubleAnimation
                Storyboard.TargetName="{Binding}"
                Storyboard.TargetProperty="(UIElement.Opacity)"
                From="0.0" To="1.0" Duration="0:0:0.35"/>
            <DoubleAnimationUsingKeyFrames
                Storyboard.TargetName="{Binding}"
                Storyboard.TargetProperty="(UIElement.RenderTransform).(TranslateTransform.Y)"
                Duration="0:0:0.35">
                <LinearDoubleKeyFrame Value="0" KeyTime="0:0:0.35"/>
            </DoubleAnimationUsingKeyFrames>
        </Storyboard>

    </Window.Resources>

    <!-- Root: dark navy background, rounded border -->
    <Border CornerRadius="12" Background="#1A1A2E" BorderBrush="#3A3A5E" BorderThickness="1">
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
            </Grid.RowDefinitions>

            <!-- Red header bar -->
            <Border Grid.Row="0" Background="#C0392B" CornerRadius="12,12,0,0" Padding="24,16">
                <StackPanel Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center">
                    <Image Source="{StaticResource icon_lock}" Width="32" Height="32" Margin="0,0,14,0" VerticalAlignment="Center"/>
                    <StackPanel VerticalAlignment="Center">
                        <TextBlock Text="BitLocker PIN Setup" Foreground="White" FontSize="19" FontWeight="Bold" FontFamily="Segoe UI"/>
                        <TextBlock Text="wpninjas.no" Foreground="#FFCCCC" FontSize="11" FontFamily="Segoe UI" Opacity="0.85"/>
                    </StackPanel>
                </StackPanel>
            </Border>

            <!-- Content area -->
            <Grid Grid.Row="1" Margin="35,22,35,28">

                <!-- Input form (visible by default, collapses on success or error) -->
                <StackPanel x:Name="InputForm" Opacity="0">
                    <StackPanel.RenderTransform><TranslateTransform Y="10"/></StackPanel.RenderTransform>
                    <StackPanel.Triggers>
                        <EventTrigger RoutedEvent="StackPanel.Loaded">
                            <BeginStoryboard Storyboard="{StaticResource FadeIn}"/>
                        </EventTrigger>
                    </StackPanel.Triggers>
                    <StackPanel.Style>
                        <Style TargetType="StackPanel">
                            <Style.Triggers>
                                <DataTrigger Binding="{Binding IsEnabled, ElementName=indicator_success}" Value="True">
                                    <Setter Property="Visibility" Value="Collapsed"/>
                                </DataTrigger>
                                <DataTrigger Binding="{Binding IsEnabled, ElementName=indicator_error}" Value="True">
                                    <Setter Property="Visibility" Value="Collapsed"/>
                                </DataTrigger>
                            </Style.Triggers>
                        </Style>
                    </StackPanel.Style>

                    <TextBlock Foreground="#A8A8C8" FontSize="12" FontFamily="Segoe UI" TextWrapping="Wrap"
                               TextAlignment="Center" Margin="0,0,0,22">
                        Choose a PIN between 4 and 20 characters using only English alphabet characters.
                        Avoid repeating or sequential characters such as 1111 or abc.
                    </TextBlock>

                    <!-- Field 1 -->
                    <TextBlock Text="BitLocker PIN" Foreground="#E0E0F0" FontSize="12" FontWeight="SemiBold"
                               FontFamily="Segoe UI" Margin="0,0,0,5"/>
                    <Border BorderThickness="1.5" CornerRadius="6" BorderBrush="#3A3A5E" Background="#0D0D1A">
                        <PasswordBox x:Name="pbx_passwordfirst" Foreground="White" Background="Transparent"
                                     BorderThickness="0" Padding="10,8" FontSize="14"
                                     IsTabStop="True" TabIndex="1"/>
                    </Border>

                    <!-- Field 2 -->
                    <TextBlock Text="Confirm PIN" Foreground="#E0E0F0" FontSize="12" FontWeight="SemiBold"
                               FontFamily="Segoe UI" Margin="0,12,0,5"/>
                    <Border BorderThickness="1.5" CornerRadius="6" BorderBrush="#3A3A5E" Background="#0D0D1A">
                        <PasswordBox x:Name="pbx_passwordsecond" Foreground="White" Background="Transparent"
                                     BorderThickness="0" Padding="10,8" FontSize="14"
                                     IsTabStop="True" TabIndex="2"/>
                    </Border>

                    <!-- Validation message -->
                    <StackPanel x:Name="stk_passwordnotaccepted" Orientation="Horizontal" Margin="2,8,0,0"
                                Visibility="Hidden" Height="18">
                        <TextBlock x:Name="tbx_passwordnotaccepted" Foreground="#E74C3C"
                                   FontSize="11" FontFamily="Segoe UI" TextWrapping="Wrap"/>
                    </StackPanel>

                    <!-- Submit button -->
                    <Button x:Name="btn_accept" Margin="0,20,0,0" Height="44"
                            IsDefault="True" IsEnabled="False" IsTabStop="True" TabIndex="3" Cursor="Hand">
                        <Button.Style>
                            <Style TargetType="Button">
                                <Setter Property="Template">
                                    <Setter.Value>
                                        <ControlTemplate TargetType="Button">
                                            <Border x:Name="bg" CornerRadius="7" Background="#C0392B">
                                                <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                            </Border>
                                            <ControlTemplate.Triggers>
                                                <Trigger Property="IsEnabled" Value="False">
                                                    <Setter TargetName="bg" Property="Opacity" Value="0.35"/>
                                                </Trigger>
                                                <Trigger Property="IsMouseOver" Value="True">
                                                    <Setter TargetName="bg" Property="Background" Value="#E74C3C"/>
                                                </Trigger>
                                                <Trigger Property="IsPressed" Value="True">
                                                    <Setter TargetName="bg" Property="Background" Value="#922B21"/>
                                                </Trigger>
                                            </ControlTemplate.Triggers>
                                        </ControlTemplate>
                                    </Setter.Value>
                                </Setter>
                            </Style>
                        </Button.Style>
                        <TextBlock Text="Set PIN" Foreground="White" FontSize="14"
                                   FontWeight="SemiBold" FontFamily="Segoe UI"/>
                    </Button>
                </StackPanel>

                <!-- State indicator canvases (invisible, used as binding triggers) -->
                <Canvas x:Name="indicator_success" IsEnabled="False"/>
                <Canvas x:Name="indicator_error"   IsEnabled="False"/>

                <!-- Success panel -->
                <StackPanel x:Name="SuccessPanel" HorizontalAlignment="Center" VerticalAlignment="Center"
                            Opacity="0">
                    <StackPanel.RenderTransform><TranslateTransform Y="10"/></StackPanel.RenderTransform>
                    <StackPanel.Style>
                        <Style TargetType="StackPanel">
                            <Setter Property="Visibility" Value="Collapsed"/>
                            <Style.Triggers>
                                <DataTrigger Binding="{Binding IsEnabled, ElementName=indicator_success}" Value="True">
                                    <DataTrigger.EnterActions>
                                        <BeginStoryboard>
                                            <Storyboard>
                                                <DoubleAnimation Storyboard.TargetProperty="Opacity"
                                                    From="0" To="1" Duration="0:0:0.4"/>
                                                <DoubleAnimationUsingKeyFrames
                                                    Storyboard.TargetProperty="(RenderTransform).(TranslateTransform.Y)"
                                                    Duration="0:0:0.4">
                                                    <LinearDoubleKeyFrame Value="0" KeyTime="0:0:0.4"/>
                                                </DoubleAnimationUsingKeyFrames>
                                            </Storyboard>
                                        </BeginStoryboard>
                                    </DataTrigger.EnterActions>
                                    <Setter Property="Visibility" Value="Visible"/>
                                </DataTrigger>
                            </Style.Triggers>
                        </Style>
                    </StackPanel.Style>
                    <Image Source="{StaticResource icon_check}" Width="64" Height="64"
                           HorizontalAlignment="Center" Margin="0,0,0,16"/>
                    <TextBlock Text="PIN Set Successfully" Foreground="#2ECC71" FontSize="19"
                               FontWeight="Bold" FontFamily="Segoe UI" HorizontalAlignment="Center"
                               Margin="0,0,0,8"/>
                    <TextBlock Text="Your BitLocker PIN has been saved and applied to this device."
                               Foreground="#A8A8C8" FontSize="12" FontFamily="Segoe UI"
                               HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center"
                               Margin="0,0,0,28"/>
                    <Button x:Name="btn_close_success" IsCancel="True" HorizontalAlignment="Center"
                            Height="40" Width="180" Cursor="Hand">
                        <Button.Style>
                            <Style TargetType="Button">
                                <Setter Property="Template">
                                    <Setter.Value>
                                        <ControlTemplate TargetType="Button">
                                            <Border x:Name="bg" CornerRadius="7" BorderBrush="#2ECC71"
                                                    BorderThickness="1.5" Background="Transparent">
                                                <ContentPresenter HorizontalAlignment="Center"
                                                                  VerticalAlignment="Center" Margin="20,0"/>
                                            </Border>
                                            <ControlTemplate.Triggers>
                                                <Trigger Property="IsMouseOver" Value="True">
                                                    <Setter TargetName="bg" Property="Background" Value="#142A1E"/>
                                                </Trigger>
                                            </ControlTemplate.Triggers>
                                        </ControlTemplate>
                                    </Setter.Value>
                                </Setter>
                            </Style>
                        </Button.Style>
                        <TextBlock Text="Close" Foreground="#2ECC71" FontSize="13" FontFamily="Segoe UI"/>
                    </Button>
                </StackPanel>

                <!-- Error panel -->
                <StackPanel x:Name="ErrorPanel" HorizontalAlignment="Center" VerticalAlignment="Center"
                            Opacity="0">
                    <StackPanel.RenderTransform><TranslateTransform Y="10"/></StackPanel.RenderTransform>
                    <StackPanel.Style>
                        <Style TargetType="StackPanel">
                            <Setter Property="Visibility" Value="Collapsed"/>
                            <Style.Triggers>
                                <DataTrigger Binding="{Binding IsEnabled, ElementName=indicator_error}" Value="True">
                                    <DataTrigger.EnterActions>
                                        <BeginStoryboard>
                                            <Storyboard>
                                                <DoubleAnimation Storyboard.TargetProperty="Opacity"
                                                    From="0" To="1" Duration="0:0:0.4"/>
                                                <DoubleAnimationUsingKeyFrames
                                                    Storyboard.TargetProperty="(RenderTransform).(TranslateTransform.Y)"
                                                    Duration="0:0:0.4">
                                                    <LinearDoubleKeyFrame Value="0" KeyTime="0:0:0.4"/>
                                                </DoubleAnimationUsingKeyFrames>
                                            </Storyboard>
                                        </BeginStoryboard>
                                    </DataTrigger.EnterActions>
                                    <Setter Property="Visibility" Value="Visible"/>
                                </DataTrigger>
                            </Style.Triggers>
                        </Style>
                    </StackPanel.Style>
                    <Image Source="{StaticResource icon_error}" Width="64" Height="64"
                           HorizontalAlignment="Center" Margin="0,0,0,16"/>
                    <TextBlock Text="Failed to Set PIN" Foreground="#E74C3C" FontSize="19"
                               FontWeight="Bold" FontFamily="Segoe UI" HorizontalAlignment="Center"
                               Margin="0,0,0,8"/>
                    <TextBlock Text="Something went wrong. Please try again or contact your IT helpdesk."
                               Foreground="#A8A8C8" FontSize="12" FontFamily="Segoe UI"
                               HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center"
                               Margin="0,0,0,10"/>
                    <TextBox x:Name="tbx_stacktrace" IsReadOnly="True" Foreground="#888888"
                             Background="#0D0D1A" BorderBrush="#3A3A5E" BorderThickness="1"
                             FontSize="10" FontFamily="Consolas" TextWrapping="Wrap"
                             Height="48" Margin="0,0,0,18" Padding="6,4"/>
                    <Button x:Name="btn_close_error" IsCancel="True" HorizontalAlignment="Center"
                            Height="40" Width="180" Cursor="Hand">
                        <Button.Style>
                            <Style TargetType="Button">
                                <Setter Property="Template">
                                    <Setter.Value>
                                        <ControlTemplate TargetType="Button">
                                            <Border x:Name="bg" CornerRadius="7" BorderBrush="#E74C3C"
                                                    BorderThickness="1.5" Background="Transparent">
                                                <ContentPresenter HorizontalAlignment="Center"
                                                                  VerticalAlignment="Center" Margin="20,0"/>
                                            </Border>
                                            <ControlTemplate.Triggers>
                                                <Trigger Property="IsMouseOver" Value="True">
                                                    <Setter TargetName="bg" Property="Background" Value="#2A0D0D"/>
                                                </Trigger>
                                            </ControlTemplate.Triggers>
                                        </ControlTemplate>
                                    </Setter.Value>
                                </Setter>
                            </Style>
                        </Button.Style>
                        <TextBlock Text="Close" Foreground="#E74C3C" FontSize="13" FontFamily="Segoe UI"/>
                    </Button>
                </StackPanel>

            </Grid>
        </Grid>
    </Border>
</Window>
"@

        $reader = New-Object System.Xml.XmlNodeReader $xaml
        $syncHash.Window = [Windows.Markup.XamlReader]::Load($reader)

        $xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object {
            $syncHash.Add($_.Name, $syncHash.Window.FindName($_.Name))
        }

        Set-WindowWorkArea -MiddleOrCorner "Middle"

        $Script:JobCleanup = [hashtable]::Synchronized(@{})
        $Script:Jobs       = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

        $jobCleanup.Flag = $true
        $cleanupRunspace = [runspacefactory]::CreateRunspace()
        $cleanupRunspace.ApartmentState = "STA"
        $cleanupRunspace.ThreadOptions  = "ReuseThread"
        $cleanupRunspace.Open()
        $cleanupRunspace.SessionStateProxy.SetVariable("jobCleanup", $jobCleanup)
        $cleanupRunspace.SessionStateProxy.SetVariable("jobs", $jobs)
        $jobCleanup.PowerShell = [PowerShell]::Create().AddScript({
            do {
                foreach ($runspace in $jobs) {
                    if ($runspace.Runspace.isCompleted) {
                        [void]$runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                    }
                }
                $temp = $jobs.clone()
                $temp | Where-Object { $_.runspace -eq $null } | ForEach-Object { $jobs.remove($_) }
                Start-Sleep -Seconds 1
            } while ($jobCleanup.Flag)
        })
        $jobCleanup.PowerShell.Runspace = $cleanupRunspace
        $jobCleanup.Thread = $jobCleanup.PowerShell.BeginInvoke()

        $syncHash.btn_accept.Add_Click({
            $workerRunspace = [runspacefactory]::CreateRunspace($SyncHash["SharedSessionState"])
            $workerRunspace.ApartmentState = "STA"
            $workerRunspace.ThreadOptions  = "ReuseThread"
            $workerRunspace.Open()
            $workerRunspace.SessionStateProxy.SetVariable("SyncHash", $SyncHash)
            $ps = [PowerShell]::Create().AddScript({
                try {
                    Write-Log -LogOutput "Setting BitLocker PIN..." -ComponentName "Main" -Path $LogLocation -Name $LogName
                    Update-Window -Control "btn_accept" -Property "IsEnabled" -Value $false
                    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive `
                        -Pin (ConvertTo-SecureString $syncHash.pbx_passwordfirst.Password -AsPlainText -Force) `
                        -TpmAndPinProtector -ErrorAction Stop
                    Write-Log -LogOutput "BitLocker PIN set successfully." -ComponentName "Main" -Path $LogLocation -Name $LogName
                    Update-Window -Control "indicator_success" -Property "IsEnabled" -Value $true
                } catch {
                    Write-Log -LogOutput ("Failed to set PIN: {0}" -f $_) -ComponentName "Main" -Path $LogLocation -Name $LogName -LogLevel 3
                    Update-Window -Control "tbx_stacktrace" -Property "Text" -Value "$_"
                    Update-Window -Control "indicator_error" -Property "IsEnabled" -Value $true
                }
            })
            $ps.Runspace = $workerRunspace
            [void]$Jobs.Add([pscustomobject]@{ PowerShell = $ps; Runspace = $ps.BeginInvoke() })
        })

        $syncHash.pbx_passwordfirst.Add_PasswordChanged({ Set-PinAcceptedState })
        $syncHash.pbx_passwordsecond.Add_PasswordChanged({ Set-PinAcceptedState })

        $syncHash.btn_close_success.Add_Click({
            Write-Log -LogOutput "User closed success dialog." -ComponentName "Main" -Path $LogLocation -Name $LogName
            $Global:CancelUserClosingWindow = $false
        })
        $syncHash.btn_close_error.Add_Click({
            Write-Log -LogOutput "User closed error dialog." -ComponentName "Main" -Path $LogLocation -Name $LogName
            $Global:CancelUserClosingWindow = $false
        })

        $syncHash.Window.Add_Closing({
            Write-Log -LogOutput ("Window closing event, cancel='{0}'" -f $CancelUserClosingWindow) -ComponentName "Closing" -Path $LogLocation -Name $LogName
            $_.Cancel = $CancelUserClosingWindow
            if (!$CancelUserClosingWindow) {
                Update-Window -Property "Close"
                $jobCleanup.Flag = $false
                $jobCleanup.PowerShell.Dispose()
                [System.Windows.Forms.Application]::Exit()
                Stop-Process $pid
            }
        })

        $syncHash.Window.ShowDialog() | Out-Null
        $syncHash.Error = $Error
    })

    $psCmd.Runspace = $newRunspace
    $data = $psCmd.BeginInvoke()

    Set-RegistryKey -Key $RegistryKeyPath -Name "PID" -Value $pid -Type "STRING"

    $AppContext = New-Object System.Windows.Forms.ApplicationContext
    [void][System.Windows.Forms.Application]::Run($AppContext)
}

function Test-IfAnyLoggedOnUsers {
    $users = ((quser) -replace '\s{2,}', ',') -replace '>', '' | ConvertFrom-Csv
    if ($users) {
        foreach ($u in $users) {
            Write-Log -LogOutput ("Found logged on user '{0}'" -f $u.Username) -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
        }
        return $true
    }
    Write-Log -LogOutput "No logged on users found." -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
    return $false
}

function Test-BitLockerShouldBeResumed {
    [int]$SuspendCount   = (Get-CimInstance -Namespace "ROOT/CIMV2/Security/MicrosoftVolumeEncryption" -Class Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'" | Invoke-CimMethod -MethodName "GetSuspendCount").SuspendCount
    [string]$Protection  = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
    $shouldResume        = (!($SuspendCount -gt 0) -and $Protection -eq "Off")
    Write-Log -LogOutput ("SuspendCount='{0}' ProtectionStatus='{1}' ShouldResume='{2}'" -f $SuspendCount, $Protection, $shouldResume) -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
    return $shouldResume
}

function Test-BitLockerPINProtectorSet {
    $pinSet = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object { $_.KeyProtectorType -eq 'TpmPin' }
    if ($pinSet) {
        Write-Log -LogOutput "BitLocker PIN protector is set." -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
        return $true
    }
    Write-Log -LogOutput "BitLocker PIN protector is not set." -ComponentName $MyInvocation.MyCommand -Path $LogLocation -Name $LogName
    return $false
}

################################################
# Main
################################################

Write-Log -LogOutput "===== BitLocker PIN Set Script Start =====" -ComponentName "Main" -Path $LogLocation -Name $LogName

if ($ShowUI) {
    Write-Log -LogOutput "ShowUI switch set, skipping BitLocker validation and showing UI directly." -ComponentName "Main" -Path $LogLocation -Name $LogName
    Show-NotificationMessage
    return
}

if (Test-BitLockerShouldBeResumed) {
    Write-Log -LogOutput "Resuming BitLocker..." -ComponentName "Main" -Path $LogLocation -Name $LogName
    Resume-BitLocker -MountPoint $env:SystemDrive | Out-Null
}

if (!(Test-BitLockerPINProtectorSet)) {

    $runningPID = Get-RegistryKey -Key $RegistryKeyPath -Name "PID"
    if (-not [string]::IsNullOrEmpty($runningPID)) {
        if (Get-Process -Id $runningPID -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -eq "powershell" }) {
            Write-Log -LogOutput "Application is already running, exiting." -ComponentName "Main" -Path $LogLocation -Name $LogName
            Exit 1
        }
    }

    if (($UserName -eq "SYSTEM") -and !$InvokeToInteractiveUser) {
        if (Test-IfAnyLoggedOnUsers) {
            Write-Log -LogOutput "Running as SYSTEM, re-launching to interactive user session." -ComponentName "Main" -Path $LogLocation -Name $LogName
            Start-RunAsSystemPresentToInteractiveUser -Path $MyInvocation.MyCommand.Path
            break
        } else {
            Exit 2
        }
    }

    if ($InvokeToInteractiveUser) {
        Write-Log -LogOutput "Showing PIN prompt to user." -ComponentName "Main" -Path $LogLocation -Name $LogName
        Show-NotificationMessage
    }
}
