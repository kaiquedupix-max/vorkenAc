using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Vorken.Agent;

internal static class AuthenticodeVerifier
{
    private static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_IGNORE = 0;

    public static (bool Trusted, string Subject) Verify(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return (false, "");

        IntPtr filePathPtr = IntPtr.Zero;
        IntPtr fileInfoPtr = IntPtr.Zero;
        IntPtr trustDataPtr = IntPtr.Zero;

        try
        {
            filePathPtr = Marshal.StringToCoTaskMemUni(path);

            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePathPtr,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            fileInfoPtr = Marshal.AllocCoTaskMem(
                Marshal.SizeOf<WINTRUST_FILE_INFO>());

            Marshal.StructureToPtr(
                fileInfo,
                fileInfoPtr,
                false);

            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_IGNORE,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = 0,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            trustDataPtr = Marshal.AllocCoTaskMem(
                Marshal.SizeOf<WINTRUST_DATA>());

            Marshal.StructureToPtr(
                trustData,
                trustDataPtr,
                false);

            Guid action = WinTrustActionGenericVerifyV2;

            int status = WinVerifyTrust(
                IntPtr.Zero,
                ref action,
                trustDataPtr);

            if (status != 0)
                return (false, "");

            try
            {
                X509Certificate certificate =
                    X509Certificate.CreateFromSignedFile(path);

                using var certificate2 =
                    new X509Certificate2(certificate);

                return (true, certificate2.Subject ?? "");
            }
            catch
            {
                return (true, "");
            }
        }
        catch
        {
            return (false, "");
        }
        finally
        {
            if (trustDataPtr != IntPtr.Zero)
                Marshal.FreeCoTaskMem(trustDataPtr);

            if (fileInfoPtr != IntPtr.Zero)
                Marshal.FreeCoTaskMem(fileInfoPtr);

            if (filePathPtr != IntPtr.Zero)
                Marshal.FreeCoTaskMem(filePathPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport(
        "wintrust.dll",
        ExactSpelling = true,
        SetLastError = true)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        ref Guid pgActionID,
        IntPtr pWVTData);
}
