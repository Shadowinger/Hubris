using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Hubris.Control;
using Hubris.Transport;

namespace Hubris.Auth;

/// <summary>Where refresh/access tokens live: the OS secret store, never config.json or SQLite.</summary>
public interface ISecureTokenStore
{
    StoredToken? Get(string account);
    /// <summary>Reads past any memory copy: another hub may have refreshed this token since we last looked.</summary>
    StoredToken? Reload(string account);
    void Set(string account, StoredToken token);
    void Delete(string account);
}

public static class SecureTokenStores
{
    public const string Service = "com.hubris.mcp.oauth";

    /// <summary>Keychain on macOS, Credential Manager on Windows, a 0600 file elsewhere; memory-cached so calls never wait on OS IPC.</summary>
    public static ISecureTokenStore ForThisOs()
    {
        ISecureTokenStore? os =
            OperatingSystem.IsMacOS() ? new MacOsKeychainStore()
            : OperatingSystem.IsWindows() ? new WindowsCredentialStore()
            : null;
        return Build(os, new FileTokenStore(TokensDir));
    }

    public static string TokensDir => Path.Combine(HubrisPaths.HomeDir, "tokens");

    /// <summary>Memory cache over the OS store with the file store as fallback; with no OS store the file store alone (never both over one directory).</summary>
    public static ISecureTokenStore Build(ISecureTokenStore? os, FileTokenStore file)
        => new CachingTokenStore(os is null ? file : new FallbackTokenStore(os, file));
}

/// <summary>Memory layer: a token is read from the OS once and then served from memory until it is replaced or deleted.</summary>
public sealed class CachingTokenStore : ISecureTokenStore
{
    private readonly ISecureTokenStore _inner;
    private readonly Dictionary<string, StoredToken?> _cache = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public CachingTokenStore(ISecureTokenStore inner) => _inner = inner;

    public StoredToken? Get(string account)
    {
        lock (_gate)
        {
            if (_cache.TryGetValue(account, out var t)) return t;
            t = _inner.Get(account);
            _cache[account] = t;
            return t;
        }
    }

    public StoredToken? Reload(string account)
    {
        lock (_gate)
        {
            var t = _inner.Reload(account);
            _cache[account] = t;
            return t;
        }
    }

    public void Set(string account, StoredToken token)
    {
        lock (_gate)
        {
            _inner.Set(account, token);
            _cache[account] = token;
        }
    }

    public void Delete(string account)
    {
        lock (_gate)
        {
            _inner.Delete(account);
            _cache[account] = null;
        }
    }
}

/// <summary>
/// The OS store first; when it refuses (the keychain would need a dialog, blob too large) the 0600 file keeps the
/// login working. A file is only ever written after the OS store refused, so when one exists it is the newest copy:
/// reads take it first and writes stay with it, otherwise two hubs with different keychain access would each keep
/// their own copy and one of them would spend an already rotated refresh token.
/// </summary>
public sealed class FallbackTokenStore : ISecureTokenStore
{
    private readonly ISecureTokenStore _primary, _fallback;
    public FallbackTokenStore(ISecureTokenStore primary, ISecureTokenStore fallback) { _primary = primary; _fallback = fallback; }

    public StoredToken? Get(string account)
    {
        if (_fallback.Get(account) is { } file) return file;
        try { return _primary.Get(account); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Refused(ex); return null; }
    }

    public StoredToken? Reload(string account)
    {
        if (_fallback.Reload(account) is { } file) return file;
        try { return _primary.Reload(account); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Refused(ex); return null; }
    }

    public void Set(string account, StoredToken token)
    {
        if (_fallback.Get(account) is not null) { _fallback.Set(account, token); return; }
        try { _primary.Set(account, token); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Refused(ex); _fallback.Set(account, token); }
    }

    private int _warned;
    private void Refused(Exception ex)
    {
        if (Interlocked.Exchange(ref _warned, 1) == 0) Log.Warn($"token store: {ex.Message}; using the file store");
    }

    public void Delete(string account)
    {
        try { _primary.Delete(account); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Log.Warn($"token store: {ex.Message}"); }
        _fallback.Delete(account);
    }
}

/// <summary>One JSON file per account under a 0700 directory, each 0600. Linux has no in-box secret store.</summary>
public sealed class FileTokenStore : ISecureTokenStore
{
    private readonly string _dir;
    public FileTokenStore(string dir) => _dir = dir;

    private string PathFor(string account)
    {
        var safe = new StringBuilder(account.Length);
        foreach (char c in account) safe.Append(char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_');
        return Path.Combine(_dir, safe + ".json");
    }

    public StoredToken? Get(string account)
    {
        string path = PathFor(account);
        if (!File.Exists(path)) return null;
        try { return JsonSerializer.Deserialize(File.ReadAllBytes(path), AuthJsonContext.Default.StoredToken); }
        catch (JsonException ex) { Log.Warn($"token file {path} unreadable: {ex.Message}"); return null; }
    }

    public StoredToken? Reload(string account) => Get(account);

    public void Set(string account, StoredToken token)
    {
        // Created 0700 / 0600 from the first byte: a chmod after the write would leave a umask-sized window.
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(_dir);
        else Directory.CreateDirectory(_dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string path = PathFor(account), tmp = path + ".tmp";
        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var fs = new FileStream(tmp, options)) fs.Write(JsonSerializer.SerializeToUtf8Bytes(token, AuthJsonContext.Default.StoredToken));
        File.Move(tmp, path, overwrite: true);
    }

    public void Delete(string account)
    {
        try { File.Delete(PathFor(account)); } catch (IOException ex) { Log.Debug($"token file delete: {ex.Message}"); }
    }
}

/// <summary>
/// One generic-password item in the login keychain (service <see cref="SecureTokenStores.Service"/>, account "vault")
/// holding a JSON map of every provider's token. Updates go through SecItemUpdate so the item keeps its access
/// list. The map is read once per process and served from memory; the keychain is touched again only when a token
/// changes. No call ever shows a dialog (see the constructor).
/// </summary>
[SupportedOSPlatform("macos")]
public sealed partial class MacOsKeychainStore : ISecureTokenStore
{
    public const string VaultAccount = "vault";

    private const string SecurityLib = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundationLib = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const uint CfStringEncodingUtf8 = 0x08000100;
    private const int ErrSecItemNotFound = -25300;

    [LibraryImport(SecurityLib)] private static partial int SecItemAdd(nint attributes, nint result);
    [LibraryImport(SecurityLib)] private static partial int SecItemCopyMatching(nint query, out nint result);
    [LibraryImport(SecurityLib)] private static partial int SecItemUpdate(nint query, nint attributesToUpdate);
    [LibraryImport(SecurityLib)] private static partial int SecItemDelete(nint query);
    [LibraryImport(SecurityLib)] private static partial int SecKeychainSetUserInteractionAllowed(byte state);

    /// <summary>
    /// The hub is a background process: a keychain dialog from it appears out of nowhere (every refresh, on every
    /// hub) and blocks the call behind it. With interaction off, an item this binary may not read fails at once
    /// (errSecAuthFailed, -25293) and the caller falls back to the file store.
    /// </summary>
    public MacOsKeychainStore()
    {
        int status = SecKeychainSetUserInteractionAllowed(0);
        if (status != 0) Log.Warn($"keychain: could not turn dialogs off (OSStatus {status})");
    }
    [LibraryImport(CoreFoundationLib)] private static partial nint CFDictionaryCreate(nint allocator, nint keys, nint values, nint count, nint keyCallBacks, nint valueCallBacks);
    [LibraryImport(CoreFoundationLib)] private static partial nint CFStringCreateWithCString(nint allocator, nint cString, uint encoding);
    [LibraryImport(CoreFoundationLib)] private static partial nint CFDataCreate(nint allocator, nint bytes, nint length);
    [LibraryImport(CoreFoundationLib)] private static partial nint CFDataGetLength(nint data);
    [LibraryImport(CoreFoundationLib)] private static partial nint CFDataGetBytePtr(nint data);
    [LibraryImport(CoreFoundationLib)] private static partial void CFRelease(nint cf);

    private static readonly nint Security = NativeLibrary.Load(SecurityLib);
    private static readonly nint CoreFoundation = NativeLibrary.Load(CoreFoundationLib);
    private static nint Const(nint lib, string symbol) => Marshal.ReadIntPtr(NativeLibrary.GetExport(lib, symbol)); // exported CFTypeRef globals

    private static readonly nint KSecClass = Const(Security, "kSecClass");
    private static readonly nint KSecClassGenericPassword = Const(Security, "kSecClassGenericPassword");
    private static readonly nint KSecAttrService = Const(Security, "kSecAttrService");
    private static readonly nint KSecAttrAccount = Const(Security, "kSecAttrAccount");
    private static readonly nint KSecValueData = Const(Security, "kSecValueData");
    private static readonly nint KSecReturnData = Const(Security, "kSecReturnData");
    private static readonly nint KSecMatchLimit = Const(Security, "kSecMatchLimit");
    private static readonly nint KSecMatchLimitOne = Const(Security, "kSecMatchLimitOne");
    private static readonly nint KCFBooleanTrue = Const(CoreFoundation, "kCFBooleanTrue");
    private static readonly nint KeyCallBacks = NativeLibrary.GetExport(CoreFoundation, "kCFTypeDictionaryKeyCallBacks");     // address of the struct
    private static readonly nint ValueCallBacks = NativeLibrary.GetExport(CoreFoundation, "kCFTypeDictionaryValueCallBacks");

    private readonly object _gate = new();
    private Dictionary<string, StoredToken>? _vault;

    public StoredToken? Get(string account)
    {
        lock (_gate)
        {
            var vault = Load();
            if (vault.TryGetValue(account, out var t)) return t;
            // Items written before the vault existed (one per provider): adopt them once, so the old prompts go away.
            var legacy = ReadItem(account);
            if (legacy is null) return null;
            vault[account] = legacy;
            WriteVault(vault);
            DeleteItem(account);
            Log.Info($"keychain: moved '{account}' into the Hubris vault item");
            return legacy;
        }
    }

    public StoredToken? Reload(string account)
    {
        lock (_gate)
        {
            _vault = null;
            return Get(account);
        }
    }

    public void Set(string account, StoredToken token)
    {
        lock (_gate)
        {
            _vault = null; // merge into what another hub may have written since we loaded
            var vault = Load();
            vault[account] = token;
            WriteVault(vault);
        }
    }

    public void Delete(string account)
    {
        lock (_gate)
        {
            _vault = null;
            var vault = Load();
            if (vault.Remove(account)) WriteVault(vault);
            DeleteItem(account); // a legacy item of that name, if any
        }
    }

    private Dictionary<string, StoredToken> Load()
    {
        if (_vault is not null) return _vault;
        byte[]? json = ReadBytes(VaultAccount);
        Dictionary<string, StoredToken>? map = null;
        if (json is not null)
        {
            try { map = JsonSerializer.Deserialize(json, AuthJsonContext.Default.DictionaryStringStoredToken); }
            catch (JsonException ex) { Log.Warn($"keychain vault unreadable, starting empty: {ex.Message}"); }
        }
        return _vault = map ?? new Dictionary<string, StoredToken>(StringComparer.Ordinal);
    }

    /// <summary>SecItemUpdate first: a delete + add would throw away the ACL the user granted with "Always Allow".</summary>
    private void WriteVault(Dictionary<string, StoredToken> vault)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(vault, AuthJsonContext.Default.DictionaryStringStoredToken);
        nint service = CfString(SecureTokenStores.Service), acct = CfString(VaultAccount), data = CfData(json);
        nint query = CfDict([KSecClass, KSecAttrService, KSecAttrAccount], [KSecClassGenericPassword, service, acct]);
        nint update = CfDict([KSecValueData], [data]);
        nint add = 0;
        try
        {
            int status = SecItemUpdate(query, update);
            if (status == ErrSecItemNotFound)
            {
                add = CfDict([KSecClass, KSecAttrService, KSecAttrAccount, KSecValueData], [KSecClassGenericPassword, service, acct, data]);
                status = SecItemAdd(add, 0);
            }
            if (status != 0) throw new IOException($"keychain write failed (OSStatus {status})");
        }
        finally
        {
            CFRelease(query); CFRelease(update); if (add != 0) CFRelease(add);
            CFRelease(service); CFRelease(acct); CFRelease(data);
        }
    }

    private static StoredToken? ReadItem(string account)
    {
        byte[]? json = ReadBytes(account);
        if (json is null) return null;
        try { return JsonSerializer.Deserialize(json, AuthJsonContext.Default.StoredToken); }
        catch (JsonException ex) { Log.Warn($"keychain item '{account}' unreadable: {ex.Message}"); return null; }
    }

    private static byte[]? ReadBytes(string account)
    {
        nint service = CfString(SecureTokenStores.Service), acct = CfString(account);
        nint query = CfDict([KSecClass, KSecAttrService, KSecAttrAccount, KSecReturnData, KSecMatchLimit],
                            [KSecClassGenericPassword, service, acct, KCFBooleanTrue, KSecMatchLimitOne]);
        try
        {
            int status = SecItemCopyMatching(query, out nint data);
            if (status == ErrSecItemNotFound) return null;
            if (status != 0) throw new IOException($"keychain read failed (OSStatus {status})");
            try
            {
                int len = checked((int)CFDataGetLength(data));
                var bytes = new byte[len];
                Marshal.Copy(CFDataGetBytePtr(data), bytes, 0, len);
                return bytes;
            }
            finally { CFRelease(data); }
        }
        finally { CFRelease(query); CFRelease(service); CFRelease(acct); }
    }

    private static void DeleteItem(string account)
    {
        nint service = CfString(SecureTokenStores.Service), acct = CfString(account);
        nint query = CfDict([KSecClass, KSecAttrService, KSecAttrAccount], [KSecClassGenericPassword, service, acct]);
        try
        {
            int status = SecItemDelete(query);
            if (status != 0 && status != ErrSecItemNotFound) throw new IOException($"keychain delete failed (OSStatus {status})");
        }
        finally { CFRelease(query); CFRelease(service); CFRelease(acct); }
    }

    private static nint CfString(string s)
    {
        nint utf8 = Marshal.StringToCoTaskMemUTF8(s);
        try { return CFStringCreateWithCString(0, utf8, CfStringEncodingUtf8); }
        finally { Marshal.FreeCoTaskMem(utf8); }
    }

    private static nint CfData(byte[] bytes)
    {
        nint buf = Marshal.AllocHGlobal(bytes.Length);
        try { Marshal.Copy(bytes, 0, buf, bytes.Length); return CFDataCreate(0, buf, bytes.Length); } // CFDataCreate copies
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static nint CfDict(nint[] keys, nint[] values)
    {
        nint k = Marshal.AllocHGlobal(nint.Size * keys.Length), v = Marshal.AllocHGlobal(nint.Size * values.Length);
        try
        {
            Marshal.Copy(keys, 0, k, keys.Length);
            Marshal.Copy(values, 0, v, values.Length);
            return CFDictionaryCreate(0, k, v, keys.Length, KeyCallBacks, ValueCallBacks);
        }
        finally { Marshal.FreeHGlobal(k); Marshal.FreeHGlobal(v); }
    }
}

/// <summary>Generic credentials in the Windows Credential Manager (DPAPI-protected by the OS), target "service/account".</summary>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsCredentialStore : ISecureTokenStore
{
    private const uint CredTypeGeneric = 1;
    private const uint CredPersistLocalMachine = 2;
    private const int ErrorNotFound = 1168;
    private const int MaxBlob = 5 * 512; // CRED_MAX_CREDENTIAL_BLOB_SIZE

    [StructLayout(LayoutKind.Sequential)]
    private struct Credential
    {
        public uint Flags;
        public uint Type;
        public nint TargetName;
        public nint Comment;
        public long LastWritten;
        public uint CredentialBlobSize;
        public nint CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public nint Attributes;
        public nint TargetAlias;
        public nint UserName;
    }

    [LibraryImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredWrite(ref Credential credential, uint flags);

    [LibraryImport("advapi32.dll", EntryPoint = "CredReadW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredRead(string target, uint type, uint flags, out nint credential);

    [LibraryImport("advapi32.dll", EntryPoint = "CredDeleteW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredDelete(string target, uint type, uint flags);

    [LibraryImport("advapi32.dll")] private static partial void CredFree(nint buffer);

    private static string Target(string account) => SecureTokenStores.Service + "/" + account;

    public StoredToken? Reload(string account) => Get(account);

    public unsafe StoredToken? Get(string account)
    {
        if (!CredRead(Target(account), CredTypeGeneric, 0, out nint ptr))
        {
            int err = Marshal.GetLastPInvokeError();
            if (err == ErrorNotFound) return null;
            throw new IOException($"credential read failed (error {err})");
        }
        try
        {
            var cred = (Credential*)ptr;
            var bytes = new byte[cred->CredentialBlobSize];
            Marshal.Copy(cred->CredentialBlob, bytes, 0, bytes.Length);
            return JsonSerializer.Deserialize(bytes, AuthJsonContext.Default.StoredToken);
        }
        finally { CredFree(ptr); }
    }

    public void Set(string account, StoredToken token)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(token, AuthJsonContext.Default.StoredToken);
        if (json.Length > MaxBlob) throw new IOException($"token too large for the Credential Manager ({json.Length} B > {MaxBlob} B)");
        nint target = Marshal.StringToHGlobalUni(Target(account)), user = Marshal.StringToHGlobalUni(OAuthPkceFlow.ClientName), blob = Marshal.AllocHGlobal(json.Length);
        try
        {
            Marshal.Copy(json, 0, blob, json.Length);
            var cred = new Credential
            {
                Type = CredTypeGeneric, TargetName = target, CredentialBlobSize = (uint)json.Length, CredentialBlob = blob,
                Persist = CredPersistLocalMachine, UserName = user,
            };
            if (!CredWrite(ref cred, 0)) throw new IOException($"credential write failed (error {Marshal.GetLastPInvokeError()})");
        }
        finally { Marshal.FreeHGlobal(target); Marshal.FreeHGlobal(user); Marshal.FreeHGlobal(blob); }
    }

    public void Delete(string account)
    {
        if (!CredDelete(Target(account), CredTypeGeneric, 0))
        {
            int err = Marshal.GetLastPInvokeError();
            if (err != ErrorNotFound) throw new IOException($"credential delete failed (error {err})");
        }
    }
}
