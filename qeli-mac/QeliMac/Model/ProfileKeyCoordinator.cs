using System.Diagnostics;
using System.Security.Cryptography;

namespace QeliMac.Model;

// Every cooperating GUI process serializes key selection and migration before using the key.
// FileShare.None is backed by .NET's Unix file locking on macOS; the OS releases it on exit.
internal sealed class ProfileKeyCoordinator(
    string directory, Func<byte[]?> findKeychain, Func<byte[], bool, bool> storeKeychain,
    Func<byte[]?> findLegacy, Func<bool> deleteLegacy)
{
    public byte[] GetOrCreate()
    {
        Directory.CreateDirectory(directory);
        var wait = Stopwatch.StartNew();
        FileStream keyLock;
        while (true)
        {
            try
            {
                keyLock = new FileStream(Path.Combine(directory, ".store.key.lock"),
                    FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                break;
            }
            catch (IOException) when (wait.Elapsed < TimeSpan.FromSeconds(1))
            {
                Thread.Sleep(25);
            }
        }
        using (keyLock) return GetOrCreateCore();
    }

    private bool HasEncryptedArchive()
    {
        foreach (var name in new[] { "profiles.json", "profiles.json.bak" })
        {
            byte[]? bytes = null;
            try
            {
                using var stream = File.OpenRead(Path.Combine(directory, name));
                bytes = BoundedStorage.Read(stream, Qeli.Shared.Model.ProfileStoreFile.MaximumStoredBytes);
                // A ciphertext nonce may itself start with '['. Only a complete valid
                // legacy archive permits first-key creation, never a punctuation heuristic.
                try
                {
                    _ = Qeli.Shared.Model.ProfileStorePayload.Decode(
                        new System.Text.UTF8Encoding(false, true).GetString(bytes));
                }
                catch (Exception error) when (error is System.Text.Json.JsonException
                    or System.Text.DecoderFallbackException)
                {
                    return true;
                }
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            finally { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
        }
        return false;
    }

    private string FallbackKeyFile => Path.Combine(directory, ".store.key");
    private string MigrationKeyFile => Path.Combine(directory, ".store.key.migration");

    /// <summary>Returns the AES-256 key, creating and persisting it on first use.</summary>
    private byte[] GetOrCreateCore()
    {
        // A migration journal is written and flushed before the legacy Keychain item is
        // touched. If the process or host died in the delete -> add window, recover that
        // exact key first; generating a replacement would make every encrypted profile
        // permanently unreadable.
        var migrationKey = FileFind(MigrationKeyFile);
        var fallbackKey = FileFind();
        if (migrationKey is { Length: 32 } && fallbackKey is { Length: 32 }
            && !CryptographicOperations.FixedTimeEquals(migrationKey, fallbackKey))
            throw new CryptographicException("Migration journal and fallback profile keys differ");
        byte[]? stored;
        try { stored = findKeychain(); }
        catch
        {
            // Preserve the old security-tool migration path when a legacy ACL denies
            // direct access. Only a recovered existing key authorizes migration.
            var legacyKey = findLegacy();
            if (legacyKey is { Length: 32 })
            {
                if (fallbackKey is { Length: 32 }
                    && !CryptographicOperations.FixedTimeEquals(legacyKey, fallbackKey))
                    throw new CryptographicException("Legacy Keychain and fallback keys differ");
                return MigrateKey(legacyKey);
            }
            if (migrationKey is { Length: 32 }) return CompleteMigration(migrationKey);
            if (fallbackKey is { Length: 32 }) return fallbackKey;
            // Refuse to invent a key when absence has not been established.
            throw;
        }
        var k = DecodeKeychainValue(stored);
        if (stored is not null && k is not { Length: 32 })
            throw new CryptographicException("The profile Keychain item is invalid; refusing to replace it");
        if (k is { Length: 32 })
        {
            if (fallbackKey is { Length: 32 }
                && !CryptographicOperations.FixedTimeEquals(k, fallbackKey))
                throw new CryptographicException("Keychain and fallback profile keys differ; refusing to choose a key");
            if (migrationKey is { Length: 32 }
                && !CryptographicOperations.FixedTimeEquals(k, migrationKey))
                throw new InvalidOperationException(
                    "The Keychain key does not match the interrupted migration journal; " +
                    "refusing to choose a key and risk profile loss");

            // Pre-0.7.15 stored base64 text through /usr/bin/security. Replace that
            // item with raw bytes and a Qeli-specific ACL without rotating the key.
            if (stored!.Length != 32)
                return MigrateKey(k);

            DeleteFileBestEffort(MigrationKeyFile);
            return k;
        }

        if (migrationKey is { Length: 32 })
            return CompleteMigration(migrationKey);

        // The old item's ACL trusted /usr/bin/security, so a direct application
        // lookup may be denied. Read it once through the legacy path, delete it,
        // and recreate it under the current application's designated requirement.
        k = findLegacy();
        if (k is { Length: 32 })
        {
            if (fallbackKey is { Length: 32 }
                && !CryptographicOperations.FixedTimeEquals(k, fallbackKey))
                throw new CryptographicException("Legacy Keychain and fallback keys differ");
            return MigrateKey(k);
        }

        if (fallbackKey is { Length: 32 }) return fallbackKey;

        // A missing/denied key must never rotate an existing encrypted archive.
        // Keep the original available for explicit recovery instead of quarantine.
        if (HasEncryptedArchive())
            throw new CryptographicException("The profile encryption key is unavailable; the archive was not changed");

        var key = RandomNumberGenerator.GetBytes(32);
        // FAIL LOUD if the key cannot be persisted anywhere. Returning an unsaved key was
        // silent data loss: the caller encrypts the profile store with it, and on the next
        // launch neither the Keychain nor the fallback file has it — every saved profile is
        // permanently undecryptable, with nothing having reported a problem. Better to
        // refuse to save than to write something that can never be read back. (C-19)
        if (StoreAndVerifyKeychain(key, allowUpdate: false)) return key;
        // A competing item is not ours to overwrite. Adopt its verified key on retry.
        var competing = findKeychain();
        if (competing is not null)
        {
            var winner = DecodeKeychainValue(competing);
            if (winner is not { Length: 32 })
                throw new CryptographicException("A competing profile Keychain item is invalid");
            return winner;
        }
        if (!FileStore(key))
            throw new InvalidOperationException(
                "Cannot persist the profile-encryption key: the macOS Keychain rejected it " +
                $"and the fallback key file (\"{FallbackKeyFile}\") could not be written. " +
                "Saving profiles now would produce data that can never be decrypted. " +
                "Check the Keychain permissions for this app, or the permissions on " +
                $"\"{directory}\".");
        return key;
    }

    private byte[] MigrateKey(byte[] key)
    {
        var existingJournal = FileFind(MigrationKeyFile);
        if (existingJournal is { Length: 32 }
            && !CryptographicOperations.FixedTimeEquals(existingJournal, key))
            throw new InvalidOperationException(
                "A different profile-key migration is already pending; refusing to overwrite its recovery copy");

        if (existingJournal is not { Length: 32 }
            && (!FileStore(MigrationKeyFile, key) || !FileMatches(MigrationKeyFile, key)))
            throw new InvalidOperationException(
                "Cannot create the durable profile-key migration journal; the legacy Keychain item was not changed");

        return CompleteMigration(key);
    }

    private byte[] CompleteMigration(byte[] key)
    {
        // First try an in-place ACL/data update. When the current application can access
        // the legacy item this avoids a delete window altogether.
        if (StoreAndVerifyKeychain(key))
        {
            DeleteFileBestEffort(MigrationKeyFile);
            return key;
        }

        // The old ACL may allow only /usr/bin/security, so an in-place update can be
        // denied. The flushed migration journal remains the authoritative recovery copy
        // throughout delete + recreate and survives a crash at either boundary.
        if (deleteLegacy() && StoreAndVerifyKeychain(key))
        {
            DeleteFileBestEffort(MigrationKeyFile);
            return key;
        }

        // Keychain can be locked/unavailable. Preserve the SAME key in the established
        // 0600 fallback instead of rotating it. Verify the destination before removing
        // the journal; otherwise the journal is deliberately retained for the next run.
        if (FileStore(key) && FileMatches(FallbackKeyFile, key))
        {
            DeleteFileBestEffort(MigrationKeyFile);
            return key;
        }

        throw new InvalidOperationException(
            "Cannot complete the profile-key migration; the durable migration journal was retained for recovery");
    }

    private bool StoreAndVerifyKeychain(byte[] key, bool allowUpdate = true)
    {
        if (!storeKeychain(key, allowUpdate)) return false;
        var check = findKeychain();
        return check is { Length: 32 }
            && CryptographicOperations.FixedTimeEquals(check, key);
    }

    // ── Keychain (preferred) ──────────────────────────────────────────────────
    private byte[]? DecodeKeychainValue(byte[]? value)
    {
        if (value is null) return null;
        if (value.Length == 32) return value;
        try { return Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(value).Trim()); }
        catch { return null; }
    }

    // ── 0600 key-file fallback (when the Keychain is unavailable) ──────────────
    private byte[]? FileFind() => FileFind(FallbackKeyFile);

    private byte[]? FileFind(string path)
    {
        try
        {
            using var input = File.OpenRead(path);
            // Bound both allocation and growth; malformed files must not look absent.
            var bytes = BoundedStorage.Read(input, 32);
            if (bytes.Length != 32)
                throw new CryptographicException("The profile key file must contain exactly 32 bytes");
            return bytes;
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    /// <summary>Persist to the 0600 fallback file. Returns false on any failure so the
    /// caller can refuse to hand out a key it could not save. (C-19)</summary>
    private bool FileStore(byte[] key) => FileStore(FallbackKeyFile, key);

    private bool FileStore(string path, byte[] key)
    {
        string? temp = null;
        try
        {
            Directory.CreateDirectory(directory);
            temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
            // Create the temporary file 0600 BEFORE the bytes land in it, flush it, then
            // atomically replace the destination. A crash can leave an unused temp file but
            // can never truncate the last verified recovery copy.
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
            };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var fs = new FileStream(temp, options))
            {
                fs.Write(key);
                fs.Flush(flushToDisk: true);
            }
            File.Move(temp, path, overwrite: true);
            return true;
        }
        catch
        {
            if (temp != null) DeleteFileBestEffort(temp);
            return false;
        }
    }

    private bool FileMatches(string path, byte[] key)
    {
        var check = FileFind(path);
        return check is { Length: 32 }
            && CryptographicOperations.FixedTimeEquals(check, key);
    }

    private void DeleteFileBestEffort(string path)
    {
        try { File.Delete(path); } catch { }
    }
}
