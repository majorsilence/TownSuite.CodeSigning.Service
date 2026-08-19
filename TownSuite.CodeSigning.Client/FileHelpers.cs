using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

public static class FileHelpers
{
    static bool IsValidFile(string file, bool isDetached)
    {
        if (string.IsNullOrWhiteSpace(file))
        {
            return false;
        }
        if (!System.IO.File.Exists(file))
        {
            return false;
        }

        if (!isDetached)
        {
            var ext = Path.GetExtension(file);
            if (ext != ".exe" && ext != ".dll" && ext != ".msi" && ext != ".msix"
                && ext != ".cab" && ext != ".sys" && ext != ".ocx" && ext != ".appx")
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Checks whether a file has an embedded Authenticode signature. Used both to skip files
    /// that are already signed before upload, and to verify that a file returned by the signing
    /// service actually has a signature attached before treating the download as successful.
    ///
    /// PE files (exe/dll/sys/ocx) are checked by reading the Certificate Table out of the PE
    /// header, which works on any OS and is authoritative - an unsigned PE has no cert table entry
    /// regardless of platform. The X509Certificate2 fallback only runs for non-PE containers
    /// (msi/cab/msix/appx), where it can extract an Authenticode signer on Windows only (on Linux
    /// those container formats always report unsigned). It must not run for PE files: repackaged
    /// Electron/Chromium exe content has been observed to false-positive as "signed" when the whole
    /// file is handed to X509Certificate2, even though HasPeAuthenticodeSignature correctly reports
    /// no certificate table entry.
    /// </summary>
    public static bool HasEmbeddedDigitalSignature(string file)
    {
        if (HasPeAuthenticodeSignature(file))
        {
            return true;
        }

        if (IsPeFile(file))
        {
            return false;
        }

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using (var cert = new X509Certificate2(file))
                {
                    if (cert != null)
                    {
                        return true;
                    }
                }
            }
            catch (Exception)
            {
                // Ignore any exceptions
            }
        }

        return false;
    }

    /// <summary>
    /// Checks the MZ/PE magic bytes only - used to decide whether the Certificate Table check in
    /// HasPeAuthenticodeSignature is authoritative (true PE files) or whether the X509Certificate2
    /// fallback should be tried instead (non-PE containers such as msi/cab/msix/appx).
    /// </summary>
    internal static bool IsPeFile(string file)
    {
        try
        {
            using var fs = System.IO.File.OpenRead(file);
            using var reader = new BinaryReader(fs);

            if (fs.Length < 0x40 || reader.ReadUInt16() != 0x5A4D) // "MZ"
            {
                return false;
            }

            fs.Position = 0x3C;
            uint peHeaderOffset = reader.ReadUInt32();
            if (peHeaderOffset + 4 > fs.Length)
            {
                return false;
            }

            fs.Position = peHeaderOffset;
            return reader.ReadUInt32() == 0x00004550; // "PE\0\0"
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Cross-platform Authenticode presence check: locates the Certificate Table entry in the
    /// PE optional header's data directories and decodes the WIN_CERTIFICATE blob it points at
    /// as CMS SignedData. Returns false for anything that is not a signed PE file.
    /// </summary>
    internal static bool HasPeAuthenticodeSignature(string file)
    {
        try
        {
            using var fs = System.IO.File.OpenRead(file);
            using var reader = new BinaryReader(fs);

            if (fs.Length < 0x40 || reader.ReadUInt16() != 0x5A4D) // "MZ"
            {
                return false;
            }

            fs.Position = 0x3C;
            uint peHeaderOffset = reader.ReadUInt32();
            if (peHeaderOffset + 24 > fs.Length)
            {
                return false;
            }

            fs.Position = peHeaderOffset;
            if (reader.ReadUInt32() != 0x00004550) // "PE\0\0"
            {
                return false;
            }

            // COFF header is 20 bytes; the optional header follows it.
            long optionalHeaderOffset = peHeaderOffset + 24;
            fs.Position = optionalHeaderOffset;
            ushort magic = reader.ReadUInt16();

            // Data directories start at offset 96 (PE32, magic 0x10B) or 112 (PE32+, magic 0x20B)
            // within the optional header; the Certificate Table is directory index 4.
            long dataDirectoriesOffset;
            if (magic == 0x10B)
            {
                dataDirectoriesOffset = optionalHeaderOffset + 96;
            }
            else if (magic == 0x20B)
            {
                dataDirectoriesOffset = optionalHeaderOffset + 112;
            }
            else
            {
                return false;
            }

            fs.Position = dataDirectoriesOffset - 4;
            uint numberOfRvaAndSizes = reader.ReadUInt32();
            if (numberOfRvaAndSizes < 5)
            {
                return false;
            }

            fs.Position = dataDirectoriesOffset + 4 * 8;
            uint certTableOffset = reader.ReadUInt32(); // a file offset, not an RVA
            uint certTableSize = reader.ReadUInt32();

            // WIN_CERTIFICATE header is 8 bytes: dwLength, wRevision, wCertificateType.
            if (certTableOffset == 0 || certTableSize < 8
                || (long)certTableOffset + certTableSize > fs.Length)
            {
                return false;
            }

            fs.Position = certTableOffset;
            uint certLength = reader.ReadUInt32();
            fs.Position += 2; // wRevision
            ushort certType = reader.ReadUInt16();

            const ushort WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002;
            if (certType != WIN_CERT_TYPE_PKCS_SIGNED_DATA || certLength < 8 || certLength > certTableSize)
            {
                return false;
            }

            byte[] pkcs7 = reader.ReadBytes((int)certLength - 8);
            var signedCms = new SignedCms();
            signedCms.Decode(pkcs7);
            return signedCms.SignerInfos.Count > 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies that a detached signature actually covers the bytes of the original file. The
    /// signing certificate lives in this side-by-side .sig file, never in the original dll/exe/zip.
    ///
    /// The service signs with OpenSSL's "-binary" flag, so the digest is computed over the content
    /// exactly as it sits on disk. That is what makes a byte-exact check possible here: any
    /// difference in content - including a line-ending rewrite somewhere in the pipeline - is
    /// rejected. Without "-binary" openssl digests a CRLF-canonicalized copy instead, which is why
    /// this check used to be structural-only.
    ///
    /// Scope: verifySignatureOnly means this proves integrity, not trust. It confirms the signature
    /// was made over this exact content by the certificate embedded in the .sig; it does not build
    /// a chain to a trusted root, so on its own it does not establish who the signer is.
    /// </summary>
    public static bool HasValidDetachedSignature(string originalFilePath, string signatureFilePath)
    {
        try
        {
            if (!System.IO.File.Exists(signatureFilePath))
            {
                return false;
            }

            byte[] signatureBytes = System.IO.File.ReadAllBytes(signatureFilePath);
            if (signatureBytes.Length == 0)
            {
                return false;
            }

            byte[] originalBytes = System.IO.File.ReadAllBytes(originalFilePath);
            var contentInfo = new ContentInfo(originalBytes);
            var signedCms = new SignedCms(contentInfo, detached: true);
            signedCms.Decode(signatureBytes);

            if (signedCms.SignerInfos.Count == 0 || signedCms.Certificates.Count == 0)
            {
                return false;
            }

            // Throws if the digest does not match originalBytes.
            signedCms.CheckSignature(verifySignatureOnly: true);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static List<string> CreateFileList(string[] filepaths, string folder, bool isDetached)
    {
        var files = new List<string>();
        if (!string.IsNullOrWhiteSpace(folder))
        {
            foreach (var file in filepaths)
            {
                if (file.Contains("*"))
                {
                    // wild cards
                    string pattern = Path.GetFileName(file);
                    string[] matchingFiles = Directory.GetFiles(folder, pattern);
                    files.AddRange(matchingFiles);
                }
                else
                {
                    string fullFilePath = Path.Combine(folder, file);
                    if (System.IO.File.Exists(fullFilePath))
                    {
                        files.Add(fullFilePath);
                    }
                }
            }
        }
        else
        {
            foreach (var file in filepaths)
            {
                if (file.Contains("*"))
                {
                    // wildcards
                    string directory = Path.GetDirectoryName(file);
                    string pattern = Path.GetFileName(file);
                    string[] matchingFiles = Directory.GetFiles(directory, pattern);
                    files.AddRange(matchingFiles);
                }
                else
                {
                    if (System.IO.File.Exists(file))
                    {
                        files.Add(file);
                    }
                }
            }
        }

        var finalFiles = new List<string>();
        foreach (var file in files)
        {
            if (IsValidFile(file, isDetached) && !HasEmbeddedDigitalSignature(file))
            {
                finalFiles.Add(file);
            }
        }

        return finalFiles;
    }

    /// <summary>
    /// Builds a combined file list from multiple folder paths, each using the same file patterns.
    /// </summary>
    public static List<string> CreateFileListFromMultipleFolders(string[] filepaths, string[] folders, bool isDetached)
    {
        var pairs = new List<(string Folder, string[] Files)>();
        foreach (string folder in folders)
        {
            string trimmed = folder.Trim();
            if (!string.IsNullOrWhiteSpace(trimmed))
            {
                pairs.Add((trimmed, filepaths));
            }
        }

        return CreateFileListFromFolderFilePairs(pairs, isDetached);
    }

    /// <summary>
    /// Builds a combined file list from folder/file pairs where each folder has its own file patterns.
    /// </summary>
    public static List<string> CreateFileListFromFolderFilePairs(List<(string Folder, string[] Files)> folderFilePairs, bool isDetached)
    {
        ArgumentNullException.ThrowIfNull(folderFilePairs);

        var allFiles = new List<string>();
        foreach (var (folder, files) in folderFilePairs)
        {
            string trimmed = folder.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                continue;
            }

            allFiles.AddRange(CreateFileList(files, trimmed, isDetached));
        }

        return allFiles;
    }

    /// <summary>
    /// Recursively scans parent folders for files matching the given patterns.
    /// Each entry is a parent folder paired with its own file patterns.
    /// Added optional exclusion of folder names.
    /// </summary>
    public static List<string> CreateFileListRecursive(List<(string Folder, string[] Files)> folderFilePairs, bool isDetached, string[]? excludeFolderNames = null)
    {
        ArgumentNullException.ThrowIfNull(folderFilePairs);
        var excludeSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (excludeFolderNames != null)
        {
            foreach (var ex in excludeFolderNames)
            {
                var t = ex?.Trim();
                if (!string.IsNullOrWhiteSpace(t))
                {
                    excludeSet.Add(t);
                }
            }
        }

        var allFiles = new List<string>();

        foreach (var (parentFolder, filePatterns) in folderFilePairs)
        {
            string root = parentFolder.Trim();
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                continue;
            }

            // BFS/stack walk so we can skip directories that match excludeSet
            var dirsToVisit = new Stack<string>();
            dirsToVisit.Push(root);

            while (dirsToVisit.Count > 0)
            {
                string currentDir = dirsToVisit.Pop();

                // Skip directory if any folder name segment matches excludes
                string folderName = Path.GetFileName(currentDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                if (!string.IsNullOrEmpty(folderName) && excludeSet.Contains(folderName))
                {
                    continue;
                }

                foreach (string pattern in filePatterns)
                {
                    string trimmedPattern = pattern.Trim();
                    if (string.IsNullOrWhiteSpace(trimmedPattern))
                    {
                        continue;
                    }

                    try
                    {
                        // Use GetFiles on the current directory only
                        string[] matchingFiles = Directory.GetFiles(currentDir, trimmedPattern);
                        if (matchingFiles.Length > 0)
                        {
                            allFiles.AddRange(matchingFiles);
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // ignore inaccessible directories
                    }
                    catch (DirectoryNotFoundException)
                    {
                        // directory removed during scan
                    }
                }

                // enqueue subdirectories
                try
                {
                    foreach (var sub in Directory.GetDirectories(currentDir))
                    {
                        // If the subfolder's name is explicitly excluded, skip pushing it
                        string subName = Path.GetFileName(sub.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                        if (!string.IsNullOrEmpty(subName) && excludeSet.Contains(subName))
                        {
                            continue;
                        }
                        dirsToVisit.Push(sub);
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    // ignore
                }
                catch (DirectoryNotFoundException)
                {
                    // ignore
                }
            }
        }

        var finalFiles = new List<string>();
        foreach (var file in allFiles)
        {
            if (IsValidFile(file, isDetached) && !HasEmbeddedDigitalSignature(file))
            {
                finalFiles.Add(file);
            }
        }

        return finalFiles;
    }

    /// <summary>
    /// Computes a SHA-256 hash of a file's contents, returned as a lowercase hex string.
    /// </summary>
    public static string ComputeFileHash(string filePath)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        using var stream = File.OpenRead(filePath);
        byte[] hashBytes = SHA256.HashData(stream);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    /// <summary>
    /// Groups files by content hash. Returns a dictionary mapping each canonical file
    /// (the first encountered with a given hash) to all other files with the same content.
    /// </summary>
    public static (List<string> UniqueFiles, Dictionary<string, List<string>> DuplicateMap) DeduplicateFiles(
        List<string> files)
    {
        ArgumentNullException.ThrowIfNull(files);

        // Normalize input paths to full paths and avoid hashing the same physical
        // file more than once (same full path). Use a case-insensitive comparer on
        // Windows and ordinal on other platforms.
        var pathComparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var seenPaths = new HashSet<string>(pathComparer);

        // hash -> list of file paths with that hash
        var hashGroups = new Dictionary<string, List<string>>(StringComparer.Ordinal);

        foreach (string file in files)
        {
            if (string.IsNullOrWhiteSpace(file))
            {
                continue;
            }

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(file);
            }
            catch
            {
                // Skip invalid paths
                continue;
            }

            // If we've already seen this exact physical path, skip it to avoid
            // creating duplicate entries that point to the same file.
            if (!seenPaths.Add(fullPath))
            {
                continue;
            }

            if (!File.Exists(fullPath))
            {
                continue;
            }

            string hash = ComputeFileHash(fullPath);
            if (!hashGroups.TryGetValue(hash, out var group))
            {
                group = new List<string>();
                hashGroups[hash] = group;
            }

            group.Add(fullPath);
        }

        var uniqueFiles = new List<string>();
        // canonical file path -> list of duplicate file paths (excluding the canonical)
        var duplicateMap = new Dictionary<string, List<string>>(StringComparer.Ordinal);

        foreach (var group in hashGroups.Values)
        {
            string canonical = group[0];
            uniqueFiles.Add(canonical);

            if (group.Count > 1)
            {
                duplicateMap[canonical] = group.GetRange(1, group.Count - 1);
            }
        }

        return (uniqueFiles, duplicateMap);
    }

    /// <summary>
    /// After signing, copies each signed canonical file to all its duplicate locations.
    /// </summary>
    public static void CopySignedFilesToDuplicates(Dictionary<string, List<string>> duplicateMap)
    {
        ArgumentNullException.ThrowIfNull(duplicateMap);

        foreach (var (canonical, duplicates) in duplicateMap)
        {
            if (string.IsNullOrWhiteSpace(canonical) || duplicates == null)
            {
                continue;
            }

            string canonicalFull;
            try
            {
                canonicalFull = Path.GetFullPath(canonical);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Skipping canonical path '{canonical}' - invalid path: {ex.Message}");
                continue;
            }

            if (!File.Exists(canonicalFull))
            {
                Console.WriteLine($"Signed canonical file not found, skipping copies: {canonicalFull}");
                continue;
            }

            foreach (string duplicate in duplicates)
            {
                if (string.IsNullOrWhiteSpace(duplicate))
                {
                    continue;
                }

                string duplicateFull;
                try
                {
                    duplicateFull = Path.GetFullPath(duplicate);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Skipping duplicate path '{duplicate}' - invalid path: {ex.Message}");
                    continue;
                }

                // Skip copying if paths refer to the same file (case-insensitive on Windows)
                if (string.Equals(canonicalFull, duplicateFull, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"Skipping copy: canonical and duplicate are the same path: {canonicalFull}");
                    continue;
                }

                try
                {
                    File.Copy(canonicalFull, duplicateFull, overwrite: true);
                    Console.WriteLine($"Copied signed file {canonicalFull} to duplicate location: {duplicateFull}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to copy signed file from '{canonicalFull}' to '{duplicateFull}': {ex.Message}");
                }
            }
        }
    }
}