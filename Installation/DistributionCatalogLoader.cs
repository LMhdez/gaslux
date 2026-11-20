using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Libertix.Helpers;
using Libertix.Models;

namespace Libertix.Installation
{
    public static class DistributionCatalogLoader
    {
        private const long MaximumCatalogBytes = 1024 * 1024;
        private const long MaximumCatalogSignatureBytes = 16 * 1024;
        private static readonly HttpClient SharedHttpClient = new HttpClient
        {
            Timeout = Timeout.InfiniteTimeSpan
        };

        public static async Task<IReadOnlyList<DistroInfo>> LoadAsync(
            FilepoolConfig filepool)
        {
            if (filepool == null)
                throw new ArgumentNullException(nameof(filepool));

            byte[] manifest = filepool.LocalDirectory == null
                ? await DownloadCatalogAsync(filepool)
                : ReadLocalCatalog(filepool);
            DistributionCatalogJson catalog = ParseCatalog(manifest);
            return CreateDistributions(catalog, filepool);
        }

        public static async Task VerifyLocalFilepoolAsync(
            FilepoolConfig filepool,
            Action<string> onProgress)
        {
            if (filepool == null || filepool.LocalDirectory == null)
                throw new ArgumentException("A local filepool must be selected.", nameof(filepool));

            byte[] localManifest = ReadLocalCatalog(filepool);
            DistributionCatalogJson catalog = ParseCatalog(localManifest);
            if (!filepool.SkipWebCatalogComparison)
            {
                byte[] onlineManifest = await DownloadCatalogAsync(filepool);
                if (!localManifest.SequenceEqual(onlineManifest))
                    throw new InvalidDataException(
                        "The local catalog.json differs from the signed online catalog.json.");
            }

            foreach (DistroInfoJson distribution in catalog.Distributions)
                ValidateDistribution(distribution, catalog.SchemaVersion);
            var artifacts = CatalogFiles.GetAll(catalog);
            // Missing distribution ISOs are downloaded only if selected.
            var optionalFileNames = new HashSet<string>(
                catalog.Distributions.Select(distribution => distribution.IsoInstallerFileName),
                StringComparer.OrdinalIgnoreCase);
            // The lab builds and deploys the executable independently of the filepool.
            if (filepool.IsDevelopmentMode)
                optionalFileNames.Add(catalog.Artifacts.Wpf.FileName);

            await Task.Run(() =>
            {
                foreach (CatalogArtifactJson artifact in artifacts)
                {
                    if (!Regex.IsMatch(
                        artifact.FileName ?? string.Empty,
                        "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"))
                        throw new InvalidDataException("A local artifact filename is invalid.");

                    string path = Path.Combine(filepool.LocalDirectory, artifact.FileName);
                    var file = new FileInfo(path);
                    if (!file.Exists && optionalFileNames.Contains(artifact.FileName))
                    {
                        onProgress?.Invoke(
                            "CHECK=LOCAL_FILEPOOL: " + artifact.FileName +
                            (filepool.IsDevelopmentMode && artifact == catalog.Artifacts.Wpf
                                ? " absent; executable built separately"
                                : " absent; download if selected"));
                        continue;
                    }
                    if (!file.Exists || file.Length != artifact.SizeBytes ||
                        (file.Attributes & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidDataException(
                            "A local filepool artifact is missing or has the wrong size: " +
                            artifact.FileName);

                    onProgress?.Invoke("CHECK=LOCAL_FILEPOOL: " + artifact.FileName);
                    using (var stream = file.OpenRead())
                    using (var sha256 = SHA256.Create())
                    {
                        string actual = BitConverter.ToString(sha256.ComputeHash(stream))
                            .Replace("-", string.Empty);
                        if (!string.Equals(
                            actual, artifact.Sha256, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException(
                                "A local filepool artifact has the wrong SHA-256: " +
                                artifact.FileName);
                    }
                }
            });
        }

        private static byte[] ReadLocalCatalog(FilepoolConfig filepool)
        {
            string manifestPath = Path.Combine(filepool.LocalDirectory, "catalog.json");
            string signaturePath = manifestPath + ".sig";
            var manifest = new FileInfo(manifestPath);
            var signature = new FileInfo(signaturePath);
            if (!manifest.Exists || manifest.Length > MaximumCatalogBytes ||
                (manifest.Attributes & FileAttributes.ReparsePoint) != 0 ||
                (filepool.RequiresCatalogSignature &&
                    (!signature.Exists || signature.Length > MaximumCatalogSignatureBytes ||
                    (signature.Attributes & FileAttributes.ReparsePoint) != 0)))
                throw new InvalidDataException(
                    "The local catalog.json or catalog.json.sig is missing or too large.");
            byte[] bytes = File.ReadAllBytes(manifestPath);
            if (filepool.RequiresCatalogSignature)
                DistributionCatalogTrust.VerifyWithApplicationKey(
                    bytes,
                    File.ReadAllText(signaturePath, Encoding.UTF8));
            return bytes;
        }

        private static async Task<byte[]> DownloadCatalogAsync(FilepoolConfig filepool)
        {
            using (var timeoutCancellation =
                new CancellationTokenSource(TimeSpan.FromSeconds(30)))
            using (var response = await SharedHttpClient.GetAsync(
                filepool.CatalogUrl,
                HttpCompletionOption.ResponseHeadersRead,
                timeoutCancellation.Token))
            {
                response.EnsureSuccessStatusCode();
                byte[] manifest = await BoundedHttpContent.ReadAsync(
                    response.Content,
                    MaximumCatalogBytes,
                    timeoutCancellation.Token);
                if (filepool.RequiresCatalogSignature)
                {
                    using (var signatureResponse = await SharedHttpClient.GetAsync(
                        filepool.CatalogSignatureUrl,
                        HttpCompletionOption.ResponseHeadersRead,
                        timeoutCancellation.Token))
                    {
                        signatureResponse.EnsureSuccessStatusCode();
                        byte[] signatureBytes = await BoundedHttpContent.ReadAsync(
                            signatureResponse.Content,
                            MaximumCatalogSignatureBytes,
                            timeoutCancellation.Token);
                        DistributionCatalogTrust.VerifyWithApplicationKey(
                            manifest,
                            Encoding.UTF8.GetString(signatureBytes));
                    }
                }

                return manifest;
            }
        }

        private static DistributionCatalogJson ParseCatalog(byte[] manifest)
        {
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            var catalog = JsonSerializer.Deserialize<DistributionCatalogJson>(
                Encoding.UTF8.GetString(manifest),
                options);
            ValidateCatalog(catalog);
            if (catalog.SchemaVersion == 2)
                ValidateV2CatalogueJsonShape(manifest);
            return catalog;
        }

        private static void ValidateV2CatalogueJsonShape(byte[] manifest)
        {
            // System.Text.Json deserialization ignores extra fields and accepts
            // duplicate property names. Version 2 must match its signed JSON
            // Schema exactly, including every capability/bootloader field.
            using (var document = JsonDocument.Parse(manifest))
            {
                JsonElement root = document.RootElement;
                AssertExactFields(root, "catalog",
                    "schemaVersion", "artifacts", "distributions");
                foreach (JsonElement distro in root.GetProperty("distributions").EnumerateArray())
                {
                    AssertExactFields(distro, "distribution",
                        "id", "name", "osReleaseId", "grubDisplayName", "grubIcon",
                        "secureBootMicrosoftAuthorities", "description", "imageUrl",
                        "isoInstaller", "isoInstallerFileName", "isoInstallerSha256",
                        "isoInstallerSizeBytes", "sizeInGB", "capabilities");
                    JsonElement cap = distro.GetProperty("capabilities");
                    AssertExactFields(cap, "capabilities",
                        "version", "backend", "source", "firmwareLayouts", "secureBoot",
                        "bootloader", "status", "minimumRamMiB", "minimumDiskGiB");
                    AssertExactFields(cap.GetProperty("bootloader"), "bootloader",
                        "bios", "uefi");
                }
            }
        }

        private static void AssertExactFields(
            JsonElement json, string path, params string[] required)
        {
            if (json.ValueKind != JsonValueKind.Object)
                throw new InvalidOperationException(
                    "Signed catalog field " + path + " must be an object.");

            var seen = new HashSet<string>(StringComparer.Ordinal);
            var expected = new HashSet<string>(required, StringComparer.Ordinal);
            foreach (JsonProperty property in json.EnumerateObject())
            {
                if (!expected.Contains(property.Name) || !seen.Add(property.Name))
                    throw new InvalidOperationException(
                        "Signed catalog field " + path + " has an unknown or duplicate key.");
            }
            if (!seen.SetEquals(expected))
                throw new InvalidOperationException(
                    "Signed catalog field " + path + " has missing keys.");
        }

        private static void ValidateCatalog(DistributionCatalogJson catalog)
        {
            if (catalog == null ||
                (catalog.SchemaVersion != 1 && catalog.SchemaVersion != 2) ||
                catalog.Artifacts?.MiniIso == null ||
                catalog.Artifacts.Support == null ||
                catalog.Distributions == null ||
                catalog.Distributions.Count == 0)
            {
                throw new InvalidOperationException(
                    "Distribution catalog JSON is empty or invalid.");
            }

            ValidateWpfArtifact(catalog.Artifacts.Wpf);
            ValidateArtifact(
                catalog.Artifacts.MiniIso.Bios,
                "libertix-installer-bios.iso");
            ValidateArtifact(
                catalog.Artifacts.MiniIso.Uefi,
                "libertix-installer-uefi.iso");
            ValidateArtifact(catalog.Artifacts.Support.Aria2Archive, "aria2-64.zip");
            ValidateArtifact(
                catalog.Artifacts.Support.Ext4Driver,
                "ext4-win-driver.exe");
            ValidateArtifact(catalog.Artifacts.Support.Grub4DosLoader, "grldr");
            ValidateArtifact(catalog.Artifacts.Support.Grub4DosMbr, "grldr.mbr");
        }

        private static IReadOnlyList<DistroInfo> CreateDistributions(
            DistributionCatalogJson catalog,
            FilepoolConfig filepool)
        {
            CatalogArtifactJson biosMiniIso = catalog.Artifacts.MiniIso.Bios;
            CatalogArtifactJson uefiMiniIso = catalog.Artifacts.MiniIso.Uefi;
            var distributions = new List<DistroInfo>(catalog.Distributions.Count);
            var seenIds = new HashSet<string>(StringComparer.Ordinal);

            foreach (DistroInfoJson source in catalog.Distributions)
            {
                ValidateDistribution(source, catalog.SchemaVersion);
                if (!seenIds.Add(source.Id))
                {
                    throw new InvalidOperationException(
                        "Distribution manifest contains a duplicate id.");
                }

                // Signed experimental records can be analysed but never shown in
                // the production selection wizard or passed to the legacy backend.
                if (catalog.SchemaVersion == 2 &&
                    !DistributionCapabilityPolicy.IsReleased(
                        source.Id, source.OsReleaseId, source.Capabilities))
                    continue;

                distributions.Add(new DistroInfo
                {
                    Id = source.Id,
                    Name = source.Name,
                    OsReleaseId = source.OsReleaseId,
                    GrubDisplayName = source.GrubDisplayName,
                    GrubIcon = source.GrubIcon,
                    SecureBootMicrosoftAuthorities =
                        source.SecureBootMicrosoftAuthorities.ToList(),
                    Description = source.Description ?? "No description available",
                    // Catalog illustrations have no signed artifact hash. Do not fetch
                    // them from external sites when the local server is selected.
                    ImageUrl = filepool.LocalServer == null ? source.ImageUrl : null,
                    IsoUrl = filepool.ResolveArtifactUrl(biosMiniIso.Url, biosMiniIso.FileName, biosMiniIso.Sha256),
                    IsoInstaller = filepool.ResolveArtifactUrl(source.IsoInstaller,
                        source.IsoInstallerFileName, source.IsoInstallerSha256),
                    IsoInstallerFileName = source.IsoInstallerFileName,
                    IsoSha256 = biosMiniIso.Sha256,
                    UefiIsoUrl = filepool.ResolveArtifactUrl(uefiMiniIso.Url, uefiMiniIso.FileName, uefiMiniIso.Sha256),
                    UefiIsoSha256 = uefiMiniIso.Sha256,
                    IsoInstallerSha256 = source.IsoInstallerSha256,
                    IsoInstallerSizeBytes = source.IsoInstallerSizeBytes,
                    SizeInGB = source.SizeInGB
                });
            }

            if (distributions.Count == 0)
                throw new InvalidOperationException(
                    "No released installation backend is available in this signed catalog.");
            return distributions;
        }

        private static void ValidateDistribution(DistroInfoJson distribution, int catalogVersion)
        {
            if (distribution == null ||
                (catalogVersion == 1 &&
                    (distribution.Capabilities != null ||
                     !DistributionBackendPolicy.CanUseLegacyDebianBackend(
                         distribution.Id, distribution.OsReleaseId))))
            {
                throw new InvalidOperationException(
                    "This distribution has no authorized installation backend.");
            }
            if (catalogVersion == 2)
                DistributionCapabilityPolicy.Validate(
                    distribution.Id, distribution.OsReleaseId, distribution.Capabilities);

            if (!Regex.IsMatch(
                    distribution.Id ?? string.Empty,
                    "^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$") ||
                string.IsNullOrWhiteSpace(distribution.Name) ||
                !Regex.IsMatch(
                    distribution.OsReleaseId ?? string.Empty,
                    "^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$") ||
                !Regex.IsMatch(
                    distribution.GrubDisplayName ?? string.Empty,
                    "^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,79}$") ||
                !Regex.IsMatch(
                    distribution.GrubIcon ?? string.Empty,
                    "^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$") ||
                distribution.SecureBootMicrosoftAuthorities == null ||
                distribution.SecureBootMicrosoftAuthorities.Count == 0 ||
                distribution.SecureBootMicrosoftAuthorities.Any(
                    authority => authority != "2011" && authority != "2023") ||
                distribution.SecureBootMicrosoftAuthorities
                    .Distinct(StringComparer.Ordinal).Count() !=
                    distribution.SecureBootMicrosoftAuthorities.Count ||
                string.IsNullOrWhiteSpace(distribution.IsoInstaller) ||
                string.IsNullOrWhiteSpace(distribution.IsoInstallerFileName) ||
                !Regex.IsMatch(
                    distribution.IsoInstallerSha256 ?? string.Empty,
                    "^[0-9a-fA-F]{64}$") ||
                distribution.IsoInstallerSizeBytes <= 0 ||
                distribution.SizeInGB < InstallationSizePolicy.MinimumFinalSizeGiB)
            {
                throw new InvalidOperationException(
                    "Distribution manifest contains an invalid entry.");
            }
        }

        private static void ValidateArtifact(
            CatalogArtifactJson artifact,
            string expectedFileName)
        {
            if (artifact == null ||
                !string.Equals(
                    artifact.FileName,
                    expectedFileName,
                    StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(artifact.Url) ||
                !Regex.IsMatch(artifact.Sha256 ?? string.Empty, "^[0-9a-fA-F]{64}$") ||
                artifact.SizeBytes <= 0)
            {
                throw new InvalidOperationException(
                    "Distribution catalog contains invalid artifact metadata.");
            }
        }

        private static void ValidateWpfArtifact(CatalogArtifactJson artifact)
        {
            if (artifact == null ||
                !Regex.IsMatch(
                    artifact.FileName ?? string.Empty,
                    "^Libertix-(?:wpf|[0-9a-f]{7}|(?:0|[1-9][0-9]*)(?:\\.(?:0|[1-9][0-9]*)){1,2}(?:-[0-9A-Za-z.-]+)?)\\.zip$") ||
                string.IsNullOrWhiteSpace(artifact.Url) ||
                !artifact.Url.EndsWith("/" + artifact.FileName, StringComparison.Ordinal) ||
                !Regex.IsMatch(artifact.Sha256 ?? string.Empty, "^[0-9a-fA-F]{64}$") ||
                artifact.SizeBytes <= 0)
            {
                throw new InvalidOperationException(
                    "Distribution catalog contains invalid WPF artifact metadata.");
            }
        }
    }
}
