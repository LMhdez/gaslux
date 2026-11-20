using System;

namespace Libertix.Installation
{
    /// <summary>
    /// Explicit release gate for the existing Debian/Ubuntu squashfs installer.
    /// A signed ISO/catalog entry does not by itself authorize a new backend.
    /// New distributions require a versioned, signed capability contract and
    /// dedicated installation, boot, update and recovery verification.
    /// </summary>
    public static class DistributionBackendPolicy
    {
        public static bool CanUseLegacyDebianBackend(string id, string osReleaseId)
        {
            return (string.Equals(id, "mint", StringComparison.Ordinal) &&
                    string.Equals(osReleaseId, "linuxmint", StringComparison.Ordinal)) ||
                   (string.Equals(id, "zorin", StringComparison.Ordinal) &&
                    string.Equals(osReleaseId, "zorin", StringComparison.Ordinal));
        }
    }
}
