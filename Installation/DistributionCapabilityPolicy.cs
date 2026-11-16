using System;
using System.Collections.Generic;
using System.Linq;
using Libertix.Models;

namespace Libertix.Installation
{
    /// <summary>
    /// Validates signed catalogue-v2 capability semantics, not source authenticity.
    /// Catalogue signatures are verified before DistributionCatalogLoader invokes this.
    /// Never infer execution support from a candidate's declared upstream capabilities.
    /// </summary>
    public static class DistributionCapabilityPolicy
    {
        public static void Validate(string id, string osReleaseId, DistributionCapabilityJson cap)
        {
            if (cap == null || cap.Version != 1 || cap.Bootloader == null ||
                cap.FirmwareLayouts == null || cap.FirmwareLayouts.Count == 0 ||
                cap.FirmwareLayouts.Count > 2 ||
                cap.FirmwareLayouts.Distinct(StringComparer.Ordinal).Count() != cap.FirmwareLayouts.Count ||
                cap.FirmwareLayouts.Any(x => x != "bios/mbr" && x != "uefi/gpt") ||
                cap.MinimumRamMiB < 1024 || cap.MinimumDiskGiB < 20 ||
                (cap.Status != "released" && cap.Status != "lab-only" && cap.Status != "unavailable"))
                throw new InvalidOperationException("Invalid signed distribution capability record.");

            string backend, source, secureBoot, bios, uefi;
            switch (id)
            {
                case "mint":
                    if (osReleaseId != "linuxmint") throw new InvalidOperationException("Invalid distro identity.");
                    backend = "debian-squashfs"; source = "casper-squashfs";
                    secureBoot = "ms-shim"; bios = "grub"; uefi = "grub";
                    break;
                case "zorin":
                    if (osReleaseId != "zorin") throw new InvalidOperationException("Invalid distro identity.");
                    backend = "debian-squashfs"; source = "casper-squashfs";
                    secureBoot = "ms-shim"; bios = "grub"; uefi = "grub";
                    break;
                case "cachyos":
                    if (osReleaseId != "cachyos") throw new InvalidOperationException("Invalid distro identity.");
                    backend = "archiso-cachyos"; source = "archiso";
                    secureBoot = "unsupported"; bios = "grub"; uefi = "grub";
                    break;
                case "popos":
                    if (osReleaseId != "pop") throw new InvalidOperationException("Invalid distro identity.");
                    backend = "system76"; source = "pop-live";
                    secureBoot = "unsupported"; bios = "grub"; uefi = "systemd-boot";
                    break;
                case "q4os":
                    if (osReleaseId != "q4os") throw new InvalidOperationException("Invalid distro identity.");
                    backend = "q4os-native"; source = "q4os-native-iso";
                    secureBoot = "unsupported"; bios = "grub"; uefi = "grub";
                    break;
                case "bazzite":
                    if (osReleaseId != "bazzite") throw new InvalidOperationException("Invalid distro identity.");
                    backend = "fedora-atomic"; source = "fedora-atomic-iso";
                    secureBoot = "manual-enrollment"; bios = "none"; uefi = "grub";
                    break;
                default:
                    throw new InvalidOperationException("Unknown distribution identity.");
            }

            if (cap.Backend != backend || cap.Source != source ||
                cap.SecureBoot != secureBoot ||
                cap.Bootloader.Bios != bios || cap.Bootloader.Uefi != uefi)
                throw new InvalidOperationException("Distribution capability/backend mismatch.");

            bool supportsBios = cap.FirmwareLayouts.Contains("bios/mbr");
            bool supportsUefi = cap.FirmwareLayouts.Contains("uefi/gpt");
            if ((supportsBios && bios == "none") || (supportsUefi && uefi == "none") ||
                (id == "bazzite" && (supportsBios || !supportsUefi)) ||
                ((id == "mint" || id == "zorin") && (!supportsBios || !supportsUefi)) ||
                (id == "bazzite" && cap.MinimumDiskGiB < 50))
                throw new InvalidOperationException("Unsupported firmware/partition capability.");

            if (cap.Status == "released" &&
                !DistributionBackendPolicy.CanUseLegacyDebianBackend(id, osReleaseId))
                throw new InvalidOperationException("Experimental backend cannot be released.");
        }

        public static bool IsReleased(string id, string osReleaseId, DistributionCapabilityJson cap)
        {
            Validate(id, osReleaseId, cap);
            return cap.Status == "released" &&
                DistributionBackendPolicy.CanUseLegacyDebianBackend(id, osReleaseId);
        }
    }
}
