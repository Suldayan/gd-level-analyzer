package com.example.gd_level_analyzer_backend.processing.internal;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration properties for Geometry Dash file locations and processing limits.
 * Internal configuration class for the leveldata module.
 */
@Data
@Validated
@ConfigurationProperties(prefix = "geometry-dash.file")
public class GeometryDashProperties {

    /**
     * Path to GD levels file on Windows systems.
     */
    @NotBlank(message = "Windows path cannot be blank")
    private String windowsPath = getDefaultWindowsPath();

    /**
     * Path to GD levels file on macOS systems.
     */
    @NotBlank(message = "macOS path cannot be blank")
    private String macPath = getDefaultMacPath();

    /**
     * Path to GD levels file on Linux systems.
     */
    @NotBlank(message = "Linux path cannot be blank")
    private String linuxPath = getDefaultLinuxPath();

    /**
     * Maximum allowed file size in bytes for processing.
     */
    @Min(value = 1024, message = "Maximum file size must be at least 1KB")
    private long maxFileSizeBytes = 100L * 1024 * 1024; // 100MB default

    /**
     * Maximum allowed decompressed data size in bytes.
     */
    @Min(value = 1024, message = "Maximum decompressed size must be at least 1KB")
    private long maxDecompressedSizeBytes = 500L * 1024 * 1024; // 500MB default

    /**
     * Timeout for file operations in milliseconds.
     */
    @Min(value = 1000, message = "Timeout must be at least 1 second")
    private long fileOperationTimeoutMs = 30_000; // 30 seconds

    private static String getDefaultWindowsPath() {
        return System.getProperty("user.home") + "\\AppData\\Local\\GeometryDash\\CCLocalLevels.dat";
    }

    private static String getDefaultMacPath() {
        return System.getProperty("user.home") + "/Library/Application Support/GeometryDash/CCLocalLevels.dat";
    }

    private static String getDefaultLinuxPath() {
        return System.getProperty("user.home") + "/.local/share/GeometryDash/CCLocalLevels.dat";
    }

    /**
     * Get the appropriate file path for the current operating system.
     */
    public String getPathForCurrentOS() {
        String osName = System.getProperty("os.name").toLowerCase();

        if (osName.contains("win")) {
            return windowsPath;
        } else if (osName.contains("mac")) {
            return macPath;
        } else {
            return linuxPath; // Default to Linux for other Unix-like systems
        }
    }
}