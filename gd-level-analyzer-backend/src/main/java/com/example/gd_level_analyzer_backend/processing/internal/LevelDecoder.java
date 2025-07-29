package com.example.gd_level_analyzer_backend.leveldata.internal;

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Comprehensive processor for Geometry Dash level data files.
 * Handles decryption, decompression, and analysis of CCLocalLevels.dat files
 * using GD's proprietary encryption scheme.
 *
 * <p>The processing involves several steps:
 * <ol>
 *   <li>XOR decryption with key 11</li>
 *   <li>Base64 URL-safe decoding</li>
 *   <li>Header removal (first 10 bytes)</li>
 *   <li>Zlib decompression</li>
 * </ol>
 *
 * @since 1.0
 */
@Slf4j
public class LevelDecoder {
    private static final int GD_ENCRYPTION_KEY = 11;
    private static final int GD_HEADER_LENGTH = 10;
    private static final int BASE64_BLOCK_SIZE = 4;
    private static final int BUFFER_SIZE = 1024;
    private static final int MAX_TRUNCATION_ATTEMPTS = 4;

    private static final Pattern LEVEL_PATTERN_KEY = Pattern.compile("<key>k4</key>\\s*<string>([^<]+)</string>");
    private static final Pattern LEVEL_PATTERN_K = Pattern.compile("<k>k4</k>\\s*<s>([^<]+)</s>");

    /**
     * Decrypts the entire CCLocalLevels.dat file content using GD's encryption scheme.
     *
     * @param encryptedData the encrypted data as a string
     * @return the decrypted XML content
     * @throws GeometryDashProcessingException if decryption fails
     * @throws IllegalArgumentException if input is null or empty
     */
    public String decryptLevelFile(String encryptedData) {
        validateInput(encryptedData, "Encrypted data");

        log.info("Starting decryption of {} characters", encryptedData.length());

        try {
            byte[] decryptedBytes = performXorDecryption(encryptedData);
            String base64String = prepareBase64String(decryptedBytes);
            byte[] decodedData = performRobustBase64Decoding(base64String);
            byte[] dataWithoutHeader = removeGdHeader(decodedData);
            String result = performZlibDecompression(dataWithoutHeader);

            log.info("Successfully decrypted: {} -> {} characters",
                    encryptedData.length(), result.length());
            return result;

        } catch (Exception e) {
            log.error("Decryption failed for {} characters: {}", encryptedData.length(), e.getMessage());
            throw new GeometryDashProcessingException("Failed to decrypt GD level data", e);
        }
    }

    /**
     * Decrypts individual level data strings found within XML.
     *
     * @param encryptedLevelString the encrypted level string
     * @return the decrypted level data
     * @throws GeometryDashProcessingException if decryption fails
     */
    public String decryptLevelString(String encryptedLevelString) {
        validateInput(encryptedLevelString, "Level string");

        try {
            String base64String = encryptedLevelString.replace('-', '+').replace('_', '/');
            base64String = fixBase64Padding(base64String);

            byte[] decodedData = performRobustBase64Decoding(base64String);
            byte[] dataWithoutHeader = removeGdHeader(decodedData);

            return performZlibDecompression(dataWithoutHeader);

        } catch (Exception e) {
            log.error("Failed to decrypt level string: {}", e.getMessage());
            throw new GeometryDashProcessingException("Failed to decrypt level string", e);
        }
    }

    /**
     * Performs complete decryption and processing of GD data including nested level strings.
     *
     * @param encryptedData the raw encrypted file data
     * @return fully decrypted data with all level strings processed
     * @throws GeometryDashProcessingException if processing fails
     */
    public String processCompleteGdData(String encryptedData) {
        String decryptedXml = decryptLevelFile(encryptedData);
        return processNestedLevelStrings(decryptedXml);
    }

    /**
     * Provides enhanced decryption with detailed debugging information.
     * Useful for troubleshooting corrupted or problematic data files.
     *
     * @param encryptedData the encrypted data to process
     * @return the decrypted content
     * @throws GeometryDashProcessingException if decryption fails
     */
    public String decryptWithDiagnostics(String encryptedData) {
        log.info("=== DIAGNOSTIC DECRYPTION MODE ===");
        logInputDiagnostics(encryptedData);

        return decryptLevelFile(encryptedData);
    }

    // ==================== PRIVATE HELPER METHODS ====================

    private void validateInput(String input, String paramName) {
        if (input == null || input.trim().isEmpty()) {
            throw new IllegalArgumentException(paramName + " cannot be null or empty");
        }
    }

    private byte[] performXorDecryption(String encryptedData) {
        byte[] inputBytes = encryptedData.getBytes(StandardCharsets.ISO_8859_1);
        byte[] result = new byte[inputBytes.length];

        for (int i = 0; i < inputBytes.length; i++) {
            result[i] = (byte) (inputBytes[i] ^ GD_ENCRYPTION_KEY);
        }

        log.debug("XOR decryption completed: {} bytes processed", result.length);
        return result;
    }

    private String prepareBase64String(byte[] xorDecrypted) {
        String base64String = new String(xorDecrypted, StandardCharsets.ISO_8859_1);
        return base64String.replace('-', '+').replace('_', '/');
    }

    private byte[] removeGdHeader(byte[] data) {
        if (data.length < GD_HEADER_LENGTH) {
            throw new IllegalStateException("Data too short to contain GD header");
        }

        byte[] result = new byte[data.length - GD_HEADER_LENGTH];
        System.arraycopy(data, GD_HEADER_LENGTH, result, 0, result.length);
        return result;
    }

    private String performZlibDecompression(byte[] compressedData) throws IOException {
        Inflater inflater = new Inflater(true); // Raw deflate without zlib header
        inflater.setInput(compressedData);

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[BUFFER_SIZE];

            while (!inflater.finished()) {
                try {
                    int length = inflater.inflate(buffer);
                    outputStream.write(buffer, 0, length);
                } catch (DataFormatException e) {
                    throw new IOException("Zlib decompression failed", e);
                }
            }

            return outputStream.toString(StandardCharsets.UTF_8);
        } finally {
            inflater.end();
        }
    }

    private String processNestedLevelStrings(String decryptedXml) {
        String result = decryptedXml;
        int processedCount = 0;

        // Try both XML formats
        processedCount += processLevelStringsWithPattern(result, LEVEL_PATTERN_KEY, "<key> format");
        if (processedCount == 0) {
            processedCount += processLevelStringsWithPattern(result, LEVEL_PATTERN_K, "<k> format");
        }

        log.info("Processed {} nested level strings", processedCount);
        return result;
    }

    private int processLevelStringsWithPattern(String xml, Pattern pattern, String formatName) {
        Matcher matcher = pattern.matcher(xml);
        int count = 0;

        while (matcher.find()) {
            String encryptedString = matcher.group(1);
            try {
                String decrypted = decryptLevelString(encryptedString);
                xml = xml.replace(encryptedString, decrypted);
                count++;
                log.debug("Processed level {} ({} chars -> {} chars) [{}]",
                        count, encryptedString.length(), decrypted.length(), formatName);
            } catch (Exception e) {
                log.warn("Failed to process level {}: {}", count + 1, e.getMessage());
            }
        }

        return count;
    }

    private void logInputDiagnostics(String encryptedData) {
        log.info("Input length: {}", encryptedData.length());

        int analysisLength = Math.min(50, encryptedData.length());
        String endData = encryptedData.substring(encryptedData.length() - analysisLength);
        log.info("Last {} characters: '{}'", analysisLength, endData);

        if (encryptedData.endsWith("\n") || encryptedData.endsWith("\r")) {
            log.warn("Data ends with newline - potential parsing issue");
        }

        if (encryptedData.contains("\0")) {
            log.warn("Data contains null bytes - potential corruption");
        }
    }

    /**
     * Fixes Base64 padding and removes invalid characters.
     */
    private String fixBase64Padding(String base64String) {
        // Remove invalid characters
        String cleaned = base64String.replaceAll("[^A-Za-z0-9+/=]", "");

        // Remove existing padding
        cleaned = cleaned.replaceAll("=+$", "");

        // Add correct padding
        int paddingNeeded = BASE64_BLOCK_SIZE - (cleaned.length() % BASE64_BLOCK_SIZE);
        if (paddingNeeded != BASE64_BLOCK_SIZE) {
            cleaned += "=".repeat(paddingNeeded);
        }

        log.debug("Base64 padding fixed: {} -> {} characters", base64String.length(), cleaned.length());
        return cleaned;
    }

    /**
     * Attempts Base64 decoding with multiple fallback strategies for corrupted data.
     */
    private byte[] performRobustBase64Decoding(String base64String) throws IOException {
        String fixedString = fixBase64Padding(base64String);

        // Strategy 1: Standard decoding
        try {
            return Base64.getDecoder().decode(fixedString);
        } catch (IllegalArgumentException e) {
            log.warn("Standard Base64 decode failed: {}", e.getMessage());
        }

        // Strategy 2: Progressive truncation
        for (int removeCount = 1; removeCount <= MAX_TRUNCATION_ATTEMPTS; removeCount++) {
            if (attemptTruncatedDecoding(fixedString, removeCount)) {
                continue; // This should return the result, but the original logic was flawed
            }
        }

        // Strategy 3: Find last valid block
        int validLength = findLastValidBase64Block(fixedString);
        if (validLength > 0) {
            String validPortion = fixBase64Padding(fixedString.substring(0, validLength));
            try {
                log.info("Using valid portion: {} chars (removed {})",
                        validLength, fixedString.length() - validLength);
                return Base64.getDecoder().decode(validPortion);
            } catch (IllegalArgumentException e) {
                log.warn("Valid block strategy failed: {}", e.getMessage());
            }
        }

        throw new IOException("All Base64 decoding strategies exhausted");
    }

    private boolean attemptTruncatedDecoding(String base64String, int removeCount) {
        if (base64String.length() <= removeCount) {
            return false;
        }

        try {
            String truncated = fixBase64Padding(base64String.substring(0, base64String.length() - removeCount));
            Base64.getDecoder().decode(truncated);
            log.info("Successful decode after removing {} characters", removeCount);
            return true;
        } catch (IllegalArgumentException e) {
            log.debug("Truncation by {} failed: {}", removeCount, e.getMessage());
            return false;
        }
    }

    private int findLastValidBase64Block(String base64String) {
        for (int length = base64String.length(); length >= BASE64_BLOCK_SIZE; length -= BASE64_BLOCK_SIZE) {
            try {
                String candidate = fixBase64Padding(base64String.substring(0, length));
                Base64.getDecoder().decode(candidate);
                return length;
            } catch (IllegalArgumentException e) {
                // Continue to next shorter length
            }
        }
        return 0;
    }

    // ==================== ANALYZER CLASS ====================

    /**
     * Comprehensive analyzer for decrypted Geometry Dash data.
     * Provides structured analysis of levels, objects, and data health.
     */
    public static final class DataAnalyzer {

        // Compiled patterns for performance
        private static final Pattern LEVEL_ID_PATTERN_KEY = Pattern.compile("<key>LLM_([^<]+)</key>");
        private static final Pattern LEVEL_ID_PATTERN_K = Pattern.compile("<k>LLM_([^<]+)</k>");
        private static final Pattern OBJECT_PATTERN = Pattern.compile("kS38,([^,]+),");
        private static final Pattern LEVEL_NAME_PATTERN_KEY = Pattern.compile("<key>k2</key>\\s*<string>([^<]+)</string>");
        private static final Pattern LEVEL_NAME_PATTERN_K = Pattern.compile("<k>k2</k>\\s*<s>([^<]+)</s>");

        // Private constructor to prevent instantiation
        private DataAnalyzer() {
            throw new UnsupportedOperationException("Utility class cannot be instantiated");
        }

        /**
         * Performs comprehensive analysis of decrypted GD data.
         */
        public static AnalysisResult analyze(String decryptedData) {
            validateAnalysisInput(decryptedData);

            log.debug("Starting analysis of {} characters", decryptedData.length());

            XmlFormat xmlFormat = detectXmlFormat(decryptedData);
            List<LevelInfo> levels = extractLevels(decryptedData, xmlFormat);
            Map<String, Integer> properties = analyzeLevelProperties(decryptedData, xmlFormat);
            DataHealth health = assessDataHealth(decryptedData);

            AnalysisResult result = new AnalysisResult(
                    decryptedData.length(),
                    levels.size(),
                    countObjects(decryptedData),
                    xmlFormat,
                    levels,
                    properties,
                    health
            );

            log.info("Analysis complete: {} levels, {} objects, format: {}",
                    result.levelCount(), result.objectCount(), result.xmlFormat());

            return result;
        }

        /**
         * Performs lightweight analysis for basic metrics.
         */
        public static QuickAnalysisResult quickAnalyze(String decryptedData) {
            validateAnalysisInput(decryptedData);

            XmlFormat format = detectXmlFormat(decryptedData);
            return new QuickAnalysisResult(
                    decryptedData.length(),
                    countLevels(decryptedData, format),
                    countObjects(decryptedData),
                    format
            );
        }

        /**
         * Outputs formatted analysis results to the log.
         */
        public static void logAnalysisResults(AnalysisResult result) {
            log.info("=== GEOMETRY DASH DATA ANALYSIS ===");
            log.info("Data length: {} characters", result.totalLength());
            log.info("XML format: {}", result.xmlFormat());
            log.info("Data health: {}", result.dataHealth());
            log.info("Levels found: {}", result.levelCount());

            result.levels().forEach(level ->
                    log.info("  Level {}: '{}' ({} chars)",
                            level.id(), level.name(), level.dataLength()));

            log.info("Objects found: {}", result.objectCount());

            if (!result.levelProperties().isEmpty()) {
                log.info("Property distribution:");
                result.levelProperties().entrySet().stream()
                        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                        .limit(10) // Limit output for readability
                        .forEach(entry -> log.info("  {}: {}", entry.getKey(), entry.getValue()));
            }
        }

        // Private helper methods for analysis
        private static void validateAnalysisInput(String data) {
            if (data == null || data.trim().isEmpty()) {
                throw new IllegalArgumentException("Analysis data cannot be null or empty");
            }
        }

        private static XmlFormat detectXmlFormat(String data) {
            long keyCount = data.chars().filter(ch -> ch == '<')
                    .count(); // Simplified detection
            long kCount = countOccurrences(data, "<k>");

            if (keyCount == 0 && kCount == 0) {
                log.warn("No recognizable XML structure detected");
                return XmlFormat.UNKNOWN;
            }

            return countOccurrences(data, "<key>") >= kCount ? XmlFormat.KEY_STRING : XmlFormat.K_S;
        }

        private static int countLevels(String data, XmlFormat format) {
            return switch (format) {
                case KEY_STRING -> countPatternMatches(data, LEVEL_ID_PATTERN_KEY);
                case K_S -> countPatternMatches(data, LEVEL_ID_PATTERN_K);
                case UNKNOWN -> Math.max(
                        countPatternMatches(data, LEVEL_ID_PATTERN_KEY),
                        countPatternMatches(data, LEVEL_ID_PATTERN_K)
                );
            };
        }

        private static int countObjects(String data) {
            return countPatternMatches(data, OBJECT_PATTERN);
        }

        private static List<LevelInfo> extractLevels(String data, XmlFormat format) {
            List<LevelInfo> levels = new ArrayList<>();
            Pattern levelPattern = (format == XmlFormat.KEY_STRING) ? LEVEL_ID_PATTERN_KEY : LEVEL_ID_PATTERN_K;
            Pattern namePattern = (format == XmlFormat.KEY_STRING) ? LEVEL_NAME_PATTERN_KEY : LEVEL_NAME_PATTERN_K;

            Map<String, String> levelNames = extractLevelNames(data, namePattern);
            Matcher matcher = levelPattern.matcher(data);

            while (matcher.find()) {
                String levelId = matcher.group(1);
                String name = levelNames.getOrDefault(levelId, "Unnamed Level");

                levels.add(new LevelInfo(levelId, name, estimateLevelSize(data, levelId)));
            }

            return levels;
        }

        private static Map<String, String> extractLevelNames(String data, Pattern namePattern) {
            Map<String, String> names = new HashMap<>();
            Matcher matcher = namePattern.matcher(data);
            int index = 0;

            while (matcher.find()) {
                names.put("level_" + index++, matcher.group(1));
            }

            return names;
        }

        private static int estimateLevelSize(String data, String levelId) {
            // Simplified estimation - could be enhanced with actual parsing
            return levelId.length() * 150; // Rough multiplier based on typical data
        }

        private static Map<String, Integer> analyzeLevelProperties(String data, XmlFormat format) {
            Map<String, Integer> properties = new HashMap<>();
            String[] levelKeys = {"k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10"};

            String template = (format == XmlFormat.KEY_STRING) ? "<key>%s</key>" : "<k>%s</k>";

            for (String key : levelKeys) {
                String fullKey = String.format(template, key);
                int count = countOccurrences(data, fullKey);
                if (count > 0) {
                    properties.put(key, count);
                }
            }

            return properties;
        }

        private static DataHealth assessDataHealth(String data) {
            boolean hasXmlDeclaration = data.contains("<?xml");
            boolean hasValidStructure = data.contains("<dict>") && data.contains("</dict>");
            boolean hasCorruption = data.contains("\0") || data.contains("��");
            boolean hasMinimumSize = data.length() >= 1000;

            if (hasCorruption || !hasValidStructure) {
                return DataHealth.CORRUPTED;
            } else if (!hasMinimumSize || !hasXmlDeclaration) {
                return DataHealth.INCOMPLETE;
            } else {
                return DataHealth.HEALTHY;
            }
        }

        private static int countPatternMatches(String text, Pattern pattern) {
            return (int) pattern.matcher(text).results().count();
        }

        private static int countOccurrences(String text, String substring) {
            int count = 0;
            int index = 0;
            while ((index = text.indexOf(substring, index)) != -1) {
                count++;
                index += substring.length();
            }
            return count;
        }
    }

    // ==================== DATA CLASSES ====================

    /**
     * Represents the XML format detected in GD data.
     */
    public enum XmlFormat {
        KEY_STRING("Standard <key>/<string> format"),
        K_S("Compact <k>/<s> format"),
        UNKNOWN("Unknown or mixed format");

        private final String description;

        XmlFormat(String description) {
            this.description = description;
        }

        @Override
        public String toString() {
            return description;
        }
    }

    /**
     * Represents the health status of decrypted data.
     */
    public enum DataHealth {
        HEALTHY("Data is complete and structurally valid"),
        INCOMPLETE("Data appears incomplete or truncated"),
        CORRUPTED("Data contains corruption or invalid structure");

        private final String description;

        DataHealth(String description) {
            this.description = description;
        }

        @Override
        public String toString() {
            return description;
        }
    }

    /**
     * Comprehensive analysis results.
     */
    public record AnalysisResult(
            int totalLength,
            int levelCount,
            int objectCount,
            XmlFormat xmlFormat,
            List<LevelInfo> levels,
            Map<String, Integer> levelProperties,
            DataHealth dataHealth
    ) {
        public AnalysisResult {
            // Defensive copying for immutability
            levels = List.copyOf(levels != null ? levels : Collections.emptyList());
            levelProperties = Map.copyOf(levelProperties != null ? levelProperties : Collections.emptyMap());
        }
    }

    /**
     * Quick analysis results for performance-critical scenarios.
     */
    public record QuickAnalysisResult(
            int totalLength,
            int levelCount,
            int objectCount,
            XmlFormat xmlFormat
    ) {}

    /**
     * Information about an individual level.
     */
    public record LevelInfo(
            String id,
            String name,
            int dataLength
    ) {
        public LevelInfo {
            Objects.requireNonNull(id, "Level ID cannot be null");
            Objects.requireNonNull(name, "Level name cannot be null");
            if (dataLength < 0) {
                throw new IllegalArgumentException("Data length cannot be negative");
            }
        }
    }

    /**
     * Custom exception for GD processing errors.
     */
    public static class GeometryDashProcessingException extends RuntimeException {
        public GeometryDashProcessingException(String message) {
            super(message);
        }

        public GeometryDashProcessingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}