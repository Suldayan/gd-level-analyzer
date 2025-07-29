package com.example.gd_level_analyzer_backend.leveldata.internal;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Internal service for handling decompression of Geometry Dash level data.
 * This service handles the GD-specific data format and zlib decompression.
 */
@Slf4j
@Service
public class DecompressionHandler {

    private static final int GD_HEADER_LENGTH = 10;
    private static final int BUFFER_SIZE = 1024;

    /**
     * Removes the GD-specific header from the raw level data.
     *
     * @param data the raw data including GD header
     * @return data with GD header removed
     * @throws IllegalArgumentException if data is null or too short
     */
    public byte[] removeGeometryDashHeader(byte[] data) {
        log.debug("Removing GD header from data of length: {}", data != null ? data.length : 0);

        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }

        if (data.length < GD_HEADER_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Data length (%d) too short to contain GD header (required: %d)",
                            data.length, GD_HEADER_LENGTH)
            );
        }

        byte[] result = new byte[data.length - GD_HEADER_LENGTH];
        System.arraycopy(data, GD_HEADER_LENGTH, result, 0, result.length);

        log.debug("Successfully removed GD header, resulting data length: {}", result.length);
        return result;
    }

    /**
     * Decompresses zlib-compressed data using raw deflate format.
     *
     * @param compressedData the compressed data without GD header
     * @return decompressed string in UTF-8 encoding
     * @throws IllegalArgumentException if compressed data is null or empty
     * @throws IOException if decompression fails due to invalid data format or IO errors
     */
    public String decompressZlibData(byte[] compressedData) throws IOException {
        if (compressedData == null || compressedData.length == 0) {
            throw new IllegalArgumentException("Compressed data cannot be null or empty");
        }

        log.debug("Starting zlib decompression for data of length: {}", compressedData.length);

        Inflater inflater = new Inflater(true); // Raw deflate without zlib header

        try {
            inflater.setInput(compressedData);

            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[BUFFER_SIZE];

                while (!inflater.finished()) {
                    try {
                        int decompressedLength = inflater.inflate(buffer);
                        if (decompressedLength == 0 && inflater.needsInput()) {
                            break; // No more data to decompress
                        }
                        outputStream.write(buffer, 0, decompressedLength);
                    } catch (DataFormatException e) {
                        throw new IOException("Invalid compressed data format", e);
                    }
                }

                String result = outputStream.toString(StandardCharsets.UTF_8);
                log.debug("Successfully decompressed {} bytes to {} characters", compressedData.length, result.length());
                return result;
            }
        } finally {
            inflater.end();
        }
    }

    /**
     * Complete decompression pipeline: removes GD header and decompresses data.
     *
     * @param rawData the raw GD level data
     * @return decompressed level data as string
     * @throws IllegalArgumentException if raw data is invalid
     * @throws IOException if decompression fails
     */
    public String processGeometryDashLevelData(byte[] rawData) throws IOException {
        log.info("Processing GD level data of length: {}", rawData != null ? rawData.length : 0);

        byte[] dataWithoutHeader = removeGeometryDashHeader(rawData);
        String decompressedData = decompressZlibData(dataWithoutHeader);

        log.info("Successfully processed GD level data, result length: {}", decompressedData.length());
        return decompressedData;
    }
}