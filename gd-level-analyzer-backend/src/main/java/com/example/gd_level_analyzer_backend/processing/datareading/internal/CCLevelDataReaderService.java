package com.example.gd_level_analyzer_backend.processing.datareading.internal;

import com.example.gd_level_analyzer_backend.processing.datareading.LevelDataReaderService;
import com.example.gd_level_analyzer_backend.processing.shared.GeometryDashProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * File system implementation of LevelDataReaderService.
 * Reads Geometry Dash CCLocalLevels.dat files from the local filesystem.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CCLevelDataReaderService implements LevelDataReaderService {
    private final GeometryDashProperties properties;

    @Override
    public byte[] readLevelData() throws LevelDataException {
        String defaultPath = getDefaultPath();
        return readLevelData(defaultPath);
    }

    @Override
    public byte[] readLevelData(String filePath) throws LevelDataException {
        return readLevelData(Paths.get(filePath));
    }

    @Override
    public byte[] readLevelData(Path path) throws LevelDataException {
        validatePath(path);

        try {
            byte[] data = Files.readAllBytes(path);
            log.info("Successfully read {} bytes from {}", data.length, path);
            return data;
        } catch (IOException e) {
            log.error("Failed to read level data from {}: {}", path, e.getMessage());
            throw new LevelDataException("Unable to read Geometry Dash level data from: " + path, e);
        }
    }

    @Override
    public boolean isLevelDataAvailable() {
        try {
            Path defaultPath = Paths.get(getDefaultPath());
            return Files.exists(defaultPath) && Files.isReadable(defaultPath) && Files.size(defaultPath) > 0;
        } catch (IOException e) {
            log.debug("Error checking level data availability: {}", e.getMessage());
            return false;
        }
    }

    private void validatePath(Path path) throws LevelDataException {
        try {
            if (!Files.exists(path)) {
                throw new LevelDataException("File does not exist: " + path);
            }
            if (!Files.isReadable(path)) {
                throw new LevelDataException("File is not readable: " + path);
            }

            long fileSize = Files.size(path);
            if (fileSize == 0) {
                throw new LevelDataException("File is empty: " + path);
            }
            if (fileSize > properties.getMaxFileSizeBytes()) {
                throw new LevelDataException(
                        String.format("File too large (%d bytes). Maximum allowed: %d bytes",
                                fileSize, properties.getMaxFileSizeBytes()));
            }
        } catch (IOException e) {
            throw new LevelDataException("Error validating file: " + path, e);
        }
    }

    private String getDefaultPath() {
        String os = System.getProperty("os.name").toLowerCase();
        return os.contains("win") ? properties.getWindowsPath() : properties.getMacPath();
    }
}