package com.example.gd_level_analyzer_backend.processing.datareading;
import com.example.gd_level_analyzer_backend.processing.datareading.internal.LevelDataException;

import java.nio.file.Path;

/**
 * Service for reading Geometry Dash level data from various sources.
 * This interface defines the public API for the leveldata module.
 */
public interface LevelDataReaderService {

    /**
     * Reads level data from the default platform-specific location.
     *
     * @return the raw level data as byte array
     * @throws LevelDataException if data cannot be read
     */
    byte[] readLevelData() throws LevelDataException;

    /**
     * Reads level data from a specific file path.
     *
     * @param filePath the path to the level data file
     * @return the raw level data as byte array
     * @throws LevelDataException if data cannot be read
     */
    byte[] readLevelData(String filePath) throws LevelDataException;

    /**
     * Reads level data from a specific path.
     *
     * @param path the path to the level data file
     * @return the raw level data as byte array
     * @throws LevelDataException if data cannot be read
     */
    byte[] readLevelData(Path path) throws LevelDataException;

    /**
     * Checks if level data exists at the default location.
     *
     * @return true if level data file exists and is readable
     */
    boolean isLevelDataAvailable();
}