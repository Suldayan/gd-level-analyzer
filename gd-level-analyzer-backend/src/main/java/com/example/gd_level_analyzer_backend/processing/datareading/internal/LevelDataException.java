package com.example.gd_level_analyzer_backend.processing.datareading.internal;

/**
 * Exception thrown when level data operations fail.
 */
public class LevelDataException extends Exception {
    public LevelDataException(String message) {
        super(message);
    }

    public LevelDataException(String message, Throwable cause) {
        super(message, cause);
    }
}