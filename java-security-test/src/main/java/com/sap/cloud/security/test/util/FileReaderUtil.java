package com.sap.cloud.security.test.util;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * Utility class that loads the content of files.
 */
public class FileReaderUtil {

	/**
	 * Loads the content of the file with the specified path. The path can either be
	 * specified relative to the current directory or as an absolute path. If it is
	 * an absolute path it will try to load the content from resources, e.g.
	 * {@code fileContentToString("/test.txt")} would load the file test.txt inside
	 * the resources directory. If it is not absolute it tries to load the file
	 * relative to the current directory.
	 *
	 * @param filePath
	 *            the path to the file.
	 * @return the content of the file as string
	 * @throws IOException
	 *             if the file cannot be read.
	 */
	public static String fileContentToString(String filePath) throws IOException {
		Path path = Paths.get(filePath);
		if (path.isAbsolute()) {
			Optional<Path> resourcesPath = getPathInResources(filePath);
			boolean fileExists = resourcesPath.map(Path::toFile).map(File::exists).orElse(false);
			if (fileExists) {
				return fileContentToString(resourcesPath.get());
			}
		} else {
			if (path.toFile().exists()) {
				return fileContentToString(path);
			}
		}
		throw new IOException("File does not exist: " + filePath);
	}

	private static Optional<Path> getPathInResources(String filePath) {
		return Optional.ofNullable(FileReaderUtil.class.getResource(filePath))
				.map(URL::getPath)
				.map(Paths::get);
	}

	private static String fileContentToString(Path path) throws IOException {
		return new String(Files.readAllBytes(path));
	}

}
