package com.sap.cloud.security.test.util;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class FileReaderUtilTest {

	private final String expectedFileContent;

	public FileReaderUtilTest() throws IOException {
		expectedFileContent = IOUtils.resourceToString("/vcap.json", StandardCharsets.UTF_8);
		;
	}

	@Test
	public void fileContentToString_canBeReadWithRelativePath() throws IOException {
		String fileContent = FileReaderUtil.fileContentToString("/vcap.json");

		assertThat(fileContent).isNotEmpty();
		assertThat(fileContent).isEqualTo(expectedFileContent);
	}

	@Test
	public void fileContentToString_canBeReadWithResourcesPath() throws IOException {
		String fileContent = FileReaderUtil.fileContentToString("src/test/resources/vcap.json");

		assertThat(fileContent).isNotEmpty();
		assertThat(fileContent).isEqualTo(expectedFileContent);
	}

	@Test
	public void fileContentToString_fileDoesNotExist_throwsException() throws IOException {
		String pathThatDoesNotExist = "__shouldNotExist___";
		assertThatThrownBy(() -> FileReaderUtil.fileContentToString(pathThatDoesNotExist))
				.isInstanceOf(IOException.class)
				.hasMessageContaining(pathThatDoesNotExist);
	}
}