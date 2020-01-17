package com.sap.cloud.security.token;

import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.util.Lists.newArrayList;

public class XsuaaScopeConverterTest {

	private XsuaaScopeConverter cut;

	@Before
	public void setUp() {
		cut = new XsuaaScopeConverter("myAppId!t1785");
	}

	@Test
	public void constructsWithInvalidAppId_raisesIllegalArgumentException() {
		assertThatThrownBy(() -> {
			new XsuaaScopeConverter(null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("appId must not be null or empty");

		assertThatThrownBy(() -> {
			new XsuaaScopeConverter("");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("appId must not be null or empty");
	}

	@Test
	public void oneLocalScope() {
		List<String> scope = newArrayList("myAppId!t1785.Read");

		List<String> translatedScope = cut.convert(scope);

		assertThat(translatedScope).containsExactly("Read");
	}

	@Test
	public void doesNotTouchLocalScopedEntries() {
		List<String> scope = newArrayList("myAppId!t1785.Read", "Display");

		List<String> translatedScope = cut.convert(scope);

		assertThat(translatedScope).containsExactly("Read", "Display");
	}

	@Test
	public void nothingToTranslate_returnsSameScope() {
		List<String> scope = newArrayList("Display");

		List<String> translatedScope = cut.convert(scope);

		assertThat(translatedScope).containsSequence(scope);
	}

	@Test
	public void doesNotTouchNonGlobalScopedEntries() {
		List<String> scope = newArrayList("myAppId.Read", "Display");

		List<String> translatedScope = cut.convert(scope);

		assertThat(translatedScope).containsSequence(scope);
	}

	@Test
	public void scopeContainsDotAndUnderscore() {
		List<String> scope = newArrayList("myAppId!t1785.Read.Context", "myAppId!t1785.Write.Context");

		List<String> translatedScope = cut.convert(scope);

		assertThat(translatedScope).containsExactly("Read.Context", "Write.Context");
	}

	@Test
	public void noScopes_emptyList() {
		List<String> scope = newArrayList();

		List<String> translatedScope = cut.convert(scope);

		assertThat(translatedScope).isEmpty();
	}

}
