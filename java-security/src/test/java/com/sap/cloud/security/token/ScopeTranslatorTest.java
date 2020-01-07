package com.sap.cloud.security.token;

import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.util.Lists.newArrayList;

public class ScopeTranslatorTest {

	private XsuaaScopeTranslator cut;

	@Before
	public void setUp() {
		cut = new XsuaaScopeTranslator();
	}

	@Test
	public void translateToLocalScope() {
		List<String> scope = newArrayList("myAppId!t1785.Read");

		List<String> translatedScope = cut.translateToLocalScope(scope);

		assertThat(translatedScope).containsExactly("Read");
	}

	@Test
	public void translateToLocalScope_doesNotTouchLocalScopedEntries() {
		List<String> scope = newArrayList("myAppId!t1785.Read", "Display");

		List<String> translatedScope = cut.translateToLocalScope(scope);

		assertThat(translatedScope).containsExactly("Read", "Display");
	}

	@Test
	public void translateToLocalScope_nothingToTranslate_returnsSameScope() {
		List<String> scope = newArrayList( "Display");

		List<String> translatedScope = cut.translateToLocalScope(scope);

		assertThat(translatedScope).containsSequence(scope);
	}

	@Test
	public void translateToLocalScope_doesNotTouchNonGlobalScopedEntries() {
		List<String> scope = newArrayList("myAppId.Read", "Display");

		List<String> translatedScope = cut.translateToLocalScope(scope);

		assertThat(translatedScope).containsSequence(scope);
	}
	@Test
	public void translateToLocalScope_scopeContainsDotAndUnderscore() {
		List<String> scope = newArrayList("my_AppId.new!t1785.Read.Context", "sub.myAppid!b13.Write.Context");

		List<String> translatedScope = cut.translateToLocalScope(scope);

		assertThat(translatedScope).containsExactly("Read.Context", "Write.Context");
	}

}
