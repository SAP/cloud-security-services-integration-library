package com.sap.cloud.security.xsuaa.jwt;

import com.sap.cloud.security.xsuaa.util.JSONWebKeyTestFactory;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;

public class JSONWebKeySetTest {

	public static final JSONWebKey JSON_WEB_KEY = JSONWebKeyTestFactory.create();

	private JSONWebKeySet cut;

	@Before
	public void setUp() {
		cut = new JSONWebKeySet(new ArrayList<>());
	}

	@Test
	public void isEmpty_isTrue_onEmptyJSONWebKeySet() {
		assertThat(cut.isEmpty()).isTrue();
	}

	@Test
	public void isEmpty_isFalse_whenKeyHasBeenInserted() {
		insertJsonWebKey();

		assertThat(cut.isEmpty()).isFalse();
	}

	@Test
	public void containsKeyByTypeAndId_returnsTrue_whenKeyHasBeenInserted() {
		insertJsonWebKey();

		assertThat(cut.containsKeyByTypeAndId(JSON_WEB_KEY.getType(), JSON_WEB_KEY.getId())).isTrue();
	}

	@Test
	public void containsKeyByTypeAndId_isFalse_onEmptyJSONWebKeySet() {
		assertThat(cut.containsKeyByTypeAndId(JSONWebKey.Type.RSA, JSON_WEB_KEY.getId())).isFalse();
	}
	@Test
	public void containsKeyByTypeAndId_returnsFalse_whenKeyIdDoesNotMatch() {
		String differentKeyId = "differentKeyId";

		insertJsonWebKey();

		assertThat(cut.containsKeyByTypeAndId(JSON_WEB_KEY.getType(), differentKeyId)).isFalse();
	}

	@Test
	public void containsKeyByTypeAndId_returnsFalse_whenKeyTypeDoesNotMatch() {
		JSONWebKey.Type differentKeyType = JSONWebKey.Type.APPLICATION_FORM_URLENCODED;

		insertJsonWebKey();

		assertThat(cut.containsKeyByTypeAndId(differentKeyType, JSON_WEB_KEY.getId())).isFalse();
	}

	@Test
	public void getKeyByTypeAndId_returnsKey_whenKeyHasBeenInserted() {
		insertJsonWebKey();

		assertThat(cut.getKeyByTypeAndId(JSON_WEB_KEY.getType(), JSON_WEB_KEY.getId())).isEqualTo(JSON_WEB_KEY);
	}

	@Test
	public void getKeyByTypeAndId_returnsNull_onEmptyJSONWebKeySet() {
		assertThat(cut.getKeyByTypeAndId(JSON_WEB_KEY.getType(), JSON_WEB_KEY.getId())).isNull();
	}

	@Test
	public void getKeyByTypeAndId_returnsNull_whenKeyTypeDoesNotMatch() {
		JSONWebKey.Type differentKeyType = JSONWebKey.Type.APPLICATION_FORM_URLENCODED;

		insertJsonWebKey();

		assertThat(cut.getKeyByTypeAndId(differentKeyType, JSON_WEB_KEY.getId())).isNull();
	}

	@Test
	public void getKeyByTypeAndId_returnsDefault_whenKeyIdDoesNotMatch() {
		String differentKeyId = "differentKeyId";

		insertJsonWebKey();

		assertThat(cut.getKeyByTypeAndId(JSON_WEB_KEY.getType(), differentKeyId)).isNull();
	}

	@Test
	public void getKeyByTypeAndId_returnsNull_whenKeyIdDoesNotMatch() {
		insertJsonWebKey();

		cut.put(JSONWebKeyTestFactory.createDefault());

		assertThat(cut.getKeyByTypeAndId(JSON_WEB_KEY.getType(), JSONWebKey.DEFAULT_KEY_ID).getId().equals(JSONWebKey.DEFAULT_KEY_ID));
	}

	@Test
	public void put_returnsTrue_whenKeyHasNotBeenInsertedYet() {
		boolean inserted = insertJsonWebKey();

		assertThat(inserted).isTrue();
	}

	@Test
	public void put_returnsFalse_whenKeyIsAlreadyInserted() {
		insertJsonWebKey();

		boolean inserted = insertJsonWebKey();

		assertThat(inserted).isFalse();
	}

	private boolean insertJsonWebKey() {
		return cut.put(JSON_WEB_KEY);
	}
}