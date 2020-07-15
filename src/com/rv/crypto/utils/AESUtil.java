package com.rv.crypto.utils;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;

/*
 * @Author - Ranvijay
 * @Description - AES Encryption/Decryption
 */

public class AESUtil {
	
	public static void main(String[] args) throws Exception {
		System.out.println(
				"----[Cryptography] AES Example - Key generation and encrypt/decrypt----");
		System.out.println(
				"----------------------------------Client-side implementation - Start--------------------------------------");
		Map<String, String> aesKeyMap = AESUtil.getAESKey();
		System.out.println("1. Generate AES Key map which holds keys like secret, salt and aes-key "+aesKeyMap);
		String secretText = "";
		String saltText = "";
		String consolidatedAESKeyInBase64 = "";
		String textToBeEncrypt = "Hey! it's a dummy text";
		String encryptedText = "";
		if(aesKeyMap != null) {
			secretText = aesKeyMap.get("secret");
			saltText = aesKeyMap.get("salt");
			consolidatedAESKeyInBase64 = aesKeyMap.get("aes-key");
			System.out.println("1.1. Generated AES secret "+secretText);
			System.out.println("1.2. Generated AES salt "+saltText);
			System.out.println("1.3. Generated AES Base64 aes-key "+consolidatedAESKeyInBase64);
			System.out.println("2.  Initaite AES's encrypt call using generated secret and salt along with dummy fields to be encrypt like - "+textToBeEncrypt);
			encryptedText = AESUtil.encrypt(textToBeEncrypt, secretText, saltText);
			System.out.println("3.  After AES ecryption, save returned encrypted text "+encryptedText);
			System.out.println("4.  After AES ecryption, returned encrypted text need to pass in request of any required REST API backend call along with aes-key in signature (Please refer RSAUtil class)");
		}
		System.out.println(
				"----------------------------------Client-side implementation - End----------------------------------------");
		System.out.println(" ");
		System.out.println(" ");
		System.out.println(
				"----------------------------------Server-side implementation - Start---------------------------------------");
		
		System.out.println("1. Fetch aesKey from Signature header of received REST request call like "+consolidatedAESKeyInBase64);
		Base64.Decoder decoder = Base64.getDecoder();
		AESKey aesKeyObj = new Gson().fromJson(new String(decoder.decode(consolidatedAESKeyInBase64.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8), AESKey.class);
		System.out.println("2. Converted aesKey's base64 text into AESKey object like "+aesKeyObj);
		
		System.out.println("2.1 Fetch secret from AESKey object : "+aesKeyObj.getSecret());
		System.out.println("2.2 Fetch salt from AESKey object : "+aesKeyObj.getSalt());
		
		System.out.println("3.  Initaite AES's decrypt call using fetched secret and salt for earlier encrypted text");
		String decryptedText = AESUtil.decrypt(encryptedText, aesKeyObj.getSecret(), aesKeyObj.getSalt());
		System.out.println("4.  After AES decryption, save returned text - "+decryptedText);
		
		System.out.println(
				"----------------------------------Server-side implementation - End-----------------------------------------");
	}

	public static Map<String, String> getAESKey() {
		
		Map<String, String> aesKeyMap = new HashMap<>();
		Base64.Encoder encoder = Base64.getEncoder();
		
		int len = 20;
		int randNumOrigin = 48, randNumBound = 122;
		
		String secret = generateRandomPassword(len, randNumOrigin, randNumBound);
		String salt = generateRandomPassword(len, randNumOrigin, randNumBound);
		
		aesKeyMap.put("secret", secret);
		aesKeyMap.put("salt", salt);
		AESKey aesKey = new AESKey();
		aesKey.setSecret(secret);
		aesKey.setSalt(salt);
		
		aesKeyMap.put("aes-key", encoder.encodeToString(new Gson().toJson(aesKey).getBytes(StandardCharsets.UTF_8)));
		
		return aesKeyMap;
	}
	/*
	 * Password based encrypt method with parameters as content, secret and salt
	 */
	public static String encrypt(String strToEncrypt, String secret, String salt) {
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			// SecretKeyFactory factory =
			// SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}

	/*
	 * Password based decrypt method with parameters as content, secret and salt
	 */
	public static String decrypt(String strToDecrypt, String secret, String salt) {
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			// SecretKeyFactory factory =
			// SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		} catch (Exception e) {
			System.out.println("Error while decrypting: " + e.toString());
		}
		return null;
	}
	
	
	public static String generateRandomPassword(int len, int randNumOrigin, int randNumBound)
	{
		SecureRandom random = new SecureRandom();
		String specialChars = "_!#@$*-=";
		String chars = "";
		chars = random.ints(randNumOrigin, randNumBound + 1)
				.filter(i -> Character.isAlphabetic(i) || Character.isDigit(i))
				.limit(len)
				.collect(StringBuilder::new, StringBuilder::appendCodePoint,
						StringBuilder::append)
				.toString();
		
		chars = chars+specialChars;
		
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < len; i++) {
			int randomIndex = random.nextInt(chars.length());
			sb.append(chars.charAt(randomIndex));
		}

		return sb.toString();
	}
}

class AESKey {
	
	private String secret;
	private String salt;
	
	public String getSecret() {
		return secret;
	}
	public void setSecret(String secret) {
		this.secret = secret;
	}
	public String getSalt() {
		return salt;
	}
	public void setSalt(String salt) {
		this.salt = salt;
	}
	
}
