package com.rv.crypto.utils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.google.gson.Gson;

/*
 * @Author - Ranvijay
 * @Description - RSA Encryption/Decryption and Customized Signature and it's verification
 */
public class RSAUtil {

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, UnrecoverableEntryException, InvalidKeySpecException {
// Generate KeyPair from .p12 file
// Note : .p12 file has been generated using keytool command from jdk bin :
// keytool -genkeypair -alias ssl_localhost_certificate -keyalg RSA -keysize
// 2048 -storetype PKCS12 -keystore finshell-ssl-Jul20-key.p12 -validity 3650
		/*
		 * InputStream ins = new FileInputStream(
		 * "A:\\Projects\\SFE\\los_apis\\oppo-common-services\\oauth-server\\finshell-ssl-Jul20-key.p12"
		 * );
		 * 
		 * KeyStore keyStore = KeyStore.getInstance("PKCS12"); keyStore.load(ins,
		 * "rv_pass_2020".toCharArray()); //Keystore password
		 * KeyStore.PasswordProtection keyPassword = //Key password new
		 * KeyStore.PasswordProtection("rv_pass_2020".toCharArray());
		 * 
		 * KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
		 * keyStore.getEntry("ssl_localhost_certificate", keyPassword);
		 * 
		 * java.security.cert.Certificate cert =
		 * keyStore.getCertificate("ssl_localhost_certificate"); PublicKey publicKey =
		 * cert.getPublicKey(); PrivateKey privateKey = privateKeyEntry.getPrivateKey();
		 * 
		 * 
		 * Base64.Encoder encoder = Base64.getEncoder();
		 * 
		 * String outFile = "A:\\Projects\\rv_ssl_server_cert"; // Writer out = new
		 * FileWriter(outFile + ".key"); //
		 * out.write("-----BEGIN RSA PRIVATE KEY-----\n"); //
		 * out.write(encoder.encodeToString(privateKey.getEncoded())); //
		 * out.write("\n-----END RSA PRIVATE KEY-----\n"); // out.close(); // // out =
		 * new FileWriter(outFile + ".pub"); //
		 * out.write("-----BEGIN RSA PUBLIC KEY-----\n"); //
		 * out.write(encoder.encodeToString(publicKey.getEncoded())); //
		 * out.write("\n-----END RSA PUBLIC KEY-----\n"); // out.close();
		 * 
		 * OutputStream out = null; out = new FileOutputStream(outFile + ".key");
		 * out.write(privateKey.getEncoded()); out.close();
		 * 
		 * out = new FileOutputStream(outFile + ".pub");
		 * out.write(publicKey.getEncoded()); out.close();
		 */

		try {
			System.out.println(
					"----[Cryptography] RSA Example - Keypair generation, encrypt/decrypt, signature and their verification----");
			System.out.println(
					"----------------------------------Client-side implementation - Start--------------------------------------");
			System.out.println(
					"1. Uncomment keypair generation code and generate public private key[Note : this should be one time activity]");
			System.out.println("2. Get generated public-key for encryption - " + RSAUtil.getServerPublicKey());
            
			//This is dummy Signature DTO for reference
			String messageBody = "Hey! this is dummy payload in simple text! i.e if you have JSON request, then first convert the same into String using any JSON library like new Gson().toJson().";
			SignatureDTO dataToBeSigned = new SignatureDTO<>();
			dataToBeSigned.setAesKey("na");
			dataToBeSigned.setAlgorithm("SHA-256");
			dataToBeSigned.setApiKey("dummy-api-key");
			dataToBeSigned.setHost("localhost");
			dataToBeSigned.setRequestBody(messageBody);
			
			System.out.println(
					"3. AES Encryption of requestBody(or it's fields) is not in scope for this demo. Although, same can be done using AES methods with dynamically generated AES key/secret and same need to be put in Signature DTO further for RSA encryption");
			System.out.println("4. Create new Signtature DTO to be encypted and signed like - "
					+ new Gson().toJson(dataToBeSigned));
			System.out.println(
					"5. Started signature-process to sign and encrypt Signtature DTO having requestBody digest, AES-Secret used in requestBody encryption and other signature stamps");
			String encryptedSignature = RSAUtil.getSignatureValue(RSAUtil.getServerPublicKey(), dataToBeSigned);
			System.out.println(
					"6. NOW, Client's implementation ends here, fetched signature in Base64 text need to be pass in any backend's REST API as http-header with tag name as 'Signature' along with other headers");
			System.out.println(
					"----------------------------------Client-side implementation - End----------------------------------------");
			System.out.println(" ");
			System.out.println(" ");

			System.out.println(
					"----------------------------------Server-side implementation - Start--------------------------------------");
			System.out.println("1. Read the header 'Signature' in String from received REST API request");
			System.out.println("2. Get generated private-key for decryption -  " + RSAUtil.getServerPrivateKey());
			System.out.println(
					"3. Initiate signature-verification along with private key, received encrypted signature and orignal request body to compare ");
			Map<String, Object> verificationOutput = RSAUtil.verifySignatureValue(RSAUtil.getServerPrivateKey(),
					encryptedSignature, messageBody);
			System.out.println("2. Handle verification-output for values like -  " + verificationOutput);
			System.out.println("2.1 status - " + verificationOutput.get("status"));
			System.out.println("2.2 verified - " + verificationOutput.get("verified"));
			System.out.println("2.3 signature - " + verificationOutput.get("signature"));

			System.out.println(
					"3. If verification done successfully and signaure is found, fetch AES-key used during AES encryption of request Body fields and decrypt those fields using AES Decrypt method ");
			if (verificationOutput.get("signature") != null) {
				dataToBeSigned = (SignatureDTO) verificationOutput.get("signature");
				System.out.println("3.1 AES-Key " + dataToBeSigned.getAesKey());
				System.out.println("3.2 API-Key " + dataToBeSigned.getApiKey());
			}

			System.out.println(
					"4. If verification done successfully and also verified, proceed with further execution of the called REST API, ELSE throw exception");
			if (!(verificationOutput.get("verified") != null && (boolean) verificationOutput.get("verified"))) {
				throw new Exception("Signature Verification Failed");
			}

			System.out.println(
					"----------------------------------Server-side implementation - End----------------------------------------");

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static PrivateKey getServerPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		/* Read all bytes from the private key file */
		Path path = Paths.get("A:\\Projects\\rv_ssl_server_cert.key");
		byte[] bytes = Files.readAllBytes(path);

		/* Generate private key. */
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey pvt = kf.generatePrivate(ks);
		return pvt;
	}

	public static PublicKey getServerPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		/* Read all the public key bytes */
		Path path = Paths.get("A:\\Projects\\rv_ssl_server_cert.pub");
		byte[] bytes = Files.readAllBytes(path);

		/* Generate public key. */
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pub = kf.generatePublic(ks);
		return pub;
	}

	public static byte[] encrypt(Key key, byte[] bytes) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedBytes = cipher.doFinal(bytes);
		System.out.println("RSA encryption done!");
		return encryptedBytes;
	}

	public static byte[] decrypt(Key key, byte[] encryptedBytes) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
		System.out.println("RSA decryption done!");
		return decryptedBytes;
	}

	public static String getSignatureValue(Key key, SignatureDTO dataToBeSigned) throws Exception {
		Base64.Encoder encoder = Base64.getEncoder();
//Create message digest for the request-body received in Signature DTO 
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] messageHash = md.digest(dataToBeSigned.getRequestBody().getBytes(StandardCharsets.UTF_8));
//After getting the hash for request-body, set again the same in Signature DTO for further encryption along with other signature params
		dataToBeSigned.setRequestBody(new String(messageHash, StandardCharsets.UTF_8));
		byte[] messageBytes = new Gson().toJson(dataToBeSigned).getBytes(StandardCharsets.UTF_8);

//Encrypt the signature bytes and return as Base64 text
		messageBytes = RSAUtil.encrypt(key, messageBytes);
		return encoder.encodeToString(messageBytes);
	}

	public static Map<String, Object> verifySignatureValue(Key key, String signatureInBase64ToBeVerify, String messageInBase64)
			throws Exception {

		Map<String, Object> output = new HashMap<String, Object>();
		output.put("status", "FAIL");
		output.put("verified", Boolean.FALSE);

		try {
			Base64.Decoder decoder = Base64.getDecoder();
			Base64.Encoder encoder = Base64.getEncoder();
			byte[] encryptedMessageDigest = decoder.decode(signatureInBase64ToBeVerify);

			byte[] decryptedMessageDigest = RSAUtil.decrypt(key, encryptedMessageDigest);

			String message = new String(decryptedMessageDigest, StandardCharsets.UTF_8);

			SignatureDTO signature = new Gson().fromJson(message, SignatureDTO.class);

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] messageHash = md.digest(messageInBase64.getBytes(StandardCharsets.UTF_8));
			messageInBase64 = new String(messageHash, StandardCharsets.UTF_8);

			if (signature.getRequestBody().equals(messageInBase64)) {
				output.put("verified", Boolean.TRUE);
			}
			output.put("status", "SUCCESS");
			output.put("signature", signature);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return output;
	}

	

}


class SignatureDTO<T> {

	private String aesKey;
	private String apiKey;
	private String host;
	private String algorithm;
	private String requestBody;

	public String getAesKey() {
		return aesKey;
	}

	public void setAesKey(String aesKey) {
		this.aesKey = aesKey;
	}

	public String getApiKey() {
		return apiKey;
	}

	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getRequestBody() {
		return requestBody;
	}

	public void setRequestBody(String requestBody) {
		this.requestBody = requestBody;
	}

}
