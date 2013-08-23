package cmsc414.p1;
import java.nio.ByteBuffer;

import javax.crypto.*;

/* Author: Alexander Bezobchuk */
/* Please do not reproduce */

public class Encrypter {
	private String encryptionType;
	
	/* Determines if AES or DES should be used */
	public Encrypter(String encryptionType) {
		if (encryptionType.equals("AES")) {
			this.encryptionType = "AES";
		}
		else if (encryptionType.equals("DES")){
			this.encryptionType = "DES";
		}
		else
			System.out.println("ERROR: COULD NOT INITIALIZE ENCRYPTIONTYPE.");
		encryptionType = null;
	}
	
	/* Generates a secret key based in encryptionType (either AES or DES) */
	public SecretKey generateSecretKey() {
		if (encryptionType.equals("AES") || encryptionType.equalsIgnoreCase("AES")) {
			try {
				KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
				keygenerator.init(128);
				return keygenerator.generateKey();
			} catch (Exception e) {
				System.out.println("ERROR: COULD NOT GENERATE AES SECRET KEY");
			}

		} else if (encryptionType.equals("DES") || encryptionType.equalsIgnoreCase("DES")) {
			try {
				KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
				return keygenerator.generateKey();
			} catch (Exception e) {
				System.out.println("ERROR: COULD NOT GENERATE DES SECRET KEY");
			}
		}
		return null;
	}
	
	/* Encryptes a plaintext msg in using CBC, with either AES or DES */
	/* Returns a string in Base64 of the encrypted message */
	public String encrypt(String plainText, SecretKey secretKey) {

		if (encryptionType.equals("DES") || encryptionType.equalsIgnoreCase("DES")) {
			try {
				Cipher des_cipher = Cipher.getInstance("DES/ECB/NoPadding");
				des_cipher.init(Cipher.ENCRYPT_MODE, secretKey);
				byte[] iv = {0,0,0,0,0,0,0,0};
				byte[] msg = plainText.getBytes("UTF8");
				byte[] xor_msg = new byte[8];
				ByteBuffer ciphertext = ByteBuffer.allocate(msg.length);


					for (int i = 0; i < msg.length; i+=8) {
						int k = 0;
						xor_msg = new byte[8];
						for (int j = i; j < i + 8; j++) {
							xor_msg[k] = (byte) (msg[j] ^ iv[k]);
							k++;
						}
						byte[] encrypted_block = des_cipher.doFinal(xor_msg);
						iv = encrypted_block.clone();
						ciphertext.put(encrypted_block);
					}
					return new String(Base64Coder.encode(ciphertext.array()));


			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}

		} else if (encryptionType.equals("AES") || encryptionType.equalsIgnoreCase("AES")) {

			try {
				Cipher aes_cipher = Cipher.getInstance("AES/ECB/NoPadding");
				aes_cipher.init(Cipher.ENCRYPT_MODE, secretKey);
				byte[] iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
				byte[] msg = plainText.getBytes("UTF8");
				byte[] xor_msg = new byte[16];
				ByteBuffer ciphertext = ByteBuffer.allocate(msg.length);
				
					for (int i = 0; i < msg.length; i+=16) {
						int k = 0;
						xor_msg = new byte[16];
						for (int j = i; j < i + 16; j++) {
							xor_msg[k] = (byte) (msg[j] ^ iv[k]);
							k++;
						}
						byte[] encrypted_block = aes_cipher.doFinal(xor_msg);
						iv = encrypted_block;
						ciphertext = ciphertext.put(encrypted_block);
					}
					return new String(Base64Coder.encode(ciphertext.array()));


			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		else
			return null;
	}

	/* Decryptes a ciphertext from Base64 to UTF-8 using CBC, with either AES or DES */
	public String decrypt(String cipherText, SecretKey secretKey) {
		if (encryptionType.equals("DES") || encryptionType.equalsIgnoreCase("DES")) {
			try {
				byte[] enc_msg = Base64Coder.decode(cipherText);
				byte[] iv = {0,0,0,0,0,0,0,0};
				Cipher des_cipher = Cipher.getInstance("DES/ECB/NoPadding");
				des_cipher.init(Cipher.DECRYPT_MODE, secretKey);
				byte[] xor_msg = new byte[8];
				byte[] ciph_msg_block = new byte[8];
				ByteBuffer plainText = ByteBuffer.allocate(enc_msg.length);
				
				for (int i = 0; i < enc_msg.length; i+=8) {
					int k = 0;
					for (int j = i; j < i + 8; j++) {
						
						ciph_msg_block[k] = enc_msg[j];
						k++;
					}
					byte[] dec_msg_block = des_cipher.doFinal(ciph_msg_block);
					for (int r = 0; r < 8; r++) {
						xor_msg[r] = (byte) (dec_msg_block[r] ^ iv[r]);
					}
					plainText.put(xor_msg);
					iv = ciph_msg_block.clone();
				}
				return new String(plainText.array());
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		else if (encryptionType.equals("AES") || encryptionType.equalsIgnoreCase("AES")) {
			try {
				byte[] enc_msg = Base64Coder.decode(cipherText);
				byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
				Cipher aes_cipher = Cipher.getInstance("AES/ECB/NoPadding");
				aes_cipher.init(Cipher.DECRYPT_MODE, secretKey);
				byte[] xor_msg = new byte[16];
				byte[] ciph_msg_block = new byte[16];
				ByteBuffer plainText = ByteBuffer.allocate(enc_msg.length);
				
				for (int i = 0; i < enc_msg.length; i+=16) {
					int k = 0;
					for (int j = i; j < i + 16; j++) {
						
						ciph_msg_block[k] = enc_msg[j];
						k++;
					}
					byte[] dec_msg_block = aes_cipher.doFinal(ciph_msg_block);
					for (int r = 0; r < 16; r++) {
						xor_msg[r] = (byte) (dec_msg_block[r] ^ iv[r]);
					}
					plainText.put(xor_msg);
					iv = ciph_msg_block.clone();
				}
				return new String(plainText.array());
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		else
			return null;
	}
}