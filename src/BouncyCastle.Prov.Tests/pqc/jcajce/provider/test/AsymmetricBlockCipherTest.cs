using System;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using ByteUtils = org.bouncycastle.pqc.math.linearalgebra.ByteUtils;


	public abstract class AsymmetricBlockCipherTest : FlexiTest
	{

		protected internal Cipher cipher;

		protected internal KeyPair keyPair;

		protected internal PublicKey pubKey;

		protected internal PrivateKey privKey;

		protected internal KeyPairGenerator kpg;

		private byte[] mBytes;

		private byte[] cBytes;

		private byte[] dBytes;

		public void performEnDecryptionTest(int numPassesKPG, int numPassesEncDec, AlgorithmParameterSpec @params)
		{

			try
			{
				for (int j = 0; j < numPassesKPG; j++)
				{
					keyPair = kpg.genKeyPair();
					pubKey = keyPair.getPublic();
					privKey = keyPair.getPrivate();

					for (int k = 1; k <= numPassesEncDec; k++)
					{
						// initialize for encryption
						cipher.init(Cipher.ENCRYPT_MODE, pubKey, @params, sr);

						// generate random message
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int plainTextSize = cipher.getBlockSize();
						int plainTextSize = cipher.getBlockSize();
						int mLength = rand.nextInt(plainTextSize) + 1;
						mBytes = new byte[mLength];
						rand.nextBytes(mBytes);

						// encrypt
						cBytes = cipher.doFinal(mBytes);

						// initialize for decryption
						cipher.init(Cipher.DECRYPT_MODE, privKey, @params);

						// decrypt
						dBytes = cipher.doFinal(cBytes);

						// compare
						assertEquals("Encryption and Decryption test failed:\n" + " actual decrypted text: " + ByteUtils.toHexString(dBytes) + "\n expected plain text: " + ByteUtils.toHexString(mBytes), mBytes, dBytes);
					}
				}
			}
			catch (Exception e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
				fail(e);
			}
		}

	}

}