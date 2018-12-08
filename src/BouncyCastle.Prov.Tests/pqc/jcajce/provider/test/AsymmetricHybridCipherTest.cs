using System;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using AsymmetricHybridCipher = org.bouncycastle.pqc.jcajce.provider.util.AsymmetricHybridCipher;
	using ByteUtils = org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

	/// <summary>
	/// Base class for unit tests of <seealso cref="AsymmetricHybridCipher"/>s.
	/// </summary>
	public abstract class AsymmetricHybridCipherTest : FlexiTest
	{

		/// <summary>
		/// the <seealso cref="KeyPairGenerator"/> to use for the test
		/// </summary>
		protected internal KeyPairGenerator kpg;

		/// <summary>
		/// the <seealso cref="AsymmetricHybridCipher"/> to use for the test
		/// </summary>
		protected internal Cipher cipher;

		private KeyPair keyPair;

		private PublicKey pubKey;

		private PrivateKey privKey;

		private byte[] mBytes, cBytes, dBytes;

		public void performEnDecryptionTest(int numPassesKPG, int numPassesEncDec, int plainTextSize, AlgorithmParameterSpec @params)
		{

			try
			{
				for (int j = 0; j < numPassesKPG; j++)
				{
					// generate key pair
					//kpg.initialize(params);
					keyPair = kpg.genKeyPair();
					pubKey = keyPair.getPublic();
					privKey = keyPair.getPrivate();

					for (int k = 1; k <= numPassesEncDec; k++)
					{
						// initialize for encryption
						cipher.init(Cipher.ENCRYPT_MODE, pubKey, @params, sr);

						// generate random message
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
						assertEquals(@"Encryption/decryption test failed for message """ + ByteUtils.toHexString(mBytes) + @""":\n actual decrypted text: " + ByteUtils.toHexString(dBytes) + "\n expected plain text: " + ByteUtils.toHexString(mBytes), mBytes, dBytes);
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