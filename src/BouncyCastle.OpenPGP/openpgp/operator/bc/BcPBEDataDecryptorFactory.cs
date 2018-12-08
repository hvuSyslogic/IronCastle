using System;

namespace org.bouncycastle.openpgp.@operator.bc
{
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;

	/// <summary>
	/// A <seealso cref="PBEDataDecryptorFactory"/> for handling PBE decryption operations using the Bouncy Castle
	/// lightweight API to implement cryptographic primitives.
	/// </summary>
	public class BcPBEDataDecryptorFactory : PBEDataDecryptorFactory
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="pass">  the passphrase to use as the primary source of key material. </param>
		/// <param name="calculatorProvider">   a digest calculator provider to provide calculators to support the key generation calculation required. </param>
		public BcPBEDataDecryptorFactory(char[] pass, BcPGPDigestCalculatorProvider calculatorProvider) : base(pass, calculatorProvider)
		{
		}

		public override byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] secKeyData)
		{
			try
			{
				if (secKeyData != null && secKeyData.Length > 0)
				{
					BlockCipher engine = BcImplProvider.createBlockCipher(keyAlgorithm);
					BufferedBlockCipher cipher = BcUtil.createSymmetricKeyWrapper(false, engine, key, new byte[engine.getBlockSize()]);

					byte[] @out = new byte[secKeyData.Length];

					int len = cipher.processBytes(secKeyData, 0, secKeyData.Length, @out, 0);

					len += cipher.doFinal(@out, len);

					return @out;
				}
				else
				{
					byte[] keyBytes = new byte[key.Length + 1];

					keyBytes[0] = (byte)keyAlgorithm;
					JavaSystem.arraycopy(key, 0, keyBytes, 1, key.Length);

					return keyBytes;
				}
			}
			catch (Exception e)
			{
				throw new PGPException("Exception recovering session info", e);
			}
		}

		public override PGPDataDecryptor createDataDecryptor(bool withIntegrityPacket, int encAlgorithm, byte[] key)
		{
			BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

			return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
		}
	}

}