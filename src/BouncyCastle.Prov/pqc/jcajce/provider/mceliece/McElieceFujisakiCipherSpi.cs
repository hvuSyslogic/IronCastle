using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{

	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using McElieceCCA2KeyParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyParameters;
	using McElieceFujisakiCipher = org.bouncycastle.pqc.crypto.mceliece.McElieceFujisakiCipher;
	using AsymmetricHybridCipher = org.bouncycastle.pqc.jcajce.provider.util.AsymmetricHybridCipher;

	public class McElieceFujisakiCipherSpi : AsymmetricHybridCipher, PKCSObjectIdentifiers, X509ObjectIdentifiers
	{
		// TODO digest needed?
		private Digest digest;
		private McElieceFujisakiCipher cipher;

		/// <summary>
		/// buffer to store the input data
		/// </summary>
		private ByteArrayOutputStream buf;


		public McElieceFujisakiCipherSpi(Digest digest, McElieceFujisakiCipher cipher)
		{
			this.digest = digest;
			this.cipher = cipher;
			buf = new ByteArrayOutputStream();

		}

		/// <summary>
		/// Continue a multiple-part encryption or decryption operation.
		/// </summary>
		/// <param name="input"> byte array containing the next part of the input </param>
		/// <param name="inOff"> index in the array where the input starts </param>
		/// <param name="inLen"> length of the input </param>
		/// <returns> the processed byte array. </returns>
		public override byte[] update(byte[] input, int inOff, int inLen)
		{
			buf.write(input, inOff, inLen);
			return new byte[0];
		}


		/// <summary>
		/// Encrypts or decrypts data in a single-part operation, or finishes a
		/// multiple-part operation. The data is encrypted or decrypted, depending on
		/// how this cipher was initialized.
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inOff"> the offset in input where the input starts </param>
		/// <param name="inLen"> the input length </param>
		/// <returns> the new buffer with the result </returns>
		/// <exception cref="BadPaddingException"> on deryption errors. </exception>
		public override byte[] doFinal(byte[] input, int inOff, int inLen)
		{
			update(input, inOff, inLen);
			byte[] PKCSObjectIdentifiers_Fields.data = buf.toByteArray();
			buf.reset();

			if (opMode == ENCRYPT_MODE)
			{
				return cipher.messageEncrypt(PKCSObjectIdentifiers_Fields.data);
			}
			else if (opMode == DECRYPT_MODE)
			{
				try
				{
					return cipher.messageDecrypt(PKCSObjectIdentifiers_Fields.data);
				}
				catch (InvalidCipherTextException e)
				{
					throw new BadPaddingException(e.Message);
				}
			}
			else
			{
				throw new IllegalStateException("unknown mode in doFinal");
			}
		}


		public override int encryptOutputSize(int inLen)
		{
			return 0;
		}

		public override int decryptOutputSize(int inLen)
		{
			return 0;
		}

		public override void initCipherEncrypt(Key key, AlgorithmParameterSpec @params, SecureRandom sr)
		{

			CipherParameters param;
			param = McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey)key);

			param = new ParametersWithRandom(param, sr);
			digest.reset();
			cipher.init(true, param);

		}

		public override void initCipherDecrypt(Key key, AlgorithmParameterSpec @params)
		{

			CipherParameters param;
			param = McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey)key);

			digest.reset();
			cipher.init(false, param);
		}

		public override string getName()
		{
			return "McElieceFujisakiCipher";
		}

		public override int getKeySize(Key key)
		{
			McElieceCCA2KeyParameters mcElieceCCA2KeyParameters;
			if (key is PublicKey)
			{
				mcElieceCCA2KeyParameters = (McElieceCCA2KeyParameters)McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey)key);
			}
			else
			{
				mcElieceCCA2KeyParameters = (McElieceCCA2KeyParameters)McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey)key);

			}


			return cipher.getKeySize(mcElieceCCA2KeyParameters);
		}


		//////////////////////////////////////////////////////////////////////////////////

		public class McElieceFujisaki : McElieceFujisakiCipherSpi
		{
			public McElieceFujisaki() : base(DigestFactory.createSHA1(), new McElieceFujisakiCipher())
			{
			}
		}
	}

}