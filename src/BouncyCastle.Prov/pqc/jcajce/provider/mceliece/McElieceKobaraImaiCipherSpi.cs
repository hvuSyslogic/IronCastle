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
	using McElieceKobaraImaiCipher = org.bouncycastle.pqc.crypto.mceliece.McElieceKobaraImaiCipher;
	using AsymmetricHybridCipher = org.bouncycastle.pqc.jcajce.provider.util.AsymmetricHybridCipher;

	public class McElieceKobaraImaiCipherSpi : AsymmetricHybridCipher, PKCSObjectIdentifiers, X509ObjectIdentifiers
	{

		// TODO digest needed?
		private Digest digest;
		private McElieceKobaraImaiCipher cipher;

		/// <summary>
		/// buffer to store the input data
		/// </summary>
		private ByteArrayOutputStream buf = new ByteArrayOutputStream();


		public McElieceKobaraImaiCipherSpi()
		{
			buf = new ByteArrayOutputStream();
		}

		public McElieceKobaraImaiCipherSpi(Digest digest, McElieceKobaraImaiCipher cipher)
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
		/// <exception cref="BadPaddingException"> if this cipher is in decryption mode, and (un)padding has
		/// been requested, but the decrypted data is not bounded by
		/// the appropriate padding bytes </exception>
		public override byte[] doFinal(byte[] input, int inOff, int inLen)
		{
			update(input, inOff, inLen);
			if (opMode == ENCRYPT_MODE)
			{
				return cipher.messageEncrypt(this.pad());
			}
			else if (opMode == DECRYPT_MODE)
			{
				try
				{
					byte[] inputOfDecr = buf.toByteArray();
					buf.reset();

					return unpad(cipher.messageDecrypt(inputOfDecr));
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

			buf.reset();
			CipherParameters param;
			param = McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey)key);

			param = new ParametersWithRandom(param, sr);
			digest.reset();
			cipher.init(true, param);
		}

		public override void initCipherDecrypt(Key key, AlgorithmParameterSpec @params)
		{

			buf.reset();
			CipherParameters param;
			param = McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey)key);

			digest.reset();
			cipher.init(false, param);
		}

		public override string getName()
		{
			return "McElieceKobaraImaiCipher";
		}

		public override int getKeySize(Key key)
		{
			McElieceCCA2KeyParameters mcElieceCCA2KeyParameters;
			if (key is PublicKey)
			{
				mcElieceCCA2KeyParameters = (McElieceCCA2KeyParameters)McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey)key);
				return cipher.getKeySize(mcElieceCCA2KeyParameters);
			}
			else if (key is PrivateKey)
			{
				mcElieceCCA2KeyParameters = (McElieceCCA2KeyParameters)McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey)key);
				return cipher.getKeySize(mcElieceCCA2KeyParameters);
			}
			else
			{
				throw new InvalidKeyException();
			}


		}

		/// <summary>
		/// Pad and return the message stored in the message buffer.
		/// </summary>
		/// <returns> the padded message </returns>
		private byte[] pad()
		{
			buf.write(0x01);
			byte[] result = buf.toByteArray();
			buf.reset();
			return result;
		}

		/// <summary>
		/// Unpad a message.
		/// </summary>
		/// <param name="pmBytes"> the padded message </param>
		/// <returns> the message </returns>
		/// <exception cref="BadPaddingException"> if the padded message is invalid. </exception>
		private byte[] unpad(byte[] pmBytes)
		{
			// find first non-zero byte
			int index;
			for (index = pmBytes.Length - 1; index >= 0 && pmBytes[index] == 0; index--)
			{
				;
			}

			// check if padding byte is valid
			if (pmBytes[index] != 0x01)
			{
				throw new BadPaddingException("invalid ciphertext");
			}

			// extract and return message
			byte[] mBytes = new byte[index];
			JavaSystem.arraycopy(pmBytes, 0, mBytes, 0, index);
			return mBytes;
		}

		public class McElieceKobaraImai : McElieceKobaraImaiCipherSpi
		{
			public McElieceKobaraImai() : base(DigestFactory.createSHA1(), new McElieceKobaraImaiCipher())
			{
			}
		}

		public class McElieceKobaraImai224 : McElieceKobaraImaiCipherSpi
		{
			public McElieceKobaraImai224() : base(DigestFactory.createSHA224(), new McElieceKobaraImaiCipher())
			{
			}
		}

		public class McElieceKobaraImai256 : McElieceKobaraImaiCipherSpi
		{
			public McElieceKobaraImai256() : base(DigestFactory.createSHA256(), new McElieceKobaraImaiCipher())
			{
			}
		}

		public class McElieceKobaraImai384 : McElieceKobaraImaiCipherSpi
		{
			public McElieceKobaraImai384() : base(DigestFactory.createSHA384(), new McElieceKobaraImaiCipher())
			{
			}
		}

		public class McElieceKobaraImai512 : McElieceKobaraImaiCipherSpi
		{
			public McElieceKobaraImai512() : base(DigestFactory.createSHA512(), new McElieceKobaraImaiCipher())
			{
			}
		}


	}

}