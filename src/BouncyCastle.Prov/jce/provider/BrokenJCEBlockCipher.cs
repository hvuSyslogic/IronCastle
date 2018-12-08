using System;

namespace org.bouncycastle.jce.provider
{


	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using DataLengthException = org.bouncycastle.crypto.DataLengthException;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using DESedeEngine = org.bouncycastle.crypto.engines.DESedeEngine;
	using TwofishEngine = org.bouncycastle.crypto.engines.TwofishEngine;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using CFBBlockCipher = org.bouncycastle.crypto.modes.CFBBlockCipher;
	using CTSBlockCipher = org.bouncycastle.crypto.modes.CTSBlockCipher;
	using OFBBlockCipher = org.bouncycastle.crypto.modes.OFBBlockCipher;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using RC2Parameters = org.bouncycastle.crypto.@params.RC2Parameters;
	using RC5Parameters = org.bouncycastle.crypto.@params.RC5Parameters;
	using BCPBEKey = org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
	using Strings = org.bouncycastle.util.Strings;

	public class BrokenJCEBlockCipher : BrokenPBE
	{
		//
		// specs we can handle.
		//
		private Class[] availableSpecs = new Class[] {typeof(IvParameterSpec), typeof(PBEParameterSpec), typeof(RC2ParameterSpec), typeof(RC5ParameterSpec)};

		private BufferedBlockCipher cipher;
		private ParametersWithIV ivParam;

		private int pbeType = BrokenPBE_Fields.PKCS12;
		private int pbeHash = BrokenPBE_Fields.SHA1;
		private int pbeKeySize;
		private int pbeIvSize;

		private int ivLength = 0;

		private AlgorithmParameters engineParams = null;

		public BrokenJCEBlockCipher(BlockCipher engine)
		{
			cipher = new PaddedBufferedBlockCipher(engine);
		}

		public BrokenJCEBlockCipher(BlockCipher engine, int pbeType, int pbeHash, int pbeKeySize, int pbeIvSize)
		{
			cipher = new PaddedBufferedBlockCipher(engine);

			this.pbeType = pbeType;
			this.pbeHash = pbeHash;
			this.pbeKeySize = pbeKeySize;
			this.pbeIvSize = pbeIvSize;
		}

		public virtual int engineGetBlockSize()
		{
			return cipher.getBlockSize();
		}

		public virtual byte[] engineGetIV()
		{
			return (ivParam != null) ? ivParam.getIV() : null;
		}

		public virtual int engineGetKeySize(Key key)
		{
			return key.getEncoded().length;
		}

		public virtual int engineGetOutputSize(int inputLen)
		{
			return cipher.getOutputSize(inputLen);
		}

		public virtual AlgorithmParameters engineGetParameters()
		{
			if (engineParams == null)
			{
				if (ivParam != null)
				{
					string name = cipher.getUnderlyingCipher().getAlgorithmName();

					if (name.IndexOf('/') >= 0)
					{
						name = name.Substring(0, name.IndexOf('/'));
					}

					try
					{
						engineParams = AlgorithmParameters.getInstance(name, BouncyCastleProvider.PROVIDER_NAME);
						engineParams.init(ivParam.getIV());
					}
					catch (Exception e)
					{
						throw new RuntimeException(e.ToString());
					}
				}
			}

			return engineParams;
		}

		public virtual void engineSetMode(string mode)
		{
			string modeName = Strings.toUpperCase(mode);

			if (modeName.Equals("ECB"))
			{
				ivLength = 0;
				cipher = new PaddedBufferedBlockCipher(cipher.getUnderlyingCipher());
			}
			else if (modeName.Equals("CBC"))
			{
				ivLength = cipher.getUnderlyingCipher().getBlockSize();
				cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(cipher.getUnderlyingCipher()));
			}
			else if (modeName.StartsWith("OFB", StringComparison.Ordinal))
			{
				ivLength = cipher.getUnderlyingCipher().getBlockSize();
				if (modeName.Length != 3)
				{
					int wordSize = int.Parse(modeName.Substring(3));

					cipher = new PaddedBufferedBlockCipher(new OFBBlockCipher(cipher.getUnderlyingCipher(), wordSize));
				}
				else
				{
					cipher = new PaddedBufferedBlockCipher(new OFBBlockCipher(cipher.getUnderlyingCipher(), 8 * cipher.getBlockSize()));
				}
			}
			else if (modeName.StartsWith("CFB", StringComparison.Ordinal))
			{
				ivLength = cipher.getUnderlyingCipher().getBlockSize();
				if (modeName.Length != 3)
				{
					int wordSize = int.Parse(modeName.Substring(3));

					cipher = new PaddedBufferedBlockCipher(new CFBBlockCipher(cipher.getUnderlyingCipher(), wordSize));
				}
				else
				{
					cipher = new PaddedBufferedBlockCipher(new CFBBlockCipher(cipher.getUnderlyingCipher(), 8 * cipher.getBlockSize()));
				}
			}
			else
			{
				throw new IllegalArgumentException("can't support mode " + mode);
			}
		}

		public virtual void engineSetPadding(string padding)
		{
			string paddingName = Strings.toUpperCase(padding);

			if (paddingName.Equals("NOPADDING"))
			{
				cipher = new BufferedBlockCipher(cipher.getUnderlyingCipher());
			}
			else if (paddingName.Equals("PKCS5PADDING") || paddingName.Equals("PKCS7PADDING") || paddingName.Equals("ISO10126PADDING"))
			{
				cipher = new PaddedBufferedBlockCipher(cipher.getUnderlyingCipher());
			}
			else if (paddingName.Equals("WITHCTS"))
			{
				cipher = new CTSBlockCipher(cipher.getUnderlyingCipher());
			}
			else
			{
				throw new NoSuchPaddingException("Padding " + padding + " unknown.");
			}
		}

		public virtual void engineInit(int opmode, Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			CipherParameters param;

			//
			// a note on iv's - if ivLength is zero the IV gets ignored (we don't use it).
			//
			if (key is BCPBEKey)
			{
				param = BrokenPBE_Util.makePBEParameters((BCPBEKey)key, @params, pbeType, pbeHash, cipher.getUnderlyingCipher().getAlgorithmName(), pbeKeySize, pbeIvSize);

				if (pbeIvSize != 0)
				{
					ivParam = (ParametersWithIV)param;
				}
			}
			else if (@params == null)
			{
				param = new KeyParameter(key.getEncoded());
			}
			else if (@params is IvParameterSpec)
			{
				if (ivLength != 0)
				{
					param = new ParametersWithIV(new KeyParameter(key.getEncoded()), ((IvParameterSpec)@params).getIV());
					ivParam = (ParametersWithIV)param;
				}
				else
				{
					param = new KeyParameter(key.getEncoded());
				}
			}
			else if (@params is RC2ParameterSpec)
			{
				RC2ParameterSpec rc2Param = (RC2ParameterSpec)@params;

				param = new RC2Parameters(key.getEncoded(), ((RC2ParameterSpec)@params).getEffectiveKeyBits());

				if (rc2Param.getIV() != null && ivLength != 0)
				{
					param = new ParametersWithIV(param, rc2Param.getIV());
					ivParam = (ParametersWithIV)param;
				}
			}
			else if (@params is RC5ParameterSpec)
			{
				RC5ParameterSpec rc5Param = (RC5ParameterSpec)@params;

				param = new RC5Parameters(key.getEncoded(), ((RC5ParameterSpec)@params).getRounds());
				if (rc5Param.getWordSize() != 32)
				{
					throw new IllegalArgumentException("can only accept RC5 word size 32 (at the moment...)");
				}
				if ((rc5Param.getIV() != null) && (ivLength != 0))
				{
					param = new ParametersWithIV(param, rc5Param.getIV());
					ivParam = (ParametersWithIV)param;
				}
			}
			else
			{
				throw new InvalidAlgorithmParameterException("unknown parameter type.");
			}

			if ((ivLength != 0) && !(param is ParametersWithIV))
			{
				if (random == null)
				{
					random = CryptoServicesRegistrar.getSecureRandom();
				}

				if ((opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE))
				{
					byte[] iv = new byte[ivLength];

					random.nextBytes(iv);
					param = new ParametersWithIV(param, iv);
					ivParam = (ParametersWithIV)param;
				}
				else
				{
					throw new InvalidAlgorithmParameterException("no IV set when one expected");
				}
			}

			switch (opmode)
			{
			case Cipher.ENCRYPT_MODE:
			case Cipher.WRAP_MODE:
				cipher.init(true, param);
				break;
			case Cipher.DECRYPT_MODE:
			case Cipher.UNWRAP_MODE:
				cipher.init(false, param);
				break;
			default:
				JavaSystem.@out.println("eeek!");
			break;
			}
		}

		public virtual void engineInit(int opmode, Key key, AlgorithmParameters @params, SecureRandom random)
		{
			AlgorithmParameterSpec paramSpec = null;

			if (@params != null)
			{
				for (int i = 0; i != availableSpecs.Length; i++)
				{
					try
					{
						paramSpec = @params.getParameterSpec(availableSpecs[i]);
						break;
					}
					catch (Exception)
					{
						continue;
					}
				}

				if (paramSpec == null)
				{
					throw new InvalidAlgorithmParameterException("can't handle parameter " + @params.ToString());
				}
			}

			engineParams = @params;
			engineInit(opmode, key, paramSpec, random);
		}

		public virtual void engineInit(int opmode, Key key, SecureRandom random)
		{
			try
			{
				engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				throw new IllegalArgumentException(e.Message);
			}
		}

		public virtual byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
		{
			int length = cipher.getUpdateOutputSize(inputLen);

			if (length > 0)
			{
					byte[] @out = new byte[length];

					cipher.processBytes(input, inputOffset, inputLen, @out, 0);
					return @out;
			}

			cipher.processBytes(input, inputOffset, inputLen, null, 0);

			return null;
		}

		public virtual int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			return cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
		}

		public virtual byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
		{
			int len = 0;
			byte[] tmp = new byte[engineGetOutputSize(inputLen)];

			if (inputLen != 0)
			{
				len = cipher.processBytes(input, inputOffset, inputLen, tmp, 0);
			}

			try
			{
				len += cipher.doFinal(tmp, len);
			}
			catch (DataLengthException e)
			{
				throw new IllegalBlockSizeException(e.Message);
			}
			catch (InvalidCipherTextException e)
			{
				throw new BadPaddingException(e.Message);
			}

			byte[] @out = new byte[len];

			JavaSystem.arraycopy(tmp, 0, @out, 0, len);

			return @out;
		}

		public virtual int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			int len = 0;

			if (inputLen != 0)
			{
					len = cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
			}

			try
			{
				return len + cipher.doFinal(output, outputOffset + len);
			}
			catch (DataLengthException e)
			{
				throw new IllegalBlockSizeException(e.Message);
			}
			catch (InvalidCipherTextException e)
			{
				throw new BadPaddingException(e.Message);
			}
		}

		public virtual byte[] engineWrap(Key key)
		{
			byte[] encoded = key.getEncoded();
			if (encoded == null)
			{
				throw new InvalidKeyException("Cannot wrap key, null encoding.");
			}

			try
			{
				return engineDoFinal(encoded, 0, encoded.Length);
			}
			catch (BadPaddingException e)
			{
				throw new IllegalBlockSizeException(e.Message);
			}
		}

		public virtual Key engineUnwrap(byte[] wrappedKey, string wrappedKeyAlgorithm, int wrappedKeyType)
		{
			byte[] encoded = null;
			try
			{
				encoded = engineDoFinal(wrappedKey, 0, wrappedKey.Length);
			}
			catch (BadPaddingException e)
			{
				throw new InvalidKeyException(e.Message);
			}
			catch (IllegalBlockSizeException e2)
			{
				throw new InvalidKeyException(e2.Message);
			}

			if (wrappedKeyType == Cipher.SECRET_KEY)
			{
				return new SecretKeySpec(encoded, wrappedKeyAlgorithm);
			}
			else
			{
				try
				{
					KeyFactory kf = KeyFactory.getInstance(wrappedKeyAlgorithm, BouncyCastleProvider.PROVIDER_NAME);

					if (wrappedKeyType == Cipher.PUBLIC_KEY)
					{
						return kf.generatePublic(new X509EncodedKeySpec(encoded));
					}
					else if (wrappedKeyType == Cipher.PRIVATE_KEY)
					{
						return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
					}
				}
				catch (NoSuchProviderException e)
				{
					throw new InvalidKeyException("Unknown key type " + e.Message);
				}
				catch (NoSuchAlgorithmException e)
				{
					throw new InvalidKeyException("Unknown key type " + e.Message);
				}
				catch (InvalidKeySpecException e2)
				{
					throw new InvalidKeyException("Unknown key type " + e2.Message);
				}

				throw new InvalidKeyException("Unknown key type " + wrappedKeyType);
			}
		}

		/*
		 * The ciphers that inherit from us.
		 */

		/// <summary>
		/// PBEWithMD5AndDES
		/// </summary>
		public class BrokePBEWithMD5AndDES : BrokenJCEBlockCipher
		{
			public BrokePBEWithMD5AndDES() : base(new CBCBlockCipher(new DESEngine()), BrokenPBE_Fields.PKCS5S1, BrokenPBE_Fields.MD5, 64, 64)
			{
			}
		}

		/// <summary>
		/// PBEWithSHA1AndDES
		/// </summary>
		public class BrokePBEWithSHA1AndDES : BrokenJCEBlockCipher
		{
			public BrokePBEWithSHA1AndDES() : base(new CBCBlockCipher(new DESEngine()), BrokenPBE_Fields.PKCS5S1, BrokenPBE_Fields.SHA1, 64, 64)
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAnd3-KeyTripleDES-CBC
		/// </summary>
		public class BrokePBEWithSHAAndDES3Key : BrokenJCEBlockCipher
		{
			public BrokePBEWithSHAAndDES3Key() : base(new CBCBlockCipher(new DESedeEngine()), BrokenPBE_Fields.PKCS12, BrokenPBE_Fields.SHA1, 192, 64)
			{
			}
		}

		/// <summary>
		/// OldPBEWithSHAAnd3-KeyTripleDES-CBC
		/// </summary>
		public class OldPBEWithSHAAndDES3Key : BrokenJCEBlockCipher
		{
			public OldPBEWithSHAAndDES3Key() : base(new CBCBlockCipher(new DESedeEngine()), BrokenPBE_Fields.OLD_PKCS12, BrokenPBE_Fields.SHA1, 192, 64)
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAnd2-KeyTripleDES-CBC
		/// </summary>
		public class BrokePBEWithSHAAndDES2Key : BrokenJCEBlockCipher
		{
			public BrokePBEWithSHAAndDES2Key() : base(new CBCBlockCipher(new DESedeEngine()), BrokenPBE_Fields.PKCS12, BrokenPBE_Fields.SHA1, 128, 64)
			{
			}
		}

		/// <summary>
		/// OldPBEWithSHAAndTwofish-CBC
		/// </summary>
		public class OldPBEWithSHAAndTwofish : BrokenJCEBlockCipher
		{
			public OldPBEWithSHAAndTwofish() : base(new CBCBlockCipher(new TwofishEngine()), BrokenPBE_Fields.OLD_PKCS12, BrokenPBE_Fields.SHA1, 256, 128)
			{
			}
		}
	}

}