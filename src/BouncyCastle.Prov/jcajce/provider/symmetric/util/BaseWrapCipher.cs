using System;

namespace org.bouncycastle.jcajce.provider.symmetric.util
{


	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using Wrapper = org.bouncycastle.crypto.Wrapper;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ParametersWithSBox = org.bouncycastle.crypto.@params.ParametersWithSBox;
	using ParametersWithUKM = org.bouncycastle.crypto.@params.ParametersWithUKM;
	using GOST28147WrapParameterSpec = org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Arrays = org.bouncycastle.util.Arrays;

	public abstract class BaseWrapCipher : CipherSpi, PBE
	{
		//
		// specs we can handle.
		//
		private Class[] availableSpecs = new Class[] {typeof(GOST28147WrapParameterSpec), typeof(PBEParameterSpec), typeof(RC2ParameterSpec), typeof(RC5ParameterSpec), typeof(IvParameterSpec)};

		protected internal int pbeType = PBE_Fields.PKCS12;
		protected internal int pbeHash = PBE_Fields.SHA1;
		protected internal int pbeKeySize;
		protected internal int pbeIvSize;

		protected internal AlgorithmParameters engineParams = null;

		protected internal Wrapper wrapEngine = null;

		private int ivSize;
		private byte[] iv;

		private ErasableOutputStream wrapStream = null;
		private bool forWrapping;

		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		public BaseWrapCipher()
		{
		}

		public BaseWrapCipher(Wrapper wrapEngine) : this(wrapEngine, 0)
		{
		}

		public BaseWrapCipher(Wrapper wrapEngine, int ivSize)
		{
			this.wrapEngine = wrapEngine;
			this.ivSize = ivSize;
		}

		public override int engineGetBlockSize()
		{
			return 0;
		}

		public override byte[] engineGetIV()
		{
			return Arrays.clone(iv);
		}

		public override int engineGetKeySize(Key key)
		{
			return key.getEncoded().length * 8;
		}

		public override int engineGetOutputSize(int inputLen)
		{
			return -1;
		}

		public override AlgorithmParameters engineGetParameters()
		{
			if (engineParams == null)
			{
				if (iv != null)
				{
					string name = wrapEngine.getAlgorithmName();

					if (name.IndexOf('/') >= 0)
					{
						name = name.Substring(0, name.IndexOf('/'));
					}

					try
					{
						engineParams = createParametersInstance(name);
						engineParams.init(new IvParameterSpec(iv));
					}
					catch (Exception e)
					{
						throw new RuntimeException(e.ToString());
					}
				}
			}

			return engineParams;
		}

		public AlgorithmParameters createParametersInstance(string algorithm)
		{
			return helper.createAlgorithmParameters(algorithm);
		}

		public override void engineSetMode(string mode)
		{
			throw new NoSuchAlgorithmException("can't support mode " + mode);
		}

		public override void engineSetPadding(string padding)
		{
			throw new NoSuchPaddingException("Padding " + padding + " unknown.");
		}

		public override void engineInit(int opmode, Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			CipherParameters param;

			if (key is BCPBEKey)
			{
				BCPBEKey k = (BCPBEKey)key;

				if (@params is PBEParameterSpec)
				{
					param = PBE_Util.makePBEParameters(k, @params, wrapEngine.getAlgorithmName());
				}
				else if (k.getParam() != null)
				{
					param = k.getParam();
				}
				else
				{
					throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
				}
			}
			else
			{
				param = new KeyParameter(key.getEncoded());
			}

			if (@params is IvParameterSpec)
			{
				IvParameterSpec ivSpec = (IvParameterSpec)@params;
				this.iv = ivSpec.getIV();
				param = new ParametersWithIV(param, iv);
			}

			if (@params is GOST28147WrapParameterSpec)
			{
				GOST28147WrapParameterSpec spec = (GOST28147WrapParameterSpec) @params;

				byte[] sBox = spec.getSBox();
				if (sBox != null)
				{
					param = new ParametersWithSBox(param, sBox);
				}
				param = new ParametersWithUKM(param, spec.getUKM());
			}

			if (param is KeyParameter && ivSize != 0)
			{
				if (opmode == Cipher.WRAP_MODE || opmode == Cipher.ENCRYPT_MODE)
				{
					iv = new byte[ivSize];
					random.nextBytes(iv);
					param = new ParametersWithIV(param, iv);
				}
			}

			if (random != null)
			{
				param = new ParametersWithRandom(param, random);
			}

			try
			{
				switch (opmode)
				{
				case Cipher.WRAP_MODE:
					wrapEngine.init(true, param);
					this.wrapStream = null;
					this.forWrapping = true;
					break;
				case Cipher.UNWRAP_MODE:
					wrapEngine.init(false, param);
					this.wrapStream = null;
					this.forWrapping = false;
					break;
				case Cipher.ENCRYPT_MODE:
					wrapEngine.init(true, param);
					this.wrapStream = new ErasableOutputStream();
					this.forWrapping = true;
					break;
				case Cipher.DECRYPT_MODE:
					wrapEngine.init(false, param);
					this.wrapStream = new ErasableOutputStream();
					this.forWrapping = false;
					break;
				default:
					throw new InvalidParameterException("Unknown mode parameter passed to init.");
				}
			}
			catch (Exception e)
			{
				throw new InvalidKeyOrParametersException(e.Message, e);
			}
		}

		public override void engineInit(int opmode, Key key, AlgorithmParameters @params, SecureRandom random)
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
						// try next spec
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

		public override void engineInit(int opmode, Key key, SecureRandom random)
		{
			try
			{
				engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				throw new InvalidKeyOrParametersException(e.Message, e);
			}
		}

		public override byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
		{
			if (wrapStream == null)
			{
				throw new IllegalStateException("not supported in a wrapping mode");
			}

			wrapStream.write(input, inputOffset, inputLen);

			return null;
		}

		public override int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			if (wrapStream == null)
			{
				throw new IllegalStateException("not supported in a wrapping mode");
			}

			wrapStream.write(input, inputOffset, inputLen);

			return 0;
		}

		public override byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
		{
			if (wrapStream == null)
			{
				throw new IllegalStateException("not supported in a wrapping mode");
			}

			wrapStream.write(input, inputOffset, inputLen);

			try
			{
				if (forWrapping)
				{
					try
					{
						return wrapEngine.wrap(wrapStream.getBuf(), 0, wrapStream.size());
					}
					catch (Exception e)
					{
						throw new IllegalBlockSizeException(e.Message);
					}
				}
				else
				{
					try
					{
						return wrapEngine.unwrap(wrapStream.getBuf(), 0, wrapStream.size());
					}
					catch (InvalidCipherTextException e)
					{
						throw new BadPaddingException(e.Message);
					}
				}
			}
			finally
			{
				wrapStream.erase();
			}
		}

		public override int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			if (wrapStream == null)
			{
				throw new IllegalStateException("not supported in a wrapping mode");
			}

			wrapStream.write(input, inputOffset, inputLen);

			try
			{
				byte[] enc;

				if (forWrapping)
				{
					try
					{
						enc = wrapEngine.wrap(wrapStream.getBuf(), 0, wrapStream.size());
					}
					catch (Exception e)
					{
						throw new IllegalBlockSizeException(e.Message);
					}
				}
				else
				{
					try
					{
						enc = wrapEngine.unwrap(wrapStream.getBuf(), 0, wrapStream.size());
					}
					catch (InvalidCipherTextException e)
					{
						throw new BadPaddingException(e.Message);
					}
				}

				if (outputOffset + enc.Length > output.Length)
				{
					throw new ShortBufferException("output buffer too short for input.");
				}

				JavaSystem.arraycopy(enc, 0, output, outputOffset, enc.Length);

				return enc.Length;
			}
			finally
			{
				wrapStream.erase();
			}
		}

		public override byte[] engineWrap(Key key)
		{
			byte[] encoded = key.getEncoded();
			if (encoded == null)
			{
				throw new InvalidKeyException("Cannot wrap key, null encoding.");
			}

			try
			{
				if (wrapEngine == null)
				{
					return engineDoFinal(encoded, 0, encoded.Length);
				}
				else
				{
					return wrapEngine.wrap(encoded, 0, encoded.Length);
				}
			}
			catch (BadPaddingException e)
			{
				throw new IllegalBlockSizeException(e.Message);
			}
		}

		public override Key engineUnwrap(byte[] wrappedKey, string wrappedKeyAlgorithm, int wrappedKeyType)
		{
			byte[] encoded;
			try
			{
				if (wrapEngine == null)
				{
					encoded = engineDoFinal(wrappedKey, 0, wrappedKey.Length);
				}
				else
				{
					encoded = wrapEngine.unwrap(wrappedKey, 0, wrappedKey.Length);
				}
			}
			catch (InvalidCipherTextException e)
			{
				throw new InvalidKeyException(e.Message);
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
			else if (wrappedKeyAlgorithm.Equals("") && wrappedKeyType == Cipher.PRIVATE_KEY)
			{
				/*
				 * The caller doesn't know the algorithm as it is part of
				 * the encrypted data.
				 */
				try
				{
					PrivateKeyInfo @in = PrivateKeyInfo.getInstance(encoded);

					PrivateKey privKey = BouncyCastleProvider.getPrivateKey(@in);

					if (privKey != null)
					{
						return privKey;
					}
					else
					{
						throw new InvalidKeyException("algorithm " + @in.getPrivateKeyAlgorithm().getAlgorithm() + " not supported");
					}
				}
				catch (Exception)
				{
					throw new InvalidKeyException("Invalid key encoding.");
				}
			}
			else
			{
				try
				{
					KeyFactory kf = helper.createKeyFactory(wrappedKeyAlgorithm);

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
				catch (InvalidKeySpecException e2)
				{
					throw new InvalidKeyException("Unknown key type " + e2.Message);
				}

				throw new InvalidKeyException("Unknown key type " + wrappedKeyType);
			}
		}

		public sealed class ErasableOutputStream : ByteArrayOutputStream
		{
			public ErasableOutputStream()
			{
			}

			public byte[] getBuf()
			{
				return buf;
			}

			public void erase()
			{
				Arrays.fill(this.buf, (byte)0);
				reset();
			}
		}

		public class InvalidKeyOrParametersException : InvalidKeyException
		{
			internal readonly Exception cause;

			public InvalidKeyOrParametersException(string msg, Exception cause) : base(msg)
			{
				this.cause = cause;
			}

			public virtual Exception getCause()
			{
				return cause;
			}
		}
	}

}