using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.util
{


	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using Wrapper = org.bouncycastle.crypto.Wrapper;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Arrays = org.bouncycastle.util.Arrays;

	public abstract class BaseCipherSpi : CipherSpi
	{
		//
		// specs we can handle.
		//
		private Class[] availableSpecs = new Class[] {typeof(IvParameterSpec), typeof(PBEParameterSpec), typeof(RC2ParameterSpec), typeof(RC5ParameterSpec)};

		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		protected internal AlgorithmParameters engineParams = null;

		protected internal Wrapper wrapEngine = null;

		private int ivSize;
		private byte[] iv;

		public BaseCipherSpi()
		{
		}

		public override int engineGetBlockSize()
		{
			return 0;
		}

		public override byte[] engineGetIV()
		{
			return null;
		}

		public override int engineGetKeySize(Key key)
		{
			return key.getEncoded().length;
		}

		public override int engineGetOutputSize(int inputLen)
		{
			return -1;
		}

		public override AlgorithmParameters engineGetParameters()
		{
			return null;
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
//JAVA TO C# CONVERTER WARNING: 'final' catch parameters are not available in C#:
//ORIGINAL LINE: catch (final javax.crypto.BadPaddingException e)
			catch (BadPaddingException e)
			{
				throw new InvalidKeyExceptionAnonymousInnerClass(this, e);
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
				catch (NoSuchAlgorithmException e)
				{
					throw new InvalidKeyException("Unknown key type " + e.Message);
				}
				catch (InvalidKeySpecException e)
				{
					throw new InvalidKeyException("Unknown key type " + e.Message);
				}
				catch (NoSuchProviderException e)
				{
					throw new InvalidKeyException("Unknown key type " + e.Message);
				}

				throw new InvalidKeyException("Unknown key type " + wrappedKeyType);
			}
		}

		public class InvalidKeyExceptionAnonymousInnerClass : InvalidKeyException
		{
			private readonly BaseCipherSpi outerInstance;

			private InvalidCipherTextException e;

			public InvalidKeyExceptionAnonymousInnerClass(BaseCipherSpi outerInstance, InvalidCipherTextException e) : base("unable to unwrap")
			{
				this.outerInstance = outerInstance;
				this.e = e;
			}

			public Exception getCause()
			{
				lock (this)
				{
					return e;
				}
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
	}

}