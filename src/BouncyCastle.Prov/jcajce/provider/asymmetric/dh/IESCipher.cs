using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dh
{


	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using KeyEncoder = org.bouncycastle.crypto.KeyEncoder;
	using DHBasicAgreement = org.bouncycastle.crypto.agreement.DHBasicAgreement;
	using AESEngine = org.bouncycastle.crypto.engines.AESEngine;
	using DESedeEngine = org.bouncycastle.crypto.engines.DESedeEngine;
	using IESEngine = org.bouncycastle.crypto.engines.IESEngine;
	using DHKeyPairGenerator = org.bouncycastle.crypto.generators.DHKeyPairGenerator;
	using EphemeralKeyPairGenerator = org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
	using KDF2BytesGenerator = org.bouncycastle.crypto.generators.KDF2BytesGenerator;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DHKeyGenerationParameters = org.bouncycastle.crypto.@params.DHKeyGenerationParameters;
	using DHKeyParameters = org.bouncycastle.crypto.@params.DHKeyParameters;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;
	using IESWithCipherParameters = org.bouncycastle.crypto.@params.IESWithCipherParameters;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using DHIESPublicKeyParser = org.bouncycastle.crypto.parsers.DHIESPublicKeyParser;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using DHUtil = org.bouncycastle.jcajce.provider.asymmetric.util.DHUtil;
	using IESUtil = org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil;
	using BadBlockException = org.bouncycastle.jcajce.provider.util.BadBlockException;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using IESKey = org.bouncycastle.jce.interfaces.IESKey;
	using IESParameterSpec = org.bouncycastle.jce.spec.IESParameterSpec;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using Strings = org.bouncycastle.util.Strings;


	public class IESCipher : CipherSpi
	{
		private readonly JcaJceHelper helper = new BCJcaJceHelper();
		private readonly int ivLength;

		private IESEngine engine;
		private int state = -1;
		private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		private AlgorithmParameters engineParam = null;
		private IESParameterSpec engineSpec = null;
		private AsymmetricKeyParameter key;
		private SecureRandom random;
		private bool dhaesMode = false;
		private AsymmetricKeyParameter otherKeyParameter = null;

		public IESCipher(IESEngine engine)
		{
			this.engine = engine;
			this.ivLength = 0;
		}

		public IESCipher(IESEngine engine, int ivLength)
		{
			this.engine = engine;
			this.ivLength = ivLength;
		}

		public override int engineGetBlockSize()
		{
			if (engine.getCipher() != null)
			{
				return engine.getCipher().getBlockSize();
			}
			else
			{
				return 0;
			}
		}


		public override int engineGetKeySize(Key key)
		{
			if (key is DHKey)
			{
				return ((DHKey)key).getParams().getP().bitLength();
			}
			else
			{
				throw new IllegalArgumentException("not a DH key");
			}
		}


		public override byte[] engineGetIV()
		{
			if (engineSpec != null)
			{
				return engineSpec.getNonce();
			}
			return null;
		}

		public override AlgorithmParameters engineGetParameters()
		{
			if (engineParam == null && engineSpec != null)
			{
				try
				{
					engineParam = helper.createAlgorithmParameters("IES");
					engineParam.init(engineSpec);
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.ToString());
				}
			}

			return engineParam;
		}


		public override void engineSetMode(string mode)
		{
			string modeName = Strings.toUpperCase(mode);

			if (modeName.Equals("NONE"))
			{
				dhaesMode = false;
			}
			else if (modeName.Equals("DHAES"))
			{
				dhaesMode = true;
			}
			else
			{
				throw new IllegalArgumentException("can't support mode " + mode);
			}
		}

		public override int engineGetOutputSize(int inputLen)
		{
			int len1, len2, len3;

			if (key == null)
			{
				throw new IllegalStateException("cipher not initialised");
			}

			len1 = engine.getMac().getMacSize();

			if (otherKeyParameter == null)
			{
				len2 = 1 + 2 * (((DHKeyParameters)key).getParameters().getP().bitLength() + 7) / 8;
			}
			else
			{
				len2 = 0;
			}

			if (engine.getCipher() == null)
			{
				len3 = inputLen;
			}
			else if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
			{
				len3 = engine.getCipher().getOutputSize(inputLen);
			}
			else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
			{
				len3 = engine.getCipher().getOutputSize(inputLen - len1 - len2);
			}
			else
			{
				throw new IllegalStateException("cipher not initialised");
			}

			if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
			{
				return buffer.size() + len1 + len2 + len3;
			}
			else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
			{
				return buffer.size() - len1 - len2 + len3;
			}
			else
			{
				throw new IllegalStateException("IESCipher not initialised");
			}

		}

		public override void engineSetPadding(string padding)
		{
			string paddingName = Strings.toUpperCase(padding);

			// TDOD: make this meaningful...
			if (paddingName.Equals("NOPADDING"))
			{

			}
			else if (paddingName.Equals("PKCS5PADDING") || paddingName.Equals("PKCS7PADDING"))
			{

			}
			else
			{
				throw new NoSuchPaddingException("padding not available with IESCipher");
			}
		}

		// Initialisation methods

		public override void engineInit(int opmode, Key key, AlgorithmParameters @params, SecureRandom random)
		{
			AlgorithmParameterSpec paramSpec = null;

			if (@params != null)
			{
				try
				{
					paramSpec = @params.getParameterSpec(typeof(IESParameterSpec));
				}
				catch (Exception e)
				{
					throw new InvalidAlgorithmParameterException("cannot recognise parameters: " + e.ToString());
				}
			}

			engineParam = @params;
			engineInit(opmode, key, paramSpec, random);
		}


		public override void engineInit(int opmode, Key key, AlgorithmParameterSpec engineSpec, SecureRandom random)
		{
			// Use default parameters (including cipher key size) if none are specified
			if (engineSpec == null)
			{
				byte[] nonce = null;
				if (ivLength != 0 && opmode == Cipher.ENCRYPT_MODE)
				{
					nonce = new byte[ivLength];
					random.nextBytes(nonce);
				}
				this.engineSpec = IESUtil.guessParameterSpec(engine.getCipher(), nonce);
			}
			else if (engineSpec is IESParameterSpec)
			{
				this.engineSpec = (IESParameterSpec)engineSpec;
			}
			else
			{
				throw new InvalidAlgorithmParameterException("must be passed IES parameters");
			}

			byte[] nonce = this.engineSpec.getNonce();

			if (ivLength != 0 && (nonce == null || nonce.Length != ivLength))
			{
				throw new InvalidAlgorithmParameterException("NONCE in IES Parameters needs to be " + ivLength + " bytes long");
			}

			// Parse the recipient's key
			if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE)
			{
				if (key is DHPublicKey)
				{
					this.key = DHUtil.generatePublicKeyParameter((PublicKey)key);
				}
				else if (key is IESKey)
				{
					IESKey ieKey = (IESKey)key;

					this.key = DHUtil.generatePublicKeyParameter(ieKey.getPublic());
					this.otherKeyParameter = DHUtil.generatePrivateKeyParameter(ieKey.getPrivate());
				}
				else
				{
					throw new InvalidKeyException("must be passed recipient's public DH key for encryption");
				}
			}
			else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE)
			{
				if (key is DHPrivateKey)
				{
					this.key = DHUtil.generatePrivateKeyParameter((PrivateKey)key);
				}
				else if (key is IESKey)
				{
					IESKey ieKey = (IESKey)key;

					this.otherKeyParameter = DHUtil.generatePublicKeyParameter(ieKey.getPublic());
					this.key = DHUtil.generatePrivateKeyParameter(ieKey.getPrivate());
				}
				else
				{
					throw new InvalidKeyException("must be passed recipient's private DH key for decryption");
				}
			}
			else
			{
				throw new InvalidKeyException("must be passed EC key");
			}

			this.random = random;
			this.state = opmode;
			buffer.reset();

		}


		public override void engineInit(int opmode, Key key, SecureRandom random)
		{
			try
			{
				engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				throw new IllegalArgumentException("cannot handle supplied parameter spec: " + e.Message);
			}

		}


		// Update methods - buffer the input

		public override byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
		{
			buffer.write(input, inputOffset, inputLen);
			return null;
		}


		public override int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			buffer.write(input, inputOffset, inputLen);
			return 0;
		}


		// Finalisation methods

		public override byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
		{
			if (inputLen != 0)
			{
				buffer.write(input, inputOffset, inputLen);
			}

			byte[] @in = buffer.toByteArray();
			buffer.reset();

			// Convert parameters for use in IESEngine
			CipherParameters @params = new IESWithCipherParameters(engineSpec.getDerivationV(), engineSpec.getEncodingV(), engineSpec.getMacKeySize(), engineSpec.getCipherKeySize());

			if (engineSpec.getNonce() != null)
			{
				@params = new ParametersWithIV(@params, engineSpec.getNonce());
			}

			DHParameters dhParams = ((DHKeyParameters)key).getParameters();

			byte[] V;
			if (otherKeyParameter != null)
			{
				try
				{
					if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
					{
						engine.init(true, otherKeyParameter, key, @params);
					}
					else
					{
						engine.init(false, key, otherKeyParameter, @params);
					}
					return engine.processBlock(@in, 0, @in.Length);
				}
				catch (Exception e)
				{
					throw new BadBlockException("unable to process block", e);
				}
			}

			if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
			{
				// Generate the ephemeral key pair
				DHKeyPairGenerator gen = new DHKeyPairGenerator();
				gen.init(new DHKeyGenerationParameters(random, dhParams));

				EphemeralKeyPairGenerator kGen = new EphemeralKeyPairGenerator(gen, new KeyEncoderAnonymousInnerClass(this));

				// Encrypt the buffer
				try
				{
					engine.init(key, @params, kGen);

					return engine.processBlock(@in, 0, @in.Length);
				}
				catch (Exception e)
				{
					throw new BadBlockException("unable to process block", e);
				}
			}
			else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
			{
				// Decrypt the buffer
				try
				{
					engine.init(key, @params, new DHIESPublicKeyParser(((DHKeyParameters)key).getParameters()));

					return engine.processBlock(@in, 0, @in.Length);
				}
				catch (InvalidCipherTextException e)
				{
					throw new BadBlockException("unable to process block", e);
				}
			}
			else
			{
				throw new IllegalStateException("IESCipher not initialised");
			}

		}

		public class KeyEncoderAnonymousInnerClass : KeyEncoder
		{
			private readonly IESCipher outerInstance;

			public KeyEncoderAnonymousInnerClass(IESCipher outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public byte[] getEncoded(AsymmetricKeyParameter keyParameter)
			{
				byte[] Vloc = new byte[(((DHKeyParameters)keyParameter).getParameters().getP().bitLength() + 7) / 8];
				byte[] Vtmp = BigIntegers.asUnsignedByteArray(((DHPublicKeyParameters)keyParameter).getY());

				if (Vtmp.Length > Vloc.Length)
				{
					throw new IllegalArgumentException("Senders's public key longer than expected.");
				}
				else
				{
					JavaSystem.arraycopy(Vtmp, 0, Vloc, Vloc.Length - Vtmp.Length, Vtmp.Length);
				}

				return Vloc;
			}
		}


		public override int engineDoFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
		{

			byte[] buf = engineDoFinal(input, inputOffset, inputLength);
			JavaSystem.arraycopy(buf, 0, output, outputOffset, buf.Length);
			return buf.Length;

		}

		/// <summary>
		/// Classes that inherit from us
		/// </summary>

		public class IES : IESCipher
		{
			public IES() : base(new IESEngine(new DHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()), new HMac(DigestFactory.createSHA1())))
			{
			}
		}

		public class IESwithDESedeCBC : IESCipher
		{
			public IESwithDESedeCBC() : base(new IESEngine(new DHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()), new HMac(DigestFactory.createSHA1()), new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()))), 8)
			{
			}
		}

		public class IESwithAESCBC : IESCipher
		{
			public IESwithAESCBC() : base(new IESEngine(new DHBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()), new HMac(DigestFactory.createSHA1()), new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()))), 16)
			{
			}
		}
	}

}