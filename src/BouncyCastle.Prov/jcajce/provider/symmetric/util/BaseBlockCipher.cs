using System;

namespace org.bouncycastle.jcajce.provider.symmetric.util
{


	using GCMParameters = org.bouncycastle.asn1.cms.GCMParameters;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using DataLengthException = org.bouncycastle.crypto.DataLengthException;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using OutputLengthException = org.bouncycastle.crypto.OutputLengthException;
	using DSTU7624Engine = org.bouncycastle.crypto.engines.DSTU7624Engine;
	using AEADBlockCipher = org.bouncycastle.crypto.modes.AEADBlockCipher;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using CCMBlockCipher = org.bouncycastle.crypto.modes.CCMBlockCipher;
	using CFBBlockCipher = org.bouncycastle.crypto.modes.CFBBlockCipher;
	using CTSBlockCipher = org.bouncycastle.crypto.modes.CTSBlockCipher;
	using EAXBlockCipher = org.bouncycastle.crypto.modes.EAXBlockCipher;
	using GCFBBlockCipher = org.bouncycastle.crypto.modes.GCFBBlockCipher;
	using GCMBlockCipher = org.bouncycastle.crypto.modes.GCMBlockCipher;
	using GOFBBlockCipher = org.bouncycastle.crypto.modes.GOFBBlockCipher;
	using KCCMBlockCipher = org.bouncycastle.crypto.modes.KCCMBlockCipher;
	using KCTRBlockCipher = org.bouncycastle.crypto.modes.KCTRBlockCipher;
	using KGCMBlockCipher = org.bouncycastle.crypto.modes.KGCMBlockCipher;
	using OCBBlockCipher = org.bouncycastle.crypto.modes.OCBBlockCipher;
	using OFBBlockCipher = org.bouncycastle.crypto.modes.OFBBlockCipher;
	using OpenPGPCFBBlockCipher = org.bouncycastle.crypto.modes.OpenPGPCFBBlockCipher;
	using PGPCFBBlockCipher = org.bouncycastle.crypto.modes.PGPCFBBlockCipher;
	using SICBlockCipher = org.bouncycastle.crypto.modes.SICBlockCipher;
	using BlockCipherPadding = org.bouncycastle.crypto.paddings.BlockCipherPadding;
	using ISO10126d2Padding = org.bouncycastle.crypto.paddings.ISO10126d2Padding;
	using ISO7816d4Padding = org.bouncycastle.crypto.paddings.ISO7816d4Padding;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using TBCPadding = org.bouncycastle.crypto.paddings.TBCPadding;
	using X923Padding = org.bouncycastle.crypto.paddings.X923Padding;
	using ZeroBytePadding = org.bouncycastle.crypto.paddings.ZeroBytePadding;
	using AEADParameters = org.bouncycastle.crypto.@params.AEADParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ParametersWithSBox = org.bouncycastle.crypto.@params.ParametersWithSBox;
	using RC2Parameters = org.bouncycastle.crypto.@params.RC2Parameters;
	using RC5Parameters = org.bouncycastle.crypto.@params.RC5Parameters;
	using AEADParameterSpec = org.bouncycastle.jcajce.spec.AEADParameterSpec;
	using GOST28147ParameterSpec = org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
	using RepeatedSecretKeySpec = org.bouncycastle.jcajce.spec.RepeatedSecretKeySpec;
	using Strings = org.bouncycastle.util.Strings;

	public class BaseBlockCipher : BaseWrapCipher, PBE
	{
		private static readonly Class gcmSpecClass = ClassUtil.loadClass(typeof(BaseBlockCipher), "javax.crypto.spec.GCMParameterSpec");

		//
		// specs we can handle.
		//
		private Class[] availableSpecs = new Class[] {typeof(RC2ParameterSpec), typeof(RC5ParameterSpec), gcmSpecClass, typeof(GOST28147ParameterSpec), typeof(IvParameterSpec), typeof(PBEParameterSpec)};

		private BlockCipher baseEngine;
		private BlockCipherProvider engineProvider;
		private GenericBlockCipher cipher;
		private ParametersWithIV ivParam;
		private AEADParameters aeadParams;

		private int keySizeInBits;
		private int scheme = -1;
		private int digest;

		private int ivLength = 0;

		private bool padded;
		private bool fixedIv = true;
		private PBEParameterSpec pbeSpec = null;
		private string pbeAlgorithm = null;

		private string modeName = null;

		public BaseBlockCipher(BlockCipher engine)
		{
			baseEngine = engine;

			cipher = new BufferedGenericBlockCipher(engine);
		}

		public BaseBlockCipher(BlockCipher engine, int scheme, int digest, int keySizeInBits, int ivLength)
		{
			baseEngine = engine;

			this.scheme = scheme;
			this.digest = digest;
			this.keySizeInBits = keySizeInBits;
			this.ivLength = ivLength;

			cipher = new BufferedGenericBlockCipher(engine);
		}

		public BaseBlockCipher(BlockCipherProvider provider)
		{
			baseEngine = provider.get();
			engineProvider = provider;

			cipher = new BufferedGenericBlockCipher(provider.get());
		}

		public BaseBlockCipher(AEADBlockCipher engine)
		{
			this.baseEngine = engine.getUnderlyingCipher();
			this.ivLength = baseEngine.getBlockSize();
			this.cipher = new AEADGenericBlockCipher(engine);
		}

		public BaseBlockCipher(AEADBlockCipher engine, bool fixedIv, int ivLength)
		{
			this.baseEngine = engine.getUnderlyingCipher();
			this.fixedIv = fixedIv;
			this.ivLength = ivLength;
			this.cipher = new AEADGenericBlockCipher(engine);
		}

		public BaseBlockCipher(BlockCipher engine, int ivLength) : this(engine, true, ivLength)
		{
		}

		public BaseBlockCipher(BlockCipher engine, bool fixedIv, int ivLength)
		{
			baseEngine = engine;

			this.fixedIv = fixedIv;
			this.cipher = new BufferedGenericBlockCipher(engine);
			this.ivLength = ivLength / 8;
		}

		public BaseBlockCipher(BufferedBlockCipher engine, int ivLength) : this(engine, true, ivLength)
		{
		}

		public BaseBlockCipher(BufferedBlockCipher engine, bool fixedIv, int ivLength)
		{
			baseEngine = engine.getUnderlyingCipher();

			this.cipher = new BufferedGenericBlockCipher(engine);
			this.fixedIv = fixedIv;
			this.ivLength = ivLength / 8;
		}

		public override int engineGetBlockSize()
		{
			return baseEngine.getBlockSize();
		}

		public override byte[] engineGetIV()
		{
			if (aeadParams != null)
			{
				return aeadParams.getNonce();
			}

			return (ivParam != null) ? ivParam.getIV() : null;
		}

		public override int engineGetKeySize(Key key)
		{
			return key.getEncoded().length * 8;
		}

		public override int engineGetOutputSize(int inputLen)
		{
			return cipher.getOutputSize(inputLen);
		}

		public override AlgorithmParameters engineGetParameters()
		{
			if (engineParams == null)
			{
				if (pbeSpec != null)
				{
					try
					{
						engineParams = createParametersInstance(pbeAlgorithm);
						engineParams.init(pbeSpec);
					}
					catch (Exception)
					{
						return null;
					}
				}
				else if (aeadParams != null)
				{
					try
					{
						engineParams = createParametersInstance("GCM");
						engineParams.init((new GCMParameters(aeadParams.getNonce(), aeadParams.getMacSize() / 8)).getEncoded());
					}
					catch (Exception e)
					{
						throw new RuntimeException(e.ToString());
					}
				}
				else if (ivParam != null)
				{
					string name = cipher.getUnderlyingCipher().getAlgorithmName();

					if (name.IndexOf('/') >= 0)
					{
						name = name.Substring(0, name.IndexOf('/'));
					}

					try
					{
						engineParams = createParametersInstance(name);
						engineParams.init(new IvParameterSpec(ivParam.getIV()));
					}
					catch (Exception e)
					{
						throw new RuntimeException(e.ToString());
					}
				}
			}

			return engineParams;
		}

		public override void engineSetMode(string mode)
		{
			modeName = Strings.toUpperCase(mode);

			if (modeName.Equals("ECB"))
			{
				ivLength = 0;
				cipher = new BufferedGenericBlockCipher(baseEngine);
			}
			else if (modeName.Equals("CBC"))
			{
				ivLength = baseEngine.getBlockSize();
				cipher = new BufferedGenericBlockCipher(new CBCBlockCipher(baseEngine));
			}
			else if (modeName.StartsWith("OFB", StringComparison.Ordinal))
			{
				ivLength = baseEngine.getBlockSize();
				if (modeName.Length != 3)
				{
					int wordSize = int.Parse(modeName.Substring(3));

					cipher = new BufferedGenericBlockCipher(new OFBBlockCipher(baseEngine, wordSize));
				}
				else
				{
					cipher = new BufferedGenericBlockCipher(new OFBBlockCipher(baseEngine, 8 * baseEngine.getBlockSize()));
				}
			}
			else if (modeName.StartsWith("CFB", StringComparison.Ordinal))
			{
				ivLength = baseEngine.getBlockSize();
				if (modeName.Length != 3)
				{
					int wordSize = int.Parse(modeName.Substring(3));

					cipher = new BufferedGenericBlockCipher(new CFBBlockCipher(baseEngine, wordSize));
				}
				else
				{
					cipher = new BufferedGenericBlockCipher(new CFBBlockCipher(baseEngine, 8 * baseEngine.getBlockSize()));
				}
			}
			else if (modeName.StartsWith("PGP", StringComparison.Ordinal))
			{
				bool inlineIV = modeName.Equals("PGPCFBwithIV", StringComparison.OrdinalIgnoreCase);

				ivLength = baseEngine.getBlockSize();
				cipher = new BufferedGenericBlockCipher(new PGPCFBBlockCipher(baseEngine, inlineIV));
			}
			else if (modeName.Equals("OpenPGPCFB", StringComparison.OrdinalIgnoreCase))
			{
				ivLength = 0;
				cipher = new BufferedGenericBlockCipher(new OpenPGPCFBBlockCipher(baseEngine));
			}
			else if (modeName.StartsWith("SIC", StringComparison.Ordinal))
			{
				ivLength = baseEngine.getBlockSize();
				if (ivLength < 16)
				{
					throw new IllegalArgumentException("Warning: SIC-Mode can become a twotime-pad if the blocksize of the cipher is too small. Use a cipher with a block size of at least 128 bits (e.g. AES)");
				}
				fixedIv = false;
				cipher = new BufferedGenericBlockCipher(new BufferedBlockCipher(new SICBlockCipher(baseEngine)));
			}
			else if (modeName.StartsWith("CTR", StringComparison.Ordinal))
			{
				ivLength = baseEngine.getBlockSize();
				fixedIv = false;
				if (baseEngine is DSTU7624Engine)
				{
					cipher = new BufferedGenericBlockCipher(new BufferedBlockCipher(new KCTRBlockCipher(baseEngine)));
				}
				else
				{
					cipher = new BufferedGenericBlockCipher(new BufferedBlockCipher(new SICBlockCipher(baseEngine)));
				}
			}
			else if (modeName.StartsWith("GOFB", StringComparison.Ordinal))
			{
				ivLength = baseEngine.getBlockSize();
				cipher = new BufferedGenericBlockCipher(new BufferedBlockCipher(new GOFBBlockCipher(baseEngine)));
			}
			else if (modeName.StartsWith("GCFB", StringComparison.Ordinal))
			{
				ivLength = baseEngine.getBlockSize();
				cipher = new BufferedGenericBlockCipher(new BufferedBlockCipher(new GCFBBlockCipher(baseEngine)));
			}
			else if (modeName.StartsWith("CTS", StringComparison.Ordinal))
			{
				ivLength = baseEngine.getBlockSize();
				cipher = new BufferedGenericBlockCipher(new CTSBlockCipher(new CBCBlockCipher(baseEngine)));
			}
			else if (modeName.StartsWith("CCM", StringComparison.Ordinal))
			{
				ivLength = 12; // CCM nonce 7..13 bytes
				if (baseEngine is DSTU7624Engine)
				{
					cipher = new AEADGenericBlockCipher(new KCCMBlockCipher(baseEngine));
				}
				else
				{
					cipher = new AEADGenericBlockCipher(new CCMBlockCipher(baseEngine));
				}
			}
			else if (modeName.StartsWith("OCB", StringComparison.Ordinal))
			{
				if (engineProvider != null)
				{
					/*
					 * RFC 7253 4.2. Nonce is a string of no more than 120 bits
					 */
					ivLength = 15;
					cipher = new AEADGenericBlockCipher(new OCBBlockCipher(baseEngine, engineProvider.get()));
				}
				else
				{
					throw new NoSuchAlgorithmException("can't support mode " + mode);
				}
			}
			else if (modeName.StartsWith("EAX", StringComparison.Ordinal))
			{
				ivLength = baseEngine.getBlockSize();
				cipher = new AEADGenericBlockCipher(new EAXBlockCipher(baseEngine));
			}
			else if (modeName.StartsWith("GCM", StringComparison.Ordinal))
			{
				ivLength = baseEngine.getBlockSize();
				if (baseEngine is DSTU7624Engine)
				{
					cipher = new AEADGenericBlockCipher(new KGCMBlockCipher(baseEngine));
				}
				else
				{
					cipher = new AEADGenericBlockCipher(new GCMBlockCipher(baseEngine));
				}
			}
			else
			{
				throw new NoSuchAlgorithmException("can't support mode " + mode);
			}
		}

		public override void engineSetPadding(string padding)
		{
			string paddingName = Strings.toUpperCase(padding);

			if (paddingName.Equals("NOPADDING"))
			{
				if (cipher.wrapOnNoPadding())
				{
					cipher = new BufferedGenericBlockCipher(new BufferedBlockCipher(cipher.getUnderlyingCipher()));
				}
			}
			else if (paddingName.Equals("WITHCTS") || paddingName.Equals("CTSPADDING") || paddingName.Equals("CS3PADDING"))
			{
				cipher = new BufferedGenericBlockCipher(new CTSBlockCipher(cipher.getUnderlyingCipher()));
			}
			else
			{
				padded = true;

				if (isAEADModeName(modeName))
				{
					throw new NoSuchPaddingException("Only NoPadding can be used with AEAD modes.");
				}
				else if (paddingName.Equals("PKCS5PADDING") || paddingName.Equals("PKCS7PADDING"))
				{
					cipher = new BufferedGenericBlockCipher(cipher.getUnderlyingCipher());
				}
				else if (paddingName.Equals("ZEROBYTEPADDING"))
				{
					cipher = new BufferedGenericBlockCipher(cipher.getUnderlyingCipher(), new ZeroBytePadding());
				}
				else if (paddingName.Equals("ISO10126PADDING") || paddingName.Equals("ISO10126-2PADDING"))
				{
					cipher = new BufferedGenericBlockCipher(cipher.getUnderlyingCipher(), new ISO10126d2Padding());
				}
				else if (paddingName.Equals("X9.23PADDING") || paddingName.Equals("X923PADDING"))
				{
					cipher = new BufferedGenericBlockCipher(cipher.getUnderlyingCipher(), new X923Padding());
				}
				else if (paddingName.Equals("ISO7816-4PADDING") || paddingName.Equals("ISO9797-1PADDING"))
				{
					cipher = new BufferedGenericBlockCipher(cipher.getUnderlyingCipher(), new ISO7816d4Padding());
				}
				else if (paddingName.Equals("TBCPADDING"))
				{
					cipher = new BufferedGenericBlockCipher(cipher.getUnderlyingCipher(), new TBCPadding());
				}
				else
				{
					throw new NoSuchPaddingException("Padding " + padding + " unknown.");
				}
			}
		}

		public override void engineInit(int opmode, Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			CipherParameters param;

			this.pbeSpec = null;
			this.pbeAlgorithm = null;
			this.engineParams = null;
			this.aeadParams = null;

			//
			// basic key check
			//
			if (!(key is SecretKey))
			{
				throw new InvalidKeyException("Key for algorithm " + ((key != null) ? key.getAlgorithm() : null) + " not suitable for symmetric enryption.");
			}

			//
			// for RC5-64 we must have some default parameters
			//
			if (@params == null && baseEngine.getAlgorithmName().StartsWith("RC5-64", StringComparison.Ordinal))
			{
				throw new InvalidAlgorithmParameterException("RC5 requires an RC5ParametersSpec to be passed in.");
			}

			//
			// a note on iv's - if ivLength is zero the IV gets ignored (we don't use it).
			//
			if (scheme == PBE_Fields.PKCS12 || key is PKCS12Key)
			{
				SecretKey k;
				try
				{
					k = (SecretKey)key;
				}
				catch (Exception)
				{
					throw new InvalidKeyException("PKCS12 requires a SecretKey/PBEKey");
				}

				if (@params is PBEParameterSpec)
				{
					pbeSpec = (PBEParameterSpec)@params;
				}

				if (k is PBEKey && pbeSpec == null)
				{
					PBEKey pbeKey = (PBEKey)k;
					if (pbeKey.getSalt() == null)
					{
						throw new InvalidAlgorithmParameterException("PBEKey requires parameters to specify salt");
					}
					pbeSpec = new PBEParameterSpec(pbeKey.getSalt(), pbeKey.getIterationCount());
				}

				if (pbeSpec == null && !(k is PBEKey))
				{
					throw new InvalidKeyException("Algorithm requires a PBE key");
				}

				if (key is BCPBEKey)
				{
					// PKCS#12 sets an IV, if we get a key that doesn't have ParametersWithIV we need to reject it. If the
					// key has no parameters it means it's an old-school JCE PBE Key - we use getEncoded() on it.
					CipherParameters pbeKeyParam = ((BCPBEKey)key).getParam();
					if (pbeKeyParam is ParametersWithIV)
					{
						param = pbeKeyParam;
					}
					else if (pbeKeyParam == null)
					{
						param = PBE_Util.makePBEParameters(k.getEncoded(), PBE_Fields.PKCS12, digest, keySizeInBits, ivLength * 8, pbeSpec, cipher.getAlgorithmName());
					}
					else
					{
						throw new InvalidKeyException("Algorithm requires a PBE key suitable for PKCS12");
					}
				}
				else
				{
					param = PBE_Util.makePBEParameters(k.getEncoded(), PBE_Fields.PKCS12, digest, keySizeInBits, ivLength * 8, pbeSpec, cipher.getAlgorithmName());
				}
				if (param is ParametersWithIV)
				{
					ivParam = (ParametersWithIV)param;
				}
			}
			else if (key is PBKDF1Key)
			{
				PBKDF1Key k = (PBKDF1Key)key;

				if (@params is PBEParameterSpec)
				{
					pbeSpec = (PBEParameterSpec)@params;
				}
				if (k is PBKDF1KeyWithParameters && pbeSpec == null)
				{
					pbeSpec = new PBEParameterSpec(((PBKDF1KeyWithParameters)k).getSalt(), ((PBKDF1KeyWithParameters)k).getIterationCount());
				}

				param = PBE_Util.makePBEParameters(k.getEncoded(), PBE_Fields.PKCS5S1, digest, keySizeInBits, ivLength * 8, pbeSpec, cipher.getAlgorithmName());
				if (param is ParametersWithIV)
				{
					ivParam = (ParametersWithIV)param;
				}
			}
			else if (key is BCPBEKey)
			{
				BCPBEKey k = (BCPBEKey)key;

				if (k.getOID() != null)
				{
					pbeAlgorithm = k.getOID().getId();
				}
				else
				{
					pbeAlgorithm = k.getAlgorithm();
				}

				if (k.getParam() != null)
				{
					param = adjustParameters(@params, k.getParam());
				}
				else if (@params is PBEParameterSpec)
				{
					pbeSpec = (PBEParameterSpec)@params;
					param = PBE_Util.makePBEParameters(k, @params, cipher.getUnderlyingCipher().getAlgorithmName());
				}
				else
				{
					throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
				}

				if (param is ParametersWithIV)
				{
					ivParam = (ParametersWithIV)param;
				}
			}
			else if (key is PBEKey)
			{
				PBEKey k = (PBEKey)key;
				pbeSpec = (PBEParameterSpec)@params;
				if (k is PKCS12KeyWithParameters && pbeSpec == null)
				{
					pbeSpec = new PBEParameterSpec(k.getSalt(), k.getIterationCount());
				}

				param = PBE_Util.makePBEParameters(k.getEncoded(), scheme, digest, keySizeInBits, ivLength * 8, pbeSpec, cipher.getAlgorithmName());
				if (param is ParametersWithIV)
				{
					ivParam = (ParametersWithIV)param;
				}
			}
			else if (!(key is RepeatedSecretKeySpec))
			{
				if (scheme == PBE_Fields.PKCS5S1 || scheme == PBE_Fields.PKCS5S1_UTF8 || scheme == PBE_Fields.PKCS5S2 || scheme == PBE_Fields.PKCS5S2_UTF8)
				{
					throw new InvalidKeyException("Algorithm requires a PBE key");
				}
				param = new KeyParameter(key.getEncoded());
			}
			else
			{
				param = null;
			}

			if (@params is AEADParameterSpec)
			{
				if (!isAEADModeName(modeName) && !(cipher is AEADGenericBlockCipher))
				{
					throw new InvalidAlgorithmParameterException("AEADParameterSpec can only be used with AEAD modes.");
				}

				AEADParameterSpec aeadSpec = (AEADParameterSpec)@params;

				KeyParameter keyParam;
				if (param is ParametersWithIV)
				{
					keyParam = (KeyParameter)((ParametersWithIV)param).getParameters();
				}
				else
				{
					keyParam = (KeyParameter)param;
				}
				param = aeadParams = new AEADParameters(keyParam, aeadSpec.getMacSizeInBits(), aeadSpec.getNonce(), aeadSpec.getAssociatedData());
			}
			else if (@params is IvParameterSpec)
			{
				if (ivLength != 0)
				{
					IvParameterSpec p = (IvParameterSpec)@params;

					if (p.getIV().Length != ivLength && !(cipher is AEADGenericBlockCipher) && fixedIv)
					{
						throw new InvalidAlgorithmParameterException("IV must be " + ivLength + " bytes long.");
					}

					if (param is ParametersWithIV)
					{
						param = new ParametersWithIV(((ParametersWithIV)param).getParameters(), p.getIV());
					}
					else
					{
						param = new ParametersWithIV(param, p.getIV());
					}
					ivParam = (ParametersWithIV)param;
				}
				else
				{
					if (!string.ReferenceEquals(modeName, null) && modeName.Equals("ECB"))
					{
						throw new InvalidAlgorithmParameterException("ECB mode does not use an IV");
					}
				}
			}
			else if (@params is GOST28147ParameterSpec)
			{
				GOST28147ParameterSpec gost28147Param = (GOST28147ParameterSpec)@params;

				param = new ParametersWithSBox(new KeyParameter(key.getEncoded()), ((GOST28147ParameterSpec)@params).getSbox());

				if (gost28147Param.getIV() != null && ivLength != 0)
				{
					if (param is ParametersWithIV)
					{
						param = new ParametersWithIV(((ParametersWithIV)param).getParameters(), gost28147Param.getIV());
					}
					else
					{
						param = new ParametersWithIV(param, gost28147Param.getIV());
					}
					ivParam = (ParametersWithIV)param;
				}
			}
			else if (@params is RC2ParameterSpec)
			{
				RC2ParameterSpec rc2Param = (RC2ParameterSpec)@params;

				param = new RC2Parameters(key.getEncoded(), ((RC2ParameterSpec)@params).getEffectiveKeyBits());

				if (rc2Param.getIV() != null && ivLength != 0)
				{
					if (param is ParametersWithIV)
					{
						param = new ParametersWithIV(((ParametersWithIV)param).getParameters(), rc2Param.getIV());
					}
					else
					{
						param = new ParametersWithIV(param, rc2Param.getIV());
					}
					ivParam = (ParametersWithIV)param;
				}
			}
			else if (@params is RC5ParameterSpec)
			{
				RC5ParameterSpec rc5Param = (RC5ParameterSpec)@params;

				param = new RC5Parameters(key.getEncoded(), ((RC5ParameterSpec)@params).getRounds());
				if (baseEngine.getAlgorithmName().StartsWith("RC5", StringComparison.Ordinal))
				{
					if (baseEngine.getAlgorithmName().Equals("RC5-32"))
					{
						if (rc5Param.getWordSize() != 32)
						{
							throw new InvalidAlgorithmParameterException("RC5 already set up for a word size of 32 not " + rc5Param.getWordSize() + ".");
						}
					}
					else if (baseEngine.getAlgorithmName().Equals("RC5-64"))
					{
						if (rc5Param.getWordSize() != 64)
						{
							throw new InvalidAlgorithmParameterException("RC5 already set up for a word size of 64 not " + rc5Param.getWordSize() + ".");
						}
					}
				}
				else
				{
					throw new InvalidAlgorithmParameterException("RC5 parameters passed to a cipher that is not RC5.");
				}
				if ((rc5Param.getIV() != null) && (ivLength != 0))
				{
					if (param is ParametersWithIV)
					{
						param = new ParametersWithIV(((ParametersWithIV)param).getParameters(), rc5Param.getIV());
					}
					else
					{
						param = new ParametersWithIV(param, rc5Param.getIV());
					}
					ivParam = (ParametersWithIV)param;
				}
			}
			else if (gcmSpecClass != null && gcmSpecClass.isInstance(@params))
			{
				if (!isAEADModeName(modeName) && !(cipher is AEADGenericBlockCipher))
				{
					throw new InvalidAlgorithmParameterException("GCMParameterSpec can only be used with AEAD modes.");
				}

				try
				{
					Method tLen = gcmSpecClass.getDeclaredMethod("getTLen", new Class[0]);
					Method iv = gcmSpecClass.getDeclaredMethod("getIV", new Class[0]);

					KeyParameter keyParam;
					if (param is ParametersWithIV)
					{
						keyParam = (KeyParameter)((ParametersWithIV)param).getParameters();
					}
					else
					{
						keyParam = (KeyParameter)param;
					}
					param = aeadParams = new AEADParameters(keyParam, ((int?)tLen.invoke(@params, new object[0])).Value, (byte[])iv.invoke(@params, new object[0]));
				}
				catch (Exception)
				{
					throw new InvalidAlgorithmParameterException("Cannot process GCMParameterSpec.");
				}
			}
			else if (@params != null && !(@params is PBEParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("unknown parameter type.");
			}

			if ((ivLength != 0) && !(param is ParametersWithIV) && !(param is AEADParameters))
			{
				SecureRandom ivRandom = random;

				if (ivRandom == null)
				{
					ivRandom = CryptoServicesRegistrar.getSecureRandom();
				}

				if ((opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE))
				{
					byte[] iv = new byte[ivLength];

					ivRandom.nextBytes(iv);
					param = new ParametersWithIV(param, iv);
					ivParam = (ParametersWithIV)param;
				}
				else if (cipher.getUnderlyingCipher().getAlgorithmName().IndexOf("PGPCFB", StringComparison.Ordinal) < 0)
				{
					throw new InvalidAlgorithmParameterException("no IV set when one expected");
				}
			}



			if (random != null && padded)
			{
				param = new ParametersWithRandom(param, random);
			}

			try
			{
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
					throw new InvalidParameterException("unknown opmode " + opmode + " passed");
				}

				if (cipher is AEADGenericBlockCipher && aeadParams == null)
				{
					AEADBlockCipher aeadCipher = ((AEADGenericBlockCipher)cipher).cipher;

					aeadParams = new AEADParameters((KeyParameter)ivParam.getParameters(), aeadCipher.getMac().Length * 8, ivParam.getIV());
				}
			}
//JAVA TO C# CONVERTER WARNING: 'final' catch parameters are not available in C#:
//ORIGINAL LINE: catch (final Exception e)
			catch (Exception e)
			{
				throw new InvalidKeyOrParametersException(e.getMessage(), e);
			}
		}

		private CipherParameters adjustParameters(AlgorithmParameterSpec @params, CipherParameters param)
		{
			CipherParameters key;

			if (param is ParametersWithIV)
			{
				key = ((ParametersWithIV)param).getParameters();
				if (@params is IvParameterSpec)
				{
					IvParameterSpec iv = (IvParameterSpec)@params;

					ivParam = new ParametersWithIV(key, iv.getIV());
					param = ivParam;
				}
				else if (@params is GOST28147ParameterSpec)
				{
					// need to pick up IV and SBox.
					GOST28147ParameterSpec gost28147Param = (GOST28147ParameterSpec)@params;

					param = new ParametersWithSBox(param, gost28147Param.getSbox());

					if (gost28147Param.getIV() != null && ivLength != 0)
					{
						ivParam = new ParametersWithIV(key, gost28147Param.getIV());
						param = ivParam;
					}
				}
			}
			else
			{
				if (@params is IvParameterSpec)
				{
					IvParameterSpec iv = (IvParameterSpec)@params;

					ivParam = new ParametersWithIV(param, iv.getIV());
					param = ivParam;
				}
				else if (@params is GOST28147ParameterSpec)
				{
					// need to pick up IV and SBox.
					GOST28147ParameterSpec gost28147Param = (GOST28147ParameterSpec)@params;

					param = new ParametersWithSBox(param, gost28147Param.getSbox());

					if (gost28147Param.getIV() != null && ivLength != 0)
					{
						param = new ParametersWithIV(param, gost28147Param.getIV());
					}
				}
			}
			return param;
		}

		public override void engineInit(int opmode, Key key, AlgorithmParameters @params, SecureRandom random)
		{
			AlgorithmParameterSpec paramSpec = null;

			if (@params != null)
			{
				for (int i = 0; i != availableSpecs.Length; i++)
				{
					if (availableSpecs[i] == null)
					{
						continue;
					}

					try
					{
						paramSpec = @params.getParameterSpec(availableSpecs[i]);
						break;
					}
					catch (Exception)
					{
						// try again if possible
					}
				}

				if (paramSpec == null)
				{
					throw new InvalidAlgorithmParameterException("can't handle parameter " + @params.ToString());
				}
			}

			engineInit(opmode, key, paramSpec, random);

			engineParams = @params;
		}

		public override void engineInit(int opmode, Key key, SecureRandom random)
		{
			try
			{
				engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				throw new InvalidKeyException(e.Message);
			}
		}

		public virtual void engineUpdateAAD(byte[] input, int offset, int length)
		{
			cipher.updateAAD(input, offset, length);
		}

		public virtual void engineUpdateAAD(ByteBuffer bytebuffer)
		{
			int offset = bytebuffer.arrayOffset() + bytebuffer.position();
			int length = bytebuffer.limit() - bytebuffer.position();
			engineUpdateAAD(bytebuffer.array(), offset, length);
		}

		public override byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
		{
			int length = cipher.getUpdateOutputSize(inputLen);

			if (length > 0)
			{
					byte[] @out = new byte[length];

					int len = cipher.processBytes(input, inputOffset, inputLen, @out, 0);

					if (len == 0)
					{
						return null;
					}
					else if (len != @out.Length)
					{
						byte[] tmp = new byte[len];

						JavaSystem.arraycopy(@out, 0, tmp, 0, len);

						return tmp;
					}

					return @out;
			}

			cipher.processBytes(input, inputOffset, inputLen, null, 0);

			return null;
		}

		public override int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			if (outputOffset + cipher.getUpdateOutputSize(inputLen) > output.Length)
			{
				throw new ShortBufferException("output buffer too short for input.");
			}

			try
			{
				return cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
			}
			catch (DataLengthException e)
			{
				// should never occur
				throw new IllegalStateException(e.ToString());
			}
		}

		public override byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
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

			if (len == tmp.Length)
			{
				return tmp;
			}

			byte[] @out = new byte[len];

			JavaSystem.arraycopy(tmp, 0, @out, 0, len);

			return @out;
		}

		public override int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			int len = 0;

			if (outputOffset + engineGetOutputSize(inputLen) > output.Length)
			{
				throw new ShortBufferException("output buffer too short for input.");
			}

			try
			{
				if (inputLen != 0)
				{
					len = cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
				}

				return (len + cipher.doFinal(output, outputOffset + len));
			}
			catch (OutputLengthException e)
			{
				throw new IllegalBlockSizeException(e.Message);
			}
			catch (DataLengthException e)
			{
				throw new IllegalBlockSizeException(e.Message);
			}
		}

		private bool isAEADModeName(string modeName)
		{
			return "CCM".Equals(modeName) || "EAX".Equals(modeName) || "GCM".Equals(modeName) || "OCB".Equals(modeName);
		}

		/*
		 * The ciphers that inherit from us.
		 */

		public interface GenericBlockCipher
		{
			void init(bool forEncryption, CipherParameters @params);

			bool wrapOnNoPadding();

			string getAlgorithmName();

			BlockCipher getUnderlyingCipher();

			int getOutputSize(int len);

			int getUpdateOutputSize(int len);

			void updateAAD(byte[] input, int offset, int length);

			int processByte(byte @in, byte[] @out, int outOff);

			int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff);

			int doFinal(byte[] @out, int outOff);
		}

		public class BufferedGenericBlockCipher : GenericBlockCipher
		{
			internal BufferedBlockCipher cipher;

			public BufferedGenericBlockCipher(BufferedBlockCipher cipher)
			{
				this.cipher = cipher;
			}

			public BufferedGenericBlockCipher(BlockCipher cipher)
			{
				this.cipher = new PaddedBufferedBlockCipher(cipher);
			}

			public BufferedGenericBlockCipher(BlockCipher cipher, BlockCipherPadding padding)
			{
				this.cipher = new PaddedBufferedBlockCipher(cipher, padding);
			}

			public virtual void init(bool forEncryption, CipherParameters @params)
			{
				cipher.init(forEncryption, @params);
			}

			public virtual bool wrapOnNoPadding()
			{
				return !(cipher is CTSBlockCipher);
			}

			public virtual string getAlgorithmName()
			{
				return cipher.getUnderlyingCipher().getAlgorithmName();
			}

			public virtual BlockCipher getUnderlyingCipher()
			{
				return cipher.getUnderlyingCipher();
			}

			public virtual int getOutputSize(int len)
			{
				return cipher.getOutputSize(len);
			}

			public virtual int getUpdateOutputSize(int len)
			{
				return cipher.getUpdateOutputSize(len);
			}

			public virtual void updateAAD(byte[] input, int offset, int length)
			{
				throw new UnsupportedOperationException("AAD is not supported in the current mode.");
			}

			public virtual int processByte(byte @in, byte[] @out, int outOff)
			{
				return cipher.processByte(@in, @out, outOff);
			}

			public virtual int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff)
			{
				return cipher.processBytes(@in, inOff, len, @out, outOff);
			}

			public virtual int doFinal(byte[] @out, int outOff)
			{
				try
				{
					return cipher.doFinal(@out, outOff);
				}
				catch (InvalidCipherTextException e)
				{
					throw new BadPaddingException(e.Message);
				}
			}
		}

		public class AEADGenericBlockCipher : GenericBlockCipher
		{
			internal static readonly Constructor aeadBadTagConstructor;

			static AEADGenericBlockCipher()
			{
				Class aeadBadTagClass = ClassUtil.loadClass(typeof(BaseBlockCipher), "javax.crypto.AEADBadTagException");
				if (aeadBadTagClass != null)
				{
					aeadBadTagConstructor = findExceptionConstructor(aeadBadTagClass);
				}
				else
				{
					aeadBadTagConstructor = null;
				}
			}

			internal static Constructor findExceptionConstructor(Class clazz)
			{
				try
				{
					return clazz.getConstructor(new Class[]{typeof(string)});
				}
				catch (Exception)
				{
					return null;
				}
			}

			internal AEADBlockCipher cipher;

			public AEADGenericBlockCipher(AEADBlockCipher cipher)
			{
				this.cipher = cipher;
			}

			public virtual void init(bool forEncryption, CipherParameters @params)
			{
				cipher.init(forEncryption, @params);
			}

			public virtual string getAlgorithmName()
			{
				return cipher.getUnderlyingCipher().getAlgorithmName();
			}

			public virtual bool wrapOnNoPadding()
			{
				return false;
			}

			public virtual BlockCipher getUnderlyingCipher()
			{
				return cipher.getUnderlyingCipher();
			}

			public virtual int getOutputSize(int len)
			{
				return cipher.getOutputSize(len);
			}

			public virtual int getUpdateOutputSize(int len)
			{
				return cipher.getUpdateOutputSize(len);
			}

			public virtual void updateAAD(byte[] input, int offset, int length)
			{
				cipher.processAADBytes(input, offset, length);
			}

			public virtual int processByte(byte @in, byte[] @out, int outOff)
			{
				return cipher.processByte(@in, @out, outOff);
			}

			public virtual int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff)
			{
				return cipher.processBytes(@in, inOff, len, @out, outOff);
			}

			public virtual int doFinal(byte[] @out, int outOff)
			{
				try
				{
					return cipher.doFinal(@out, outOff);
				}
				catch (InvalidCipherTextException e)
				{
					if (aeadBadTagConstructor != null)
					{
						BadPaddingException aeadBadTag = null;
						try
						{
							aeadBadTag = (BadPaddingException)aeadBadTagConstructor.newInstance(new object[]{e.Message});
						}
						catch (Exception)
						{
							// Shouldn't happen, but fall through to BadPaddingException
						}
						if (aeadBadTag != null)
						{
							throw aeadBadTag;
						}
					}
					throw new BadPaddingException(e.Message);
				}
			}
		}
	}

}