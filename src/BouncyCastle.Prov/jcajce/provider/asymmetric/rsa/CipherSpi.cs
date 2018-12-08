using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{


	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using Digest = org.bouncycastle.crypto.Digest;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using ISO9796d1Encoding = org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
	using OAEPEncoding = org.bouncycastle.crypto.encodings.OAEPEncoding;
	using PKCS1Encoding = org.bouncycastle.crypto.encodings.PKCS1Encoding;
	using RSABlindedEngine = org.bouncycastle.crypto.engines.RSABlindedEngine;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using BaseCipherSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
	using BadBlockException = org.bouncycastle.jcajce.provider.util.BadBlockException;
	using DigestFactory = org.bouncycastle.jcajce.provider.util.DigestFactory;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using Strings = org.bouncycastle.util.Strings;

	public class CipherSpi : BaseCipherSpi
	{
		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		private AsymmetricBlockCipher cipher;
		private AlgorithmParameterSpec paramSpec;
		private new AlgorithmParameters engineParams;
		private bool publicKeyOnly = false;
		private bool privateKeyOnly = false;
		private ErasableOutputStream bOut = new ErasableOutputStream();

		public CipherSpi(AsymmetricBlockCipher engine)
		{
			cipher = engine;
		}

		public CipherSpi(OAEPParameterSpec pSpec)
		{
			try
			{
				initFromSpec(pSpec);
			}
			catch (NoSuchPaddingException e)
			{
				throw new IllegalArgumentException(e.Message);
			}
		}

		public CipherSpi(bool publicKeyOnly, bool privateKeyOnly, AsymmetricBlockCipher engine)
		{
			this.publicKeyOnly = publicKeyOnly;
			this.privateKeyOnly = privateKeyOnly;
			cipher = engine;
		}

		private void initFromSpec(OAEPParameterSpec pSpec)
		{
			MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)pSpec.getMGFParameters();
			Digest digest = DigestFactory.getDigest(mgfParams.getDigestAlgorithm());

			if (digest == null)
			{
				throw new NoSuchPaddingException("no match on OAEP constructor for digest algorithm: " + mgfParams.getDigestAlgorithm());
			}

			cipher = new OAEPEncoding(new RSABlindedEngine(), digest, ((PSource.PSpecified)pSpec.getPSource()).getValue());
			paramSpec = pSpec;
		}

		public override int engineGetBlockSize()
		{
			try
			{
				return cipher.getInputBlockSize();
			}
			catch (NullPointerException)
			{
				throw new IllegalStateException("RSA Cipher not initialised");
			}
		}

		public override int engineGetKeySize(Key key)
		{
			if (key is RSAPrivateKey)
			{
				RSAPrivateKey k = (RSAPrivateKey)key;

				return k.getModulus().bitLength();
			}
			else if (key is RSAPublicKey)
			{
				RSAPublicKey k = (RSAPublicKey)key;

				return k.getModulus().bitLength();
			}

			throw new IllegalArgumentException("not an RSA key!");
		}

		public override int engineGetOutputSize(int inputLen)
		{
			try
			{
				return cipher.getOutputBlockSize();
			}
			catch (NullPointerException)
			{
				throw new IllegalStateException("RSA Cipher not initialised");
			}
		}

		public override AlgorithmParameters engineGetParameters()
		{
			if (engineParams == null)
			{
				if (paramSpec != null)
				{
					try
					{
						engineParams = helper.createAlgorithmParameters("OAEP");
						engineParams.init(paramSpec);
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
			string md = Strings.toUpperCase(mode);

			if (md.Equals("NONE") || md.Equals("ECB"))
			{
				return;
			}

			if (md.Equals("1"))
			{
				privateKeyOnly = true;
				publicKeyOnly = false;
				return;
			}
			else if (md.Equals("2"))
			{
				privateKeyOnly = false;
				publicKeyOnly = true;
				return;
			}

			throw new NoSuchAlgorithmException("can't support mode " + mode);
		}

		public override void engineSetPadding(string padding)
		{
			string pad = Strings.toUpperCase(padding);

			if (pad.Equals("NOPADDING"))
			{
				cipher = new RSABlindedEngine();
			}
			else if (pad.Equals("PKCS1PADDING"))
			{
				cipher = new PKCS1Encoding(new RSABlindedEngine());
			}
			else if (pad.Equals("ISO9796-1PADDING"))
			{
				cipher = new ISO9796d1Encoding(new RSABlindedEngine());
			}
			else if (pad.Equals("OAEPWITHMD5ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("MD5", "MGF1", new MGF1ParameterSpec("MD5"), PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPPADDING"))
			{
				initFromSpec(OAEPParameterSpec.DEFAULT);
			}
			else if (pad.Equals("OAEPWITHSHA1ANDMGF1PADDING") || pad.Equals("OAEPWITHSHA-1ANDMGF1PADDING"))
			{
				initFromSpec(OAEPParameterSpec.DEFAULT);
			}
			else if (pad.Equals("OAEPWITHSHA224ANDMGF1PADDING") || pad.Equals("OAEPWITHSHA-224ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA256ANDMGF1PADDING") || pad.Equals("OAEPWITHSHA-256ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA384ANDMGF1PADDING") || pad.Equals("OAEPWITHSHA-384ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA512ANDMGF1PADDING") || pad.Equals("OAEPWITHSHA-512ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA3-224ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA3-224", "MGF1", new MGF1ParameterSpec("SHA3-224"), PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA3-256ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA3-256", "MGF1", new MGF1ParameterSpec("SHA3-256"), PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA3-384ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA3-384", "MGF1", new MGF1ParameterSpec("SHA3-384"), PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA3-512ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA3-512", "MGF1", new MGF1ParameterSpec("SHA3-512"), PSource.PSpecified.DEFAULT));
			}
			else
			{
				throw new NoSuchPaddingException(padding + " unavailable with RSA.");
			}
		}

		public override void engineInit(int opmode, Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			CipherParameters param;

			if (@params == null || @params is OAEPParameterSpec)
			{
				if (key is RSAPublicKey)
				{
					if (privateKeyOnly && opmode == Cipher.ENCRYPT_MODE)
					{
						throw new InvalidKeyException("mode 1 requires RSAPrivateKey");
					}

					param = RSAUtil.generatePublicKeyParameter((RSAPublicKey)key);
				}
				else if (key is RSAPrivateKey)
				{
					if (publicKeyOnly && opmode == Cipher.ENCRYPT_MODE)
					{
						throw new InvalidKeyException("mode 2 requires RSAPublicKey");
					}

					param = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)key);
				}
				else
				{
					throw new InvalidKeyException("unknown key type passed to RSA");
				}

				if (@params != null)
				{
					OAEPParameterSpec spec = (OAEPParameterSpec)@params;

					paramSpec = @params;

					if (!spec.getMGFAlgorithm().Equals("MGF1", StringComparison.OrdinalIgnoreCase) && !spec.getMGFAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_mgf1.getId()))
					{
						throw new InvalidAlgorithmParameterException("unknown mask generation function specified");
					}

					if (!(spec.getMGFParameters() is MGF1ParameterSpec))
					{
						throw new InvalidAlgorithmParameterException("unkown MGF parameters");
					}

					Digest digest = DigestFactory.getDigest(spec.getDigestAlgorithm());

					if (digest == null)
					{
						throw new InvalidAlgorithmParameterException("no match on digest algorithm: " + spec.getDigestAlgorithm());
					}

					MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)spec.getMGFParameters();
					Digest mgfDigest = DigestFactory.getDigest(mgfParams.getDigestAlgorithm());

					if (mgfDigest == null)
					{
						throw new InvalidAlgorithmParameterException("no match on MGF digest algorithm: " + mgfParams.getDigestAlgorithm());
					}

					cipher = new OAEPEncoding(new RSABlindedEngine(), digest, mgfDigest, ((PSource.PSpecified)spec.getPSource()).getValue());
				}
			}
			else
			{
				throw new InvalidAlgorithmParameterException("unknown parameter type: " + @params.GetType().getName());
			}

			if (!(cipher is RSABlindedEngine))
			{
				if (random != null)
				{
					param = new ParametersWithRandom(param, random);
				}
				else
				{
					param = new ParametersWithRandom(param, CryptoServicesRegistrar.getSecureRandom());
				}
			}

			bOut.reset();

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
				throw new InvalidParameterException("unknown opmode " + opmode + " passed to RSA");
			}
		}

		public override void engineInit(int opmode, Key key, AlgorithmParameters @params, SecureRandom random)
		{
			AlgorithmParameterSpec paramSpec = null;

			if (@params != null)
			{
				try
				{
					paramSpec = @params.getParameterSpec(typeof(OAEPParameterSpec));
				}
				catch (InvalidParameterSpecException e)
				{
					throw new InvalidAlgorithmParameterException("cannot recognise parameters: " + e.ToString(), e);
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
				// this shouldn't happen
				throw new InvalidKeyException("Eeeek! " + e.ToString(), e);
			}
		}

		public override byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
		{
			bOut.write(input, inputOffset, inputLen);

			if (cipher is RSABlindedEngine)
			{
				if (bOut.size() > cipher.getInputBlockSize() + 1)
				{
					throw new ArrayIndexOutOfBoundsException("too much data for RSA block");
				}
			}
			else
			{
				if (bOut.size() > cipher.getInputBlockSize())
				{
					throw new ArrayIndexOutOfBoundsException("too much data for RSA block");
				}
			}

			return null;
		}

		public override int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			bOut.write(input, inputOffset, inputLen);

			if (cipher is RSABlindedEngine)
			{
				if (bOut.size() > cipher.getInputBlockSize() + 1)
				{
					throw new ArrayIndexOutOfBoundsException("too much data for RSA block");
				}
			}
			else
			{
				if (bOut.size() > cipher.getInputBlockSize())
				{
					throw new ArrayIndexOutOfBoundsException("too much data for RSA block");
				}
			}

			return 0;
		}

		public override byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
		{
			if (input != null)
			{
				bOut.write(input, inputOffset, inputLen);
			}

			if (cipher is RSABlindedEngine)
			{
				if (bOut.size() > cipher.getInputBlockSize() + 1)
				{
					throw new ArrayIndexOutOfBoundsException("too much data for RSA block");
				}
			}
			else
			{
				if (bOut.size() > cipher.getInputBlockSize())
				{
					throw new ArrayIndexOutOfBoundsException("too much data for RSA block");
				}
			}

			return getOutput();
		}

		public override int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			if (outputOffset + engineGetOutputSize(inputLen) > output.Length)
			{
				throw new ShortBufferException("output buffer too short for input.");
			}

			if (input != null)
			{
				bOut.write(input, inputOffset, inputLen);
			}

			if (cipher is RSABlindedEngine)
			{
				if (bOut.size() > cipher.getInputBlockSize() + 1)
				{
					throw new ArrayIndexOutOfBoundsException("too much data for RSA block");
				}
			}
			else
			{
				if (bOut.size() > cipher.getInputBlockSize())
				{
					throw new ArrayIndexOutOfBoundsException("too much data for RSA block");
				}
			}

			byte[] @out = getOutput();

			for (int i = 0; i != @out.Length; i++)
			{
				output[outputOffset + i] = @out[i];
			}

			return @out.Length;
		}

		private byte[] getOutput()
		{
			try
			{
				return cipher.processBlock(bOut.getBuf(), 0, bOut.size());
			}
			catch (InvalidCipherTextException e)
			{
				throw new BadBlockException("unable to decrypt block", e);
			}
			catch (ArrayIndexOutOfBoundsException e)
			{
				throw new BadBlockException("unable to decrypt block", e);
			}
			finally
			{
				bOut.erase();
			}
		}

		/// <summary>
		/// classes that inherit from us.
		/// </summary>

		public class NoPadding : CipherSpi
		{
			public NoPadding() : base(new RSABlindedEngine())
			{
			}
		}

		public class PKCS1v1_5Padding : CipherSpi
		{
			public PKCS1v1_5Padding() : base(new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class PKCS1v1_5Padding_PrivateOnly : CipherSpi
		{
			public PKCS1v1_5Padding_PrivateOnly() : base(false, true, new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class PKCS1v1_5Padding_PublicOnly : CipherSpi
		{
			public PKCS1v1_5Padding_PublicOnly() : base(true, false, new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class OAEPPadding : CipherSpi
		{
			public OAEPPadding() : base(OAEPParameterSpec.DEFAULT)
			{
			}
		}

		public class ISO9796d1Padding : CipherSpi
		{
			public ISO9796d1Padding() : base(new ISO9796d1Encoding(new RSABlindedEngine()))
			{
			}
		}
	}

}