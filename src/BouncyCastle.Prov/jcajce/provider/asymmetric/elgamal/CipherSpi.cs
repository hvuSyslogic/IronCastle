using org.bouncycastle.asn1.pkcs;
using javax.crypto;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.elgamal
{


	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using ISO9796d1Encoding = org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
	using OAEPEncoding = org.bouncycastle.crypto.encodings.OAEPEncoding;
	using PKCS1Encoding = org.bouncycastle.crypto.encodings.PKCS1Encoding;
	using ElGamalEngine = org.bouncycastle.crypto.engines.ElGamalEngine;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using BaseCipherSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
	using BadBlockException = org.bouncycastle.jcajce.provider.util.BadBlockException;
	using DigestFactory = org.bouncycastle.jcajce.provider.util.DigestFactory;
	using ElGamalKey = org.bouncycastle.jce.interfaces.ElGamalKey;
	using Strings = org.bouncycastle.util.Strings;

	public class CipherSpi : BaseCipherSpi
	{
		private AsymmetricBlockCipher cipher;
		private AlgorithmParameterSpec paramSpec;
		private new AlgorithmParameters engineParams;
		private ErasableOutputStream bOut = new ErasableOutputStream();

		public CipherSpi(AsymmetricBlockCipher engine)
		{
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

			cipher = new OAEPEncoding(new ElGamalEngine(), digest, ((PSource.PSpecified)pSpec.getPSource()).getValue());
			paramSpec = pSpec;
		}

		public override int engineGetBlockSize()
		{
			return cipher.getInputBlockSize();
		}

		public override int engineGetKeySize(Key key)
		{
			if (key is ElGamalKey)
			{
				ElGamalKey k = (ElGamalKey)key;

				return k.getParameters().getP().bitLength();
			}
			else if (key is DHKey)
			{
				DHKey k = (DHKey)key;

				return k.getParams().getP().bitLength();
			}

			throw new IllegalArgumentException("not an ElGamal key!");
		}

		public override int engineGetOutputSize(int inputLen)
		{
			return cipher.getOutputBlockSize();
		}

		public override AlgorithmParameters engineGetParameters()
		{
			if (engineParams == null)
			{
				if (paramSpec != null)
				{
					try
					{
						engineParams = createParametersInstance("OAEP");
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

			throw new NoSuchAlgorithmException("can't support mode " + mode);
		}

		public override void engineSetPadding(string padding)
		{
			string pad = Strings.toUpperCase(padding);

			if (pad.Equals("NOPADDING"))
			{
				cipher = new ElGamalEngine();
			}
			else if (pad.Equals("PKCS1PADDING"))
			{
				cipher = new PKCS1Encoding(new ElGamalEngine());
			}
			else if (pad.Equals("ISO9796-1PADDING"))
			{
				cipher = new ISO9796d1Encoding(new ElGamalEngine());
			}
			else if (pad.Equals("OAEPPADDING"))
			{
				initFromSpec(OAEPParameterSpec.DEFAULT);
			}
			else if (pad.Equals("OAEPWITHMD5ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("MD5", "MGF1", new MGF1ParameterSpec("MD5"), PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA1ANDMGF1PADDING"))
			{
				initFromSpec(OAEPParameterSpec.DEFAULT);
			}
			else if (pad.Equals("OAEPWITHSHA224ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA256ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA384ANDMGF1PADDING"))
			{
				initFromSpec(new OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, PSource.PSpecified.DEFAULT));
			}
			else if (pad.Equals("OAEPWITHSHA512ANDMGF1PADDING"))
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
				throw new NoSuchPaddingException(padding + " unavailable with ElGamal.");
			}
		}

		public override void engineInit(int opmode, Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			CipherParameters param;

			if (key is DHPublicKey)
			{
				param = ElGamalUtil.generatePublicKeyParameter((PublicKey)key);
			}
			else if (key is DHPrivateKey)
			{
				param = ElGamalUtil.generatePrivateKeyParameter((PrivateKey)key);
			}
			else
			{
				throw new InvalidKeyException("unknown key type passed to ElGamal");
			}

			if (@params is OAEPParameterSpec)
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

				cipher = new OAEPEncoding(new ElGamalEngine(), digest, mgfDigest, ((PSource.PSpecified)spec.getPSource()).getValue());
			}
			else if (@params != null)
			{
				throw new InvalidAlgorithmParameterException("unknown parameter type.");
			}

			if (random != null)
			{
				param = new ParametersWithRandom(param, random);
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
				throw new InvalidParameterException("unknown opmode " + opmode + " passed to ElGamal");
			}
		}

		public override void engineInit(int opmode, Key key, AlgorithmParameters @params, SecureRandom random)
		{
			throw new InvalidAlgorithmParameterException("can't handle parameters in ElGamal");
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
			return null;
		}

		public override int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			bOut.write(input, inputOffset, inputLen);
			return 0;
		}


		public override byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
		{
			if (input != null)
			{
				bOut.write(input, inputOffset, inputLen);
			}

			if (cipher is ElGamalEngine)
			{
				if (bOut.size() > cipher.getInputBlockSize() + 1)
				{
					throw new ArrayIndexOutOfBoundsException("too much data for ElGamal block");
				}
			}
			else
			{
				if (bOut.size() > cipher.getInputBlockSize())
				{
					throw new ArrayIndexOutOfBoundsException("too much data for ElGamal block");
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

			if (cipher is ElGamalEngine)
			{
				if (bOut.size() > cipher.getInputBlockSize() + 1)
				{
					throw new ArrayIndexOutOfBoundsException("too much data for ElGamal block");
				}
			}
			else
			{
				if (bOut.size() > cipher.getInputBlockSize())
				{
					throw new ArrayIndexOutOfBoundsException("too much data for ElGamal block");
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
			public NoPadding() : base(new ElGamalEngine())
			{
			}
		}

		public class PKCS1v1_5Padding : CipherSpi
		{
			public PKCS1v1_5Padding() : base(new PKCS1Encoding(new ElGamalEngine()))
			{
			}
		}
	}

}