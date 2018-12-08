using System;

namespace org.bouncycastle.jcajce.provider.symmetric.util
{


	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using DataLengthException = org.bouncycastle.crypto.DataLengthException;
	using StreamCipher = org.bouncycastle.crypto.StreamCipher;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	public class BaseStreamCipher : BaseWrapCipher, PBE
	{
		//
		// specs we can handle.
		//
		private Class[] availableSpecs = new Class[] {typeof(RC2ParameterSpec), typeof(RC5ParameterSpec), typeof(IvParameterSpec), typeof(PBEParameterSpec)};

		private StreamCipher cipher;
		private int keySizeInBits;
		private int digest;
		private ParametersWithIV ivParam;

		private int ivLength = 0;

		private PBEParameterSpec pbeSpec = null;
		private string pbeAlgorithm = null;

		public BaseStreamCipher(StreamCipher engine, int ivLength) : this(engine, ivLength, -1, -1)
		{
		}

		public BaseStreamCipher(StreamCipher engine, int ivLength, int keySizeInBits, int digest)
		{
			cipher = engine;
			this.ivLength = ivLength;
			this.keySizeInBits = keySizeInBits;
			this.digest = digest;
		}

		public override int engineGetBlockSize()
		{
			return 0;
		}

		public override byte[] engineGetIV()
		{
			return (ivParam != null) ? ivParam.getIV() : null;
		}

		public override int engineGetKeySize(Key key)
		{
			return key.getEncoded().length * 8;
		}

		public override int engineGetOutputSize(int inputLen)
		{
			return inputLen;
		}

		public override AlgorithmParameters engineGetParameters()
		{
			if (engineParams == null)
			{
				if (pbeSpec != null)
				{
					try
					{
						AlgorithmParameters engineParams = createParametersInstance(pbeAlgorithm);
						engineParams.init(pbeSpec);

						return engineParams;
					}
					catch (Exception)
					{
						return null;
					}
				}
			}

			return engineParams;
		}

		/// <summary>
		/// should never be called.
		/// </summary>
		public override void engineSetMode(string mode)
		{
			if (!mode.Equals("ECB", StringComparison.OrdinalIgnoreCase))
			{
				throw new NoSuchAlgorithmException("can't support mode " + mode);
			}
		}

		/// <summary>
		/// should never be called.
		/// </summary>
		public override void engineSetPadding(string padding)
		{
			if (!padding.Equals("NoPadding", StringComparison.OrdinalIgnoreCase))
			{
				throw new NoSuchPaddingException("Padding " + padding + " unknown.");
			}
		}

		public override void engineInit(int opmode, Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			CipherParameters param;

			this.pbeSpec = null;
			this.pbeAlgorithm = null;

			this.engineParams = null;

			//
			// basic key check
			//
			if (!(key is SecretKey))
			{
				throw new InvalidKeyException("Key for algorithm " + key.getAlgorithm() + " not suitable for symmetric enryption.");
			}

			if (key is PKCS12Key)
			{
				PKCS12Key k = (PKCS12Key)key;
				pbeSpec = (PBEParameterSpec)@params;
				if (k is PKCS12KeyWithParameters && pbeSpec == null)
				{
					pbeSpec = new PBEParameterSpec(((PKCS12KeyWithParameters)k).getSalt(), ((PKCS12KeyWithParameters)k).getIterationCount());
				}

				param = PBE_Util.makePBEParameters(k.getEncoded(), PBE_Fields.PKCS12, digest, keySizeInBits, ivLength * 8, pbeSpec, cipher.getAlgorithmName());
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
					param = k.getParam();
					pbeSpec = new PBEParameterSpec(k.getSalt(), k.getIterationCount());
				}
				else if (@params is PBEParameterSpec)
				{
					param = PBE_Util.makePBEParameters(k, @params, cipher.getAlgorithmName());
					pbeSpec = (PBEParameterSpec)@params;
				}
				else
				{
					throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
				}

				if (k.getIvSize() != 0)
				{
					ivParam = (ParametersWithIV)param;
				}
			}
			else if (@params == null)
			{
				if (digest > 0)
				{
					throw new InvalidKeyException("Algorithm requires a PBE key");
				}
				param = new KeyParameter(key.getEncoded());
			}
			else if (@params is IvParameterSpec)
			{
				param = new ParametersWithIV(new KeyParameter(key.getEncoded()), ((IvParameterSpec)@params).getIV());
				ivParam = (ParametersWithIV)param;
			}
			else
			{
				throw new InvalidAlgorithmParameterException("unknown parameter type.");
			}

			if ((ivLength != 0) && !(param is ParametersWithIV))
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
				else
				{
					throw new InvalidAlgorithmParameterException("no IV set when one expected");
				}
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
			}
			catch (Exception e)
			{
				throw new InvalidKeyException(e.Message);
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
						continue;
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

		public override byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
		{
			byte[] @out = new byte[inputLen];

			cipher.processBytes(input, inputOffset, inputLen, @out, 0);

			return @out;
		}

		public override int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			if (outputOffset + inputLen > output.Length)
			{
				throw new ShortBufferException("output buffer too short for input.");
			}

			try
			{
				cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);

				return inputLen;
			}
			catch (DataLengthException e)
			{
				// should never happen
				throw new IllegalStateException(e.Message);
			}
		}

		public override byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
		{
			if (inputLen != 0)
			{
				byte[] @out = engineUpdate(input, inputOffset, inputLen);

				cipher.reset();

				return @out;
			}

			cipher.reset();

			return new byte[0];
		}

		public override int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			if (outputOffset + inputLen > output.Length)
			{
				throw new ShortBufferException("output buffer too short for input.");
			}

			if (inputLen != 0)
			{
				cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
			}

			cipher.reset();

			return inputLen;
		}
	}

}