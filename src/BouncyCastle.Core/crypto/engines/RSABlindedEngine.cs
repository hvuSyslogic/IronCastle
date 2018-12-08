using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.engines
{

	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// this does your basic RSA algorithm with blinding
	/// </summary>
	public class RSABlindedEngine : AsymmetricBlockCipher
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private RSACoreEngine core = new RSACoreEngine();
		private RSAKeyParameters key;
		private SecureRandom random;

		/// <summary>
		/// initialise the RSA engine.
		/// </summary>
		/// <param name="forEncryption"> true if we are encrypting, false otherwise. </param>
		/// <param name="param"> the necessary RSA key parameters. </param>
		public virtual void init(bool forEncryption, CipherParameters param)
		{
			core.init(forEncryption, param);

			if (param is ParametersWithRandom)
			{
				ParametersWithRandom rParam = (ParametersWithRandom)param;

				key = (RSAKeyParameters)rParam.getParameters();
				random = rParam.getRandom();
			}
			else
			{
				key = (RSAKeyParameters)param;
				random = CryptoServicesRegistrar.getSecureRandom();
			}
		}

		/// <summary>
		/// Return the maximum size for an input block to this engine.
		/// For RSA this is always one byte less than the key size on
		/// encryption, and the same length as the key size on decryption.
		/// </summary>
		/// <returns> maximum size for an input block. </returns>
		public virtual int getInputBlockSize()
		{
			return core.getInputBlockSize();
		}

		/// <summary>
		/// Return the maximum size for an output block to this engine.
		/// For RSA this is always one byte less than the key size on
		/// decryption, and the same length as the key size on encryption.
		/// </summary>
		/// <returns> maximum size for an output block. </returns>
		public virtual int getOutputBlockSize()
		{
			return core.getOutputBlockSize();
		}

		/// <summary>
		/// Process a single block using the basic RSA algorithm.
		/// </summary>
		/// <param name="in"> the input array. </param>
		/// <param name="inOff"> the offset into the input buffer where the data starts. </param>
		/// <param name="inLen"> the length of the data to be processed. </param>
		/// <returns> the result of the RSA process. </returns>
		/// <exception cref="DataLengthException"> the input block is too large. </exception>
		public virtual byte[] processBlock(byte[] @in, int inOff, int inLen)
		{
			if (key == null)
			{
				throw new IllegalStateException("RSA engine not initialised");
			}

			BigInteger input = core.convertInput(@in, inOff, inLen);

			BigInteger result;
			if (key is RSAPrivateCrtKeyParameters)
			{
				RSAPrivateCrtKeyParameters k = (RSAPrivateCrtKeyParameters)key;

				BigInteger e = k.getPublicExponent();
				if (e != null) // can't do blinding without a public exponent
				{
					BigInteger m = k.getModulus();
					BigInteger r = BigIntegers.createRandomInRange(ONE, m.subtract(ONE), random);

					BigInteger blindedInput = r.modPow(e, m).multiply(input).mod(m);
					BigInteger blindedResult = core.processBlock(blindedInput);

					BigInteger rInv = r.modInverse(m);
					result = blindedResult.multiply(rInv).mod(m);
					// defence against Arjen Lenstra’s CRT attack
					if (!input.Equals(result.modPow(e, m)))
					{
						throw new IllegalStateException("RSA engine faulty decryption/signing detected");
					}
				}
				else
				{
					result = core.processBlock(input);
				}
			}
			else
			{
				result = core.processBlock(input);
			}

			return core.convertOutput(result);
		}
	}

}