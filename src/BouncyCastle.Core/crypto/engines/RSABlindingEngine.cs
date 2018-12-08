using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.engines
{
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using RSABlindingParameters = org.bouncycastle.crypto.@params.RSABlindingParameters;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;

	/// <summary>
	/// This does your basic RSA Chaum's blinding and unblinding as outlined in
	/// "Handbook of Applied Cryptography", page 475. You need to use this if you are
	/// trying to get another party to generate signatures without them being aware
	/// of the message they are signing.
	/// </summary>
	public class RSABlindingEngine : AsymmetricBlockCipher
	{
		private RSACoreEngine core = new RSACoreEngine();

		private RSAKeyParameters key;
		private BigInteger blindingFactor;

		private bool forEncryption;

		/// <summary>
		/// Initialise the blinding engine.
		/// </summary>
		/// <param name="forEncryption"> true if we are encrypting (blinding), false otherwise. </param>
		/// <param name="param">         the necessary RSA key parameters. </param>
		public virtual void init(bool forEncryption, CipherParameters param)
		{
			RSABlindingParameters p;

			if (param is ParametersWithRandom)
			{
				ParametersWithRandom rParam = (ParametersWithRandom)param;

				p = (RSABlindingParameters)rParam.getParameters();
			}
			else
			{
				p = (RSABlindingParameters)param;
			}

			core.init(forEncryption, p.getPublicKey());

			this.forEncryption = forEncryption;
			this.key = p.getPublicKey();
			this.blindingFactor = p.getBlindingFactor();
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
		/// Process a single block using the RSA blinding algorithm.
		/// </summary>
		/// <param name="in">    the input array. </param>
		/// <param name="inOff"> the offset into the input buffer where the data starts. </param>
		/// <param name="inLen"> the length of the data to be processed. </param>
		/// <returns> the result of the RSA process. </returns>
		/// <exception cref="DataLengthException"> the input block is too large. </exception>
		public virtual byte[] processBlock(byte[] @in, int inOff, int inLen)
		{
			BigInteger msg = core.convertInput(@in, inOff, inLen);

			if (forEncryption)
			{
				msg = blindMessage(msg);
			}
			else
			{
				msg = unblindMessage(msg);
			}

			return core.convertOutput(msg);
		}

		/*
		 * Blind message with the blind factor.
		 */
		private BigInteger blindMessage(BigInteger msg)
		{
			BigInteger blindMsg = blindingFactor;
			blindMsg = msg.multiply(blindMsg.modPow(key.getExponent(), key.getModulus()));
			blindMsg = blindMsg.mod(key.getModulus());

			return blindMsg;
		}

		/*
		 * Unblind the message blinded with the blind factor.
		 */
		private BigInteger unblindMessage(BigInteger blindedMsg)
		{
			BigInteger m = key.getModulus();
			BigInteger msg = blindedMsg;
			BigInteger blindFactorInverse = blindingFactor.modInverse(m);
			msg = msg.multiply(blindFactorInverse);
			msg = msg.mod(m);

			return msg;
		}
	}

}