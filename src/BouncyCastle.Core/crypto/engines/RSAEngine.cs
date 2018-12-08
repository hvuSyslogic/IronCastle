using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.engines
{

	/// <summary>
	/// this does your basic RSA algorithm.
	/// </summary>
	public class RSAEngine : AsymmetricBlockCipher
	{
		private RSACoreEngine core;

		/// <summary>
		/// initialise the RSA engine.
		/// </summary>
		/// <param name="forEncryption"> true if we are encrypting, false otherwise. </param>
		/// <param name="param"> the necessary RSA key parameters. </param>
		public virtual void init(bool forEncryption, CipherParameters param)
		{
			if (core == null)
			{
				core = new RSACoreEngine();
			}

			core.init(forEncryption, param);
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
			if (core == null)
			{
				throw new IllegalStateException("RSA engine not initialised");
			}

			return core.convertOutput(core.processBlock(core.convertInput(@in, inOff, inLen)));
		}
	}

}