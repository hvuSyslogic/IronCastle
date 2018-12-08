using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.paddings
{


	/// <summary>
	/// A padder that adds ISO10126-2 padding to a block.
	/// </summary>
	public class ISO10126d2Padding : BlockCipherPadding
	{
		internal SecureRandom random;

		/// <summary>
		/// Initialise the padder.
		/// </summary>
		/// <param name="random"> a SecureRandom if available. </param>
		public virtual void init(SecureRandom random)
		{
			if (random != null)
			{
				this.random = random;
			}
			else
			{
				this.random = CryptoServicesRegistrar.getSecureRandom();
			}
		}

		/// <summary>
		/// Return the name of the algorithm the padder implements.
		/// </summary>
		/// <returns> the name of the algorithm the padder implements. </returns>
		public virtual string getPaddingName()
		{
			return "ISO10126-2";
		}

		/// <summary>
		/// add the pad bytes to the passed in block, returning the
		/// number of bytes added.
		/// </summary>
		public virtual int addPadding(byte[] @in, int inOff)
		{
			byte code = (byte)(@in.Length - inOff);

			while (inOff < (@in.Length - 1))
			{
				@in[inOff] = (byte)random.nextInt();
				inOff++;
			}

			@in[inOff] = code;

			return code;
		}

		/// <summary>
		/// return the number of pad bytes present in the block.
		/// </summary>
		public virtual int padCount(byte[] @in)
		{
			int count = @in[@in.Length - 1] & 0xff;

			if (count > @in.Length)
			{
				throw new InvalidCipherTextException("pad block corrupted");
			}

			return count;
		}
	}

}