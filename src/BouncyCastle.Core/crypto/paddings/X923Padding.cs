using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.paddings
{

	/// <summary>
	/// A padder that adds X9.23 padding to a block - if a SecureRandom is
	/// passed in random padding is assumed, otherwise padding with zeros is used.
	/// </summary>
	public class X923Padding : BlockCipherPadding
	{
		internal SecureRandom random = null;

		/// <summary>
		/// Initialise the padder.
		/// </summary>
		/// <param name="random"> a SecureRandom if one is available. </param>
		public virtual void init(SecureRandom random)
		{
			this.random = random;
		}

		/// <summary>
		/// Return the name of the algorithm the padder implements.
		/// </summary>
		/// <returns> the name of the algorithm the padder implements. </returns>
		public virtual string getPaddingName()
		{
			return "X9.23";
		}

		/// <summary>
		/// add the pad bytes to the passed in block, returning the
		/// number of bytes added.
		/// </summary>
		public virtual int addPadding(byte[] @in, int inOff)
		{
			byte code = (byte)(@in.Length - inOff);

			while (inOff < @in.Length - 1)
			{
				if (random == null)
				{
					@in[inOff] = 0;
				}
				else
				{
					@in[inOff] = (byte)random.nextInt();
				}
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