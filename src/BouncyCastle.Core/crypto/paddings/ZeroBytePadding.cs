using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.paddings
{

	/// <summary>
	/// A padder that adds NULL byte padding to a block.
	/// </summary>
	public class ZeroBytePadding : BlockCipherPadding
	{
		/// <summary>
		/// Initialise the padder.
		/// </summary>
		/// <param name="random"> - a SecureRandom if available. </param>
		public virtual void init(SecureRandom random)
		{
			// nothing to do.
		}

		/// <summary>
		/// Return the name of the algorithm the padder implements.
		/// </summary>
		/// <returns> the name of the algorithm the padder implements. </returns>
		public virtual string getPaddingName()
		{
			return "ZeroByte";
		}

		/// <summary>
		/// add the pad bytes to the passed in block, returning the
		/// number of bytes added.
		/// </summary>
		public virtual int addPadding(byte[] @in, int inOff)
		{
			int added = (@in.Length - inOff);

			while (inOff < @in.Length)
			{
				@in[inOff] = (byte) 0;
				inOff++;
			}

			return added;
		}

		/// <summary>
		/// return the number of pad bytes present in the block.
		/// </summary>
		public virtual int padCount(byte[] @in)
		{
			int count = @in.Length;

			while (count > 0)
			{
				if (@in[count - 1] != 0)
				{
					break;
				}

				count--;
			}

			return @in.Length - count;
		}
	}

}