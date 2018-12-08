using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.paddings
{

	/// <summary>
	/// A padder that adds the padding according to the scheme referenced in
	/// ISO 7814-4 - scheme 2 from ISO 9797-1. The first byte is 0x80, rest is 0x00
	/// </summary>
	public class ISO7816d4Padding : BlockCipherPadding
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
			return "ISO7816-4";
		}

		/// <summary>
		/// add the pad bytes to the passed in block, returning the
		/// number of bytes added.
		/// </summary>
		public virtual int addPadding(byte[] @in, int inOff)
		{
			int added = (@in.Length - inOff);

			@in [inOff] = unchecked((byte) 0x80);
			inOff++;

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
			int count = @in.Length - 1;

			while (count > 0 && @in[count] == 0)
			{
				count--;
			}

			if (@in[count] != unchecked((byte)0x80))
			{
				throw new InvalidCipherTextException("pad block corrupted");
			}

			return @in.Length - count;
		}
	}

}