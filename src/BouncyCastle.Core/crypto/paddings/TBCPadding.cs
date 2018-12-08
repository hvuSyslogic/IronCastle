using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.paddings
{

	/// <summary>
	/// A padder that adds Trailing-Bit-Compliment padding to a block.
	/// <para>
	/// This padding pads the block out with the compliment of the last bit
	/// of the plain text.
	/// </para>
	/// </summary>
	public class TBCPadding : BlockCipherPadding
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
			return "TBC";
		}

		/// <summary>
		/// add the pad bytes to the passed in block, returning the
		/// number of bytes added.
		/// <para>
		/// Note: this assumes that the last block of plain text is always 
		/// passed to it inside in. i.e. if inOff is zero, indicating the
		/// entire block is to be overwritten with padding the value of in
		/// should be the same as the last block of plain text.
		/// </para>
		/// </summary>
		public virtual int addPadding(byte[] @in, int inOff)
		{
			int count = @in.Length - inOff;
			byte code;

			if (inOff > 0)
			{
				code = (byte)((@in[inOff - 1] & 0x01) == 0 ? 0xff : 0x00);
			}
			else
			{
				code = (byte)((@in[@in.Length - 1] & 0x01) == 0 ? 0xff : 0x00);
			}

			while (inOff < @in.Length)
			{
				@in[inOff] = code;
				inOff++;
			}

			return count;
		}

		/// <summary>
		/// return the number of pad bytes present in the block.
		/// </summary>
		public virtual int padCount(byte[] @in)
		{
			byte code = @in[@in.Length - 1];

			int index = @in.Length - 1;
			while (index > 0 && @in[index - 1] == code)
			{
				index--;
			}

			return @in.Length - index;
		}
	}

}