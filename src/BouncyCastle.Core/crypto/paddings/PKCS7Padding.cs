using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.paddings
{

	/// <summary>
	/// A padder that adds PKCS7/PKCS5 padding to a block.
	/// </summary>
	public class PKCS7Padding : BlockCipherPadding
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
			return "PKCS7";
		}

		/// <summary>
		/// add the pad bytes to the passed in block, returning the
		/// number of bytes added.
		/// </summary>
		public virtual int addPadding(byte[] @in, int inOff)
		{
			byte code = (byte)(@in.Length - inOff);

			while (inOff < @in.Length)
			{
				@in[inOff] = code;
				inOff++;
			}

			return code;
		}

		/// <summary>
		/// return the number of pad bytes present in the block.
		/// </summary>
		public virtual int padCount(byte[] @in)
		{
			int count = @in[@in.Length - 1] & 0xff;
			byte countAsbyte = (byte)count;

			// constant time version
			bool failed = (count > @in.Length | count == 0);

			for (int i = 0; i < @in.Length; i++)
			{
				failed |= (@in.Length - i <= count) & (@in[i] != countAsbyte);
			}

			if (failed)
			{
				throw new InvalidCipherTextException("pad block corrupted");
			}

			return count;
		}
	}

}