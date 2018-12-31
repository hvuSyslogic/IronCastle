using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec;
using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.x9
{

		
	/// <summary>
	/// A class which converts integers to byte arrays, allowing padding and calculations
	/// to be done according the the filed size of the curve or field element involved.
	/// </summary>
	public class X9IntegerConverter
	{
		/// <summary>
		/// Return the curve's field size in bytes.
		/// </summary>
		/// <param name="c"> the curve of interest. </param>
		/// <returns> the field size in bytes (rounded up). </returns>
		public virtual int getByteLength(ECCurve c)
		{
			return (c.getFieldSize() + 7) / 8;
		}

		/// <summary>
		/// Return the field element's field size in bytes.
		/// </summary>
		/// <param name="fe"> the field element of interest. </param>
		/// <returns> the field size in bytes (rounded up). </returns>
		public virtual int getByteLength(ECFieldElement fe)
		{
			return (fe.getFieldSize() + 7) / 8;
		}

		/// <summary>
		/// Convert an integer to a byte array, ensuring it is exactly qLength long.
		/// </summary>
		/// <param name="s"> the integer to be converted. </param>
		/// <param name="qLength"> the length </param>
		/// <returns> the resulting byte array. </returns>
		public virtual byte[] integerToBytes(BigInteger s, int qLength)
		{
			byte[] bytes = s.toByteArray();

			if (qLength < bytes.Length)
			{
				byte[] tmp = new byte[qLength];

				JavaSystem.arraycopy(bytes, bytes.Length - tmp.Length, tmp, 0, tmp.Length);

				return tmp;
			}
			else if (qLength > bytes.Length)
			{
				byte[] tmp = new byte[qLength];

				JavaSystem.arraycopy(bytes, 0, tmp, tmp.Length - bytes.Length, bytes.Length);

				return tmp;
			}

			return bytes;
		}
	}

}