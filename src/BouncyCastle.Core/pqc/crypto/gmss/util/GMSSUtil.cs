using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.gmss.util
{
	/// <summary>
	/// This class provides several methods that are required by the GMSS classes.
	/// </summary>
	public class GMSSUtil
	{
		/// <summary>
		/// Converts a 32 bit integer into a byte array beginning at
		/// <code>offset</code> (little-endian representation)
		/// </summary>
		/// <param name="value"> the integer to convert </param>
		public virtual byte[] intToBytesLittleEndian(int value)
		{
			byte[] bytes = new byte[4];

			bytes[0] = unchecked((byte)((value) & 0xff));
			bytes[1] = unchecked((byte)((value >> 8) & 0xff));
			bytes[2] = unchecked((byte)((value >> 16) & 0xff));
			bytes[3] = unchecked((byte)((value >> 24) & 0xff));
			return bytes;
		}

		/// <summary>
		/// Converts a byte array beginning at <code>offset</code> into a 32 bit
		/// integer (little-endian representation)
		/// </summary>
		/// <param name="bytes"> the byte array </param>
		/// <returns> The resulting integer </returns>
		public virtual int bytesToIntLittleEndian(byte[] bytes)
		{

			return ((bytes[0] & 0xff)) | ((bytes[1] & 0xff) << 8) | ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff)) << 24;
		}

		/// <summary>
		/// Converts a byte array beginning at <code>offset</code> into a 32 bit
		/// integer (little-endian representation)
		/// </summary>
		/// <param name="bytes">  the byte array </param>
		/// <param name="offset"> the integer offset into the byte array </param>
		/// <returns> The resulting integer </returns>
		public virtual int bytesToIntLittleEndian(byte[] bytes, int offset)
		{
			return ((bytes[offset++] & 0xff)) | ((bytes[offset++] & 0xff) << 8) | ((bytes[offset++] & 0xff) << 16) | ((bytes[offset] & 0xff)) << 24;
		}

		/// <summary>
		/// This method concatenates a 2-dimensional byte array into a 1-dimensional
		/// byte array
		/// </summary>
		/// <param name="arraycp"> a 2-dimensional byte array. </param>
		/// <returns> 1-dimensional byte array with concatenated input array </returns>
		public virtual byte[] concatenateArray(byte[][] arraycp)
		{
			byte[] dest = new byte[arraycp.Length * arraycp[0].Length];
			int indx = 0;
			for (int i = 0; i < arraycp.Length; i++)
			{
				JavaSystem.arraycopy(arraycp[i], 0, dest, indx, arraycp[i].Length);
				indx = indx + arraycp[i].Length;
			}
			return dest;
		}

		/// <summary>
		/// This method prints the values of a 2-dimensional byte array
		/// </summary>
		/// <param name="text">  a String </param>
		/// <param name="array"> a 2-dimensional byte array </param>
		public virtual void printArray(string text, byte[][] array)
		{
			JavaSystem.@out.println(text);
			int counter = 0;
			for (int i = 0; i < array.Length; i++)
			{
				for (int j = 0; j < array[0].Length; j++)
				{
					JavaSystem.@out.println(counter + "; " + array[i][j]);
					counter++;
				}
			}
		}

		/// <summary>
		/// This method prints the values of a 1-dimensional byte array
		/// </summary>
		/// <param name="text">  a String </param>
		/// <param name="array"> a 1-dimensional byte array. </param>
		public virtual void printArray(string text, byte[] array)
		{
			JavaSystem.@out.println(text);
			int counter = 0;
			for (int i = 0; i < array.Length; i++)
			{
				JavaSystem.@out.println(counter + "; " + array[i]);
				counter++;
			}
		}

		/// <summary>
		/// This method tests if an integer is a power of 2.
		/// </summary>
		/// <param name="testValue"> an integer </param>
		/// <returns> <code>TRUE</code> if <code>testValue</code> is a power of 2,
		///         <code>FALSE</code> otherwise </returns>
		public virtual bool testPowerOfTwo(int testValue)
		{
			int a = 1;
			while (a < testValue)
			{
				a <<= 1;
			}
			if (testValue == a)
			{
				return true;
			}

			return false;
		}

		/// <summary>
		/// This method returns the least integer that is greater or equal to the
		/// logarithm to the base 2 of an integer <code>intValue</code>.
		/// </summary>
		/// <param name="intValue"> an integer </param>
		/// <returns> The least integer greater or equal to the logarithm to the base 2
		///         of <code>intValue</code> </returns>
		public virtual int getLog(int intValue)
		{
			int log = 1;
			int i = 2;
			while (i < intValue)
			{
				i <<= 1;
				log++;
			}
			return log;
		}
	}

}