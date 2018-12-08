using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.modes
{
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Some methods for GOST 3412 cipher algorithm
	/// </summary>
	public class GOST3413CipherUtil
	{
		/// <summary>
		/// copy first <b>size</b> elements from <b>from</b>
		/// </summary>
		/// <param name="from"> source array </param>
		/// <param name="size"> size of new array
		/// @return </param>
		public static byte[] MSB(byte[] from, int size)
		{
			return Arrays.copyOf(from, size);
		}


		/// <summary>
		/// copy last <b>size</b> elements from <b>from</b>
		/// </summary>
		/// <param name="from"> source array </param>
		/// <param name="size"> size of new array
		/// @return </param>
		public static byte[] LSB(byte[] from, int size)
		{
			byte[] result = new byte[size];
			JavaSystem.arraycopy(from, from.Length - size, result, 0, size);
			return result;
		}


		/// <summary>
		/// componentwise addition modulo 2 (XOR)
		/// </summary>
		/// <param name="in">    clear text </param>
		/// <param name="gamma"> gamma parameter
		/// @return </param>
		public static byte[] sum(byte[] @in, byte[] gamma)
		{

			byte[] @out = new byte[@in.Length];
			for (int i = 0; i < @in.Length; i++)
			{
				@out[i] = (byte)(@in[i] ^ gamma[i]);
			}
			return @out;
		}


		/// <summary>
		/// copy from <b>input</b> array <b>size</b> bytes with <b>offset</b>
		/// </summary>
		/// <param name="input">  input byte array </param>
		/// <param name="size">   count bytes to copy </param>
		/// <param name="offset"> <b>inputs</b> offset
		/// @return </param>
		public static byte[] copyFromInput(byte[] input, int size, int offset)
		{

			if (input.Length < (size + offset))
			{
				size = input.Length - offset;
			}

			byte[] newIn = new byte[size];
			JavaSystem.arraycopy(input, offset, newIn, 0, size);
			return newIn;
		}
	}

}