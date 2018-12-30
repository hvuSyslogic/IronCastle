namespace org.bouncycastle.pqc.crypto.rainbow.util
{
	/// <summary>
	/// This class is needed for the conversions while encoding and decoding, as well as for
	/// comparison between arrays of some dimensions
	/// </summary>
	public class RainbowUtil
	{

		/// <summary>
		/// This function converts an one-dimensional array of bytes into a
		/// one-dimensional array of int
		/// </summary>
		/// <param name="in"> the array to be converted </param>
		/// <returns> out
		///         the one-dimensional int-array that corresponds the input </returns>
		public static int[] convertArraytoInt(byte[] @in)
		{
			int[] @out = new int[@in.Length];
			for (int i = 0; i < @in.Length; i++)
			{
				@out[i] = @in[i] & GF2Field.MASK;
			}
			return @out;
		}

		/// <summary>
		/// This function converts an one-dimensional array of bytes into a
		/// one-dimensional array of type short
		/// </summary>
		/// <param name="in"> the array to be converted </param>
		/// <returns> out
		///         one-dimensional short-array that corresponds the input </returns>
		public static short[] convertArray(byte[] @in)
		{
			short[] @out = new short[@in.Length];
			for (int i = 0; i < @in.Length; i++)
			{
				@out[i] = (short)(@in[i] & GF2Field.MASK);
			}
			return @out;
		}

		/// <summary>
		/// This function converts a matrix of bytes into a matrix of type short
		/// </summary>
		/// <param name="in"> the matrix to be converted </param>
		/// <returns> out
		///         short-matrix that corresponds the input </returns>
		public static short[][] convertArray(byte[][] @in)
		{

			short[][] @out = RectangularArrays.ReturnRectangularShortArray(@in.Length, @in[0].Length);
			for (int i = 0; i < @in.Length; i++)
			{
				for (int j = 0; j < @in[0].Length; j++)
				{
					@out[i][j] = (short)(@in[i][j] & GF2Field.MASK);
				}
			}
			return @out;
		}

		/// <summary>
		/// This function converts a 3-dimensional array of bytes into a 3-dimensional array of type short
		/// </summary>
		/// <param name="in"> the array to be converted </param>
		/// <returns> out
		///         short-array that corresponds the input </returns>
		public static short[][][] convertArray(byte[][][] @in)
		{

			short[][][] @out = RectangularArrays.ReturnRectangularShortArray(@in.Length, @in[0].Length, @in[0][0].Length);
			for (int i = 0; i < @in.Length; i++)
			{
				for (int j = 0; j < @in[0].Length; j++)
				{
					for (int k = 0; k < @in[0][0].Length; k++)
					{
						@out[i][j][k] = (short)(@in[i][j][k] & GF2Field.MASK);
					}
				}
			}
			return @out;
		}

		/// <summary>
		/// This function converts an array of type int into an array of type byte
		/// </summary>
		/// <param name="in"> the array to be converted </param>
		/// <returns> out
		///         the byte-array that corresponds the input </returns>
		public static byte[] convertIntArray(int[] @in)
		{
			byte[] @out = new byte[@in.Length];
			for (int i = 0; i < @in.Length; i++)
			{
				@out[i] = (byte)@in[i];
			}
			return @out;
		}


		/// <summary>
		/// This function converts an array of type short into an array of type byte
		/// </summary>
		/// <param name="in"> the array to be converted </param>
		/// <returns> out
		///         the byte-array that corresponds the input </returns>
		public static byte[] convertArray(short[] @in)
		{
			byte[] @out = new byte[@in.Length];
			for (int i = 0; i < @in.Length; i++)
			{
				@out[i] = (byte)@in[i];
			}
			return @out;
		}

		/// <summary>
		/// This function converts a matrix of type short into a matrix of type byte
		/// </summary>
		/// <param name="in"> the matrix to be converted </param>
		/// <returns> out
		///         the byte-matrix that corresponds the input </returns>
		public static byte[][] convertArray(short[][] @in)
		{

			byte[][] @out = RectangularArrays.ReturnRectangularSbyteArray(@in.Length, @in[0].Length);
			for (int i = 0; i < @in.Length; i++)
			{
				for (int j = 0; j < @in[0].Length; j++)
				{
					@out[i][j] = (byte)@in[i][j];
				}
			}
			return @out;
		}

		/// <summary>
		/// This function converts a 3-dimensional array of type short into a 3-dimensional array of type byte
		/// </summary>
		/// <param name="in"> the array to be converted </param>
		/// <returns> out
		///         the byte-array that corresponds the input </returns>
		public static byte[][][] convertArray(short[][][] @in)
		{

			byte[][][] @out = RectangularArrays.ReturnRectangularSbyteArray(@in.Length, @in[0].Length, @in[0][0].Length);
			for (int i = 0; i < @in.Length; i++)
			{
				for (int j = 0; j < @in[0].Length; j++)
				{
					for (int k = 0; k < @in[0][0].Length; k++)
					{
						@out[i][j][k] = (byte)@in[i][j][k];
					}
				}
			}
			return @out;
		}

		/// <summary>
		/// Compare two short arrays. No null checks are performed.
		/// </summary>
		/// <param name="left">  the first short array </param>
		/// <param name="right"> the second short array </param>
		/// <returns> the result of the comparison </returns>
		public static bool Equals(short[] left, short[] right)
		{
			if (left.Length != right.Length)
			{
				return false;
			}
			bool result = true;
			for (int i = left.Length - 1; i >= 0; i--)
			{
				result &= left[i] == right[i];
			}
			return result;
		}

		/// <summary>
		/// Compare two two-dimensional short arrays. No null checks are performed.
		/// </summary>
		/// <param name="left">  the first short array </param>
		/// <param name="right"> the second short array </param>
		/// <returns> the result of the comparison </returns>
		public static bool Equals(short[][] left, short[][] right)
		{
			if (left.Length != right.Length)
			{
				return false;
			}
			bool result = true;
			for (int i = left.Length - 1; i >= 0; i--)
			{
				result &= Equals(left[i], right[i]);
			}
			return result;
		}

		/// <summary>
		/// Compare two three-dimensional short arrays. No null checks are performed.
		/// </summary>
		/// <param name="left">  the first short array </param>
		/// <param name="right"> the second short array </param>
		/// <returns> the result of the comparison </returns>
		public static bool Equals(short[][][] left, short[][][] right)
		{
			if (left.Length != right.Length)
			{
				return false;
			}
			bool result = true;
			for (int i = left.Length - 1; i >= 0; i--)
			{
				result &= Equals(left[i], right[i]);
			}
			return result;
		}

	}

}