using System;
using org.bouncycastle.Port;

namespace org.bouncycastle.util
{
	/// <summary>
	/// Utility methods for ints.
	/// </summary>
	public class Integers
	{
		public static int rotateLeft(int i, int distance)
		{
			return Integer.rotateLeft(i, distance);
		}

		public static int rotateRight(int i, int distance)
		{
			return Integer.rotateRight(i, distance);
		}

		public static int valueOf(int value)
		{
			return Convert.ToInt32(value);
		}
	}

}