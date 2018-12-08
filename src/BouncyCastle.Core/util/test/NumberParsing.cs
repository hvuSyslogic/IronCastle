using System;

namespace org.bouncycastle.util.test
{
	/// <summary>
	/// Parsing
	/// </summary>
	public sealed class NumberParsing
	{
		private NumberParsing()
		{
			// Hide constructor
		}

		public static long decodeLongFromHex(string longAsString)
		{
			if ((longAsString[1] == 'x') || (longAsString[1] == 'X'))
			{
				return Convert.ToInt64(longAsString.Substring(2), 16);
			}

			return Convert.ToInt64(longAsString, 16);
		}

		public static int decodeIntFromHex(string intAsString)
		{
			if ((intAsString[1] == 'x') || (intAsString[1] == 'X'))
			{
				return Convert.ToInt32(intAsString.Substring(2), 16);
			}

			return Convert.ToInt32(intAsString, 16);
		}
	}

}