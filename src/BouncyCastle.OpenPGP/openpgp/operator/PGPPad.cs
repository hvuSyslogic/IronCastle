namespace org.bouncycastle.openpgp.@operator
{

	/// <summary>
	/// Utility class that provides padding addition and removal for PGP session keys.
	/// </summary>
	public class PGPPad
	{
		private PGPPad()
		{

		}

		public static byte[] padSessionData(byte[] sessionInfo)
		{
			byte[] result = new byte[40];

			JavaSystem.arraycopy(sessionInfo, 0, result, 0, sessionInfo.Length);

			byte padValue = (byte)(result.Length - sessionInfo.Length);

			for (int i = sessionInfo.Length; i != result.Length; i++)
			{
				result[i] = padValue;
			}

			return result;
		}

		public static byte[] unpadSessionData(byte[] encoded)
		{
			byte padValue = encoded[encoded.Length - 1];

			for (int i = encoded.Length - padValue; i != encoded.Length; i++)
			{
				if (encoded[i] != padValue)
				{
					throw new PGPException("bad padding found in session data");
				}
			}

			byte[] taggedKey = new byte[encoded.Length - padValue];

			JavaSystem.arraycopy(encoded, 0, taggedKey, 0, taggedKey.Length);

			return taggedKey;
		}
	}

}