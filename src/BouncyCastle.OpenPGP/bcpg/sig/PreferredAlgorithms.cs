namespace org.bouncycastle.bcpg.sig
{

	/// <summary>
	/// packet giving signature creation time.
	/// </summary>
	public class PreferredAlgorithms : SignatureSubpacket
	{
		private static byte[] intToByteArray(int[] v)
		{
			byte[] data = new byte[v.Length];

			for (int i = 0; i != v.Length; i++)
			{
				data[i] = (byte)v[i];
			}

			return data;
		}

		public PreferredAlgorithms(int type, bool critical, bool isLongLength, byte[] data) : base(type, critical, isLongLength, data)
		{
		}

		public PreferredAlgorithms(int type, bool critical, int[] preferrences) : base(type, critical, false, intToByteArray(preferrences))
		{
		}

		/// @deprecated mispelt! 
		public virtual int[] getPreferrences()
		{
			return getPreferences();
		}

		public virtual int[] getPreferences()
		{
			int[] v = new int[data.Length];

			for (int i = 0; i != v.Length; i++)
			{
				v[i] = data[i] & 0xff;
			}

			return v;
		}
	}

}