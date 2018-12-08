namespace org.bouncycastle.bcpg.sig
{

	public class Features : SignatureSubpacket
	{

		/// <summary>
		/// Identifier for the modification detection feature </summary>
		public const byte FEATURE_MODIFICATION_DETECTION = 1;

		private static byte[] featureToByteArray(byte feature)
		{
			byte[] data = new byte[1];
			data[0] = feature;
			return data;
		}

		public Features(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.FEATURES, critical, isLongLength, data)
		{
		}

		public Features(bool critical, byte feature) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.FEATURES, critical, false, featureToByteArray(feature))
		{
		}

		/// <summary>
		/// Returns if modification detection is supported.
		/// </summary>
		public virtual bool supportsModificationDetection()
		{
			return supportsFeature(FEATURE_MODIFICATION_DETECTION);
		}

		/// <summary>
		/// Returns if a particular feature is supported.
		/// </summary>
		public virtual bool supportsFeature(byte feature)
		{
			for (int i = 0; i < data.Length; i++)
			{
				if (data[i] == feature)
				{
					return true;
				}
			}
			return false;
		}


		/// <summary>
		/// Sets support for a particular feature.
		/// </summary>
		private void setSupportsFeature(byte feature, bool support)
		{
			if (feature == 0)
			{
				throw new IllegalArgumentException("feature == 0");
			}
			if (supportsFeature(feature) != support)
			{
				if (support == true)
				{
					byte[] temp = new byte[data.Length + 1];
					JavaSystem.arraycopy(data, 0, temp, 0, data.Length);
					temp[data.Length] = feature;
					data = temp;
				}
				else
				{
					for (int i = 0; i < data.Length; i++)
					{
						if (data[i] == feature)
						{
							byte[] temp = new byte[data.Length - 1];
							JavaSystem.arraycopy(data, 0, temp, 0, i);
							JavaSystem.arraycopy(data, i + 1, temp, i, temp.Length - i);
							data = temp;
							break;
						}
					}
				}
			}
		}
	}

}