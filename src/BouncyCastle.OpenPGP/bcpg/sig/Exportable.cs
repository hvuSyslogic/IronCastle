namespace org.bouncycastle.bcpg.sig
{

	/// <summary>
	/// packet giving signature creation time.
	/// </summary>
	public class Exportable : SignatureSubpacket
	{
		private static byte[] booleanToByteArray(bool value)
		{
			byte[] data = new byte[1];

			if (value)
			{
				data[0] = 1;
				return data;
			}
			else
			{
				return data;
			}
		}

		public Exportable(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.EXPORTABLE, critical, isLongLength, data)
		{
		}

		public Exportable(bool critical, bool isExportable) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.EXPORTABLE, critical, false, booleanToByteArray(isExportable))
		{
		}

		public virtual bool isExportable()
		{
			return data[0] != 0;
		}
	}

}