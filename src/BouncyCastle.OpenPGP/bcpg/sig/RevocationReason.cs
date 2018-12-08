namespace org.bouncycastle.bcpg.sig
{
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Represents revocation reason OpenPGP signature sub packet.
	/// </summary>
	public class RevocationReason : SignatureSubpacket
	{
		public RevocationReason(bool isCritical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.REVOCATION_REASON, isCritical, isLongLength, data)
		{
		}

		public RevocationReason(bool isCritical, byte reason, string description) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.REVOCATION_REASON, isCritical, false, createData(reason, description))
		{
		}

		private static byte[] createData(byte reason, string description)
		{
			byte[] descriptionBytes = Strings.toUTF8ByteArray(description);
			byte[] data = new byte[1 + descriptionBytes.Length];

			data[0] = reason;
			JavaSystem.arraycopy(descriptionBytes, 0, data, 1, descriptionBytes.Length);

			return data;
		}

		public virtual byte getRevocationReason()
		{
			return getData()[0];
		}

		public virtual string getRevocationDescription()
		{
			byte[] data = getData();
			if (data.Length == 1)
			{
				return "";
			}

			byte[] description = new byte[data.Length - 1];
			JavaSystem.arraycopy(data, 1, description, 0, description.Length);

			return Strings.fromUTF8ByteArray(description);
		}
	}

}