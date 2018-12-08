namespace org.bouncycastle.bcpg.sig
{
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// packet giving the User ID of the signer.
	/// </summary>
	public class SignerUserID : SignatureSubpacket
	{
		public SignerUserID(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.SIGNER_USER_ID, critical, isLongLength, data)
		{
		}

		public SignerUserID(bool critical, string userID) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.SIGNER_USER_ID, critical, false, Strings.toUTF8ByteArray(userID))
		{
		}

		public virtual string getID()
		{
			return Strings.fromUTF8ByteArray(data);
		}

		public virtual byte[] getRawID()
		{
			return Arrays.clone(data);
		}
	}

}