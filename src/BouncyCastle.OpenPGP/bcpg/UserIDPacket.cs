namespace org.bouncycastle.bcpg
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Basic type for a user ID packet.
	/// </summary>
	public class UserIDPacket : ContainedPacket
	{
		private byte[] idData;

		public UserIDPacket(BCPGInputStream @in)
		{
			this.idData = @in.readAll();
		}

		public UserIDPacket(string id)
		{
			this.idData = Strings.toUTF8ByteArray(id);
		}

		public UserIDPacket(byte[] rawID)
		{
			this.idData = Arrays.clone(rawID);
		}

		public virtual string getID()
		{
			return Strings.fromUTF8ByteArray(idData);
		}

		public virtual byte[] getRawID()
		{
			return Arrays.clone(idData);
		}

		public override bool Equals(object o)
		{
			if (o is UserIDPacket)
			{
				return Arrays.areEqual(this.idData, ((UserIDPacket)o).idData);
			}

			return false;
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(this.idData);
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writePacket(PacketTags_Fields.USER_ID, idData, true);
		}
	}

}