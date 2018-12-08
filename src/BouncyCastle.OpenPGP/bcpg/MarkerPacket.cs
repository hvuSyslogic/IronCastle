namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// Basic type for a marker packet
	/// </summary>
	public class MarkerPacket : ContainedPacket
	{
		// "PGP"

		internal byte[] marker = new byte[] {(byte)0x50, (byte)0x47, (byte)0x50};

		public MarkerPacket(BCPGInputStream @in)
		{
			 @in.readFully(marker);
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writePacket(PacketTags_Fields.MARKER, marker, true);
		}
	}

}