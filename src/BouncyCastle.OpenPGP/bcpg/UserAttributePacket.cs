namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// Basic type for a user attribute packet.
	/// </summary>
	public class UserAttributePacket : ContainedPacket
	{
		private UserAttributeSubpacket[] subpackets;

		public UserAttributePacket(BCPGInputStream @in)
		{
			UserAttributeSubpacketInputStream sIn = new UserAttributeSubpacketInputStream(@in);
			UserAttributeSubpacket sub;

			Vector v = new Vector();
			while ((sub = sIn.readPacket()) != null)
			{
				v.addElement(sub);
			}

			subpackets = new UserAttributeSubpacket[v.size()];

			for (int i = 0; i != subpackets.Length; i++)
			{
				subpackets[i] = (UserAttributeSubpacket)v.elementAt(i);
			}
		}

		public UserAttributePacket(UserAttributeSubpacket[] subpackets)
		{
			this.subpackets = subpackets;
		}

		public virtual UserAttributeSubpacket[] getSubpackets()
		{
			return subpackets;
		}

		public override void encode(BCPGOutputStream @out)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			for (int i = 0; i != subpackets.Length; i++)
			{
				subpackets[i].encode(bOut);
			}

			@out.writePacket(PacketTags_Fields.USER_ATTRIBUTE, bOut.toByteArray(), false);
		}
	}

}