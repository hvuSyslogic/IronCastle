using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp
{
	using UserAttributeSubpacket = org.bouncycastle.bcpg.UserAttributeSubpacket;
	using UserAttributeSubpacketTags = org.bouncycastle.bcpg.UserAttributeSubpacketTags;
	using ImageAttribute = org.bouncycastle.bcpg.attr.ImageAttribute;

	/// <summary>
	/// Container for a list of user attribute subpackets.
	/// </summary>
	public class PGPUserAttributeSubpacketVector
	{
		internal UserAttributeSubpacket[] packets;

		public PGPUserAttributeSubpacketVector(UserAttributeSubpacket[] packets)
		{
			this.packets = packets;
		}

		public virtual UserAttributeSubpacket getSubpacket(int type)
		{
			for (int i = 0; i != packets.Length; i++)
			{
				if (packets[i].getType() == type)
				{
					return packets[i];
				}
			}

			return null;
		}

		public virtual ImageAttribute getImageAttribute()
		{
			UserAttributeSubpacket p = this.getSubpacket(UserAttributeSubpacketTags_Fields.IMAGE_ATTRIBUTE);

			if (p == null)
			{
				return null;
			}

			return (ImageAttribute)p;
		}

		public virtual UserAttributeSubpacket[] toSubpacketArray()
		{
			return packets;
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (o is PGPUserAttributeSubpacketVector)
			{
				PGPUserAttributeSubpacketVector other = (PGPUserAttributeSubpacketVector)o;

				if (other.packets.Length != packets.Length)
				{
					return false;
				}

				for (int i = 0; i != packets.Length; i++)
				{
					if (!other.packets[i].Equals(packets[i]))
					{
						return false;
					}
				}

				return true;
			}

			return false;
		}

		public override int GetHashCode()
		{
			int code = 0;

			for (int i = 0; i != packets.Length; i++)
			{
				code ^= packets[i].GetHashCode();
			}

			return code;
		}
	}

}